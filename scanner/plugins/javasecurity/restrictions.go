// Copyright 2024 IBM
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package javasecurity

import (
	"fmt"
	"github.com/IBM/cbomkit-theia/provider/cyclonedx"
	"github.com/IBM/cbomkit-theia/utils"
	"log/slog"
	"strconv"
	"strings"

	scannererrors "github.com/IBM/cbomkit-theia/scanner/errors"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// AlgorithmRestriction Represents a single restriction on algorithms by the java.security file
type AlgorithmRestriction struct {
	name            string
	keySizeOperator keySizeOperator
	keySize         int
}

// keySizeOperator holds operators for the possible comparison functions (e.g., greater than etc.)
type keySizeOperator int

const (
	keySizeOperatorGreaterEqual keySizeOperator = iota + 1
	keySizeOperatorGreater
	keySizeOperatorLowerEqual
	keySizeOperatorLower
	keySizeOperatorEqual
	keySizeOperatorNotEqual
	keySizeOperatorNone
)

type RestrictionResult struct {
	target string
	reason string
}

// Evaluates all AlgorithmRestriction for a component
func isAllowed(component cdx.Component, components *[]cdx.Component, javaSecurity *JavaSecurity) (bool, *[]RestrictionResult, error) {
	if javaSecurity == nil {
		return true, nil, fmt.Errorf("no java.security file provided")
	}

	if len(javaSecurity.tlsDisabledAlgorithms) == 0 {
		return true, nil, fmt.Errorf("no restrictions found in java.security file")
	}

	if component.Type != cdx.ComponentTypeCryptographicAsset {
		return true, nil, fmt.Errorf("component is not a cryptographic asset")
	}

	if component.CryptoProperties == nil {
		return true, nil, fmt.Errorf("component does not have any cryptographic properties")
	}

	assetType := component.CryptoProperties.AssetType
	switch assetType {
	case cdx.CryptoAssetTypeProtocol:
		return updateProtocolComponent(component, components, javaSecurity.tlsDisabledAlgorithms)
	case cdx.CryptoAssetTypeAlgorithm:
		slog.Info("")
	}
	return true, nil, nil
}

func updateProtocolComponent(component cdx.Component, components *[]cdx.Component, algorithmRestrictions []AlgorithmRestriction) (bool, *[]RestrictionResult, error) {
	if component.CryptoProperties.ProtocolProperties == nil {
		return true, nil, fmt.Errorf("component has not enough information (protocolProperties)")
	}

	switch component.CryptoProperties.ProtocolProperties.Type {
	case cdx.CryptoProtocolTypeTLS:
		return updateTLSComponent(component, components, algorithmRestrictions)
	}
	return true, nil, nil
}

func updateTLSComponent(component cdx.Component, components *[]cdx.Component, algorithmRestrictions []AlgorithmRestriction) (bool, *[]RestrictionResult, error) {
	if component.CryptoProperties.ProtocolProperties.CipherSuites == nil {
		return true, nil, fmt.Errorf("component has not enough information (cipherSuites)")
	}

	var restrictionResults []RestrictionResult
	for _, cipherSuite := range *component.CryptoProperties.ProtocolProperties.CipherSuites {
		for _, algorithmRestriction := range algorithmRestrictions {
			allowed, err := algorithmRestriction.allowed(component)
			if err != nil {
				slog.Debug(err.Error())
				continue
			}

			if !allowed {
				restrictionResults = append(restrictionResults, RestrictionResult{
					target: cipherSuite.Name,
					reason: fmt.Sprintf("%v", algorithmRestriction),
				})
			}
		}

		// test all algorithms related to cipher suite
		for _, algorithmRef := range *cipherSuite.Algorithms {
			algorithmComponent := cyclonedx.GetByBomRef(algorithmRef, components)
			if algorithmComponent == nil {
				continue
			}

			for _, algorithmRestriction := range algorithmRestrictions {
				allowed, err := algorithmRestriction.allowed(*algorithmComponent)
				if err != nil {
					slog.Debug(err.Error())
					continue
				}

				if !allowed {
					restrictionResults = append(restrictionResults, RestrictionResult{
						target: algorithmComponent.Name,
						reason: fmt.Sprintf("%v", algorithmRestriction),
					})
				}
			}
		}
	}
	return true, &restrictionResults, nil
}

// Evaluates if a single component is allowed based on a single restriction; returns true if the component is allowed, false otherwise;
func (javaSecurityAlgorithmRestriction AlgorithmRestriction) allowed(component cdx.Component) (bool, error) {
	slog.Debug("evaluating component with restriction", "component", component.Name, "restriction_name", javaSecurityAlgorithmRestriction.name, "restriction_operator", javaSecurityAlgorithmRestriction.keySizeOperator, "restriction_value", javaSecurityAlgorithmRestriction.keySize)

	if component.CryptoProperties == nil {
		return false, fmt.Errorf("cannot allow components other than algorithm or protocol for applying restrictions")
	}

	if component.CryptoProperties.AssetType != cdx.CryptoAssetTypeAlgorithm {
		return false, fmt.Errorf("cannot allow components other than algorithm for applying restrictions")
	}

	if component.CryptoProperties.AlgorithmProperties == nil {
		return false, fmt.Errorf("cannot allow components other than algorithm for applying restrictions")
	}

	// The Format could be: <digest>with<encryption>and<mgf>
	replacer := strings.NewReplacer("with", " ", "and", " ")
	subAlgorithms := strings.Fields(replacer.Replace(component.Name))

	// Also need to test the full name
	if len(subAlgorithms) > 1 {
		subAlgorithms = append(subAlgorithms, component.Name)
	}

	for _, subAlgorithm := range subAlgorithms {
		restrictionStandardized, subAlgorithmStandardized := utils.StandardizeString(javaSecurityAlgorithmRestriction.name), utils.StandardizeString(subAlgorithm)
		if strings.EqualFold(restrictionStandardized, subAlgorithmStandardized) {
			if component.CryptoProperties.AlgorithmProperties == nil {
				return false, scannererrors.GetInsufficientInformationError(fmt.Sprintf("missing algorithm properties in BOM for rule affecting %v", javaSecurityAlgorithmRestriction.name), "java.security", "component", component.Name)
			}

			// There is no need to test further if the component does not provide a keySize
			if component.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier == "" {
				if javaSecurityAlgorithmRestriction.keySizeOperator != keySizeOperatorNone {
					return false, scannererrors.GetInsufficientInformationError(fmt.Sprintf("missing key size parameter in BOM for rule affecting %v", javaSecurityAlgorithmRestriction.name), "java.security", "component", component.Name) // We actually need a keySize so we cannot go on here
				} else {
					return false, nil // Names match, and we do not need a keySize --> The algorithm is not allowed!
				}
			}

			// Parsing the key size
			param, err := strconv.Atoi(component.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier)
			if err != nil {
				return false, scannererrors.GetInsufficientInformationError(fmt.Sprintf("missing key size parameter in BOM for rule affecting %v", javaSecurityAlgorithmRestriction.name), "java.security", "component", component.Name) // We actually need a keySize so we cannot go on here
			}

			if param <= 0 || param > 2147483647 {
				// Following Java reference implementation
				// (see https://github.com/openjdk/jdk/blob/4f1a10f84bcfadef263a0890b6834ccd3d5bb52f/src/java.base/share/classes/sun/security/util/DisabledAlgorithmConstraints.java#L944 and https://github.com/openjdk/jdk/blob/4f1a10f84bcfadef263a0890b6834ccd3d5bb52f/src/java.base/share/classes/sun/security/util/DisabledAlgorithmConstraints.java#L843)
				return false, fmt.Errorf("key size not in the limits: %d", param)
			}

			var allowed bool
			switch javaSecurityAlgorithmRestriction.keySizeOperator {
			case keySizeOperatorLowerEqual:
				allowed = param <= javaSecurityAlgorithmRestriction.keySize
			case keySizeOperatorLower:
				allowed = param < javaSecurityAlgorithmRestriction.keySize
			case keySizeOperatorEqual:
				allowed = param == javaSecurityAlgorithmRestriction.keySize
			case keySizeOperatorNotEqual:
				allowed = param != javaSecurityAlgorithmRestriction.keySize
			case keySizeOperatorGreaterEqual:
				allowed = param >= javaSecurityAlgorithmRestriction.keySize
			case keySizeOperatorGreater:
				allowed = param > javaSecurityAlgorithmRestriction.keySize
			case keySizeOperatorNone:
				allowed = false
			default:
				return false, fmt.Errorf("invalid keySizeOperator in JavaSecurityAlgorithmRestriction: %v", javaSecurityAlgorithmRestriction.keySizeOperator)
			}

			if allowed {
				return true, nil
			}
		}
	}
	return false, nil
}
