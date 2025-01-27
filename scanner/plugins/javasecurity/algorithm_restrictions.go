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
	goerrors "errors"
	"fmt"
	"github.com/IBM/cbomkit-theia/scanner/confidenceLevel"
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

// Evaluates all AlgorithmRestriction for a component
func evaluateRestrictions(algorithmRestrictions []AlgorithmRestriction, component cdx.Component) (*confidenceLevel.ConfidenceLevel, error) {
	confidence := confidenceLevel.New()

	var insufficientInformationErrors []error
	for _, algorithmRestriction := range algorithmRestrictions {
		currentConfidenceLevel, err := algorithmRestriction.evaluate(component)
		if err != nil {
			if goerrors.Is(err, scannererrors.ErrInsufficientInformation) {
				insufficientInformationErrors = append(insufficientInformationErrors, err)
			} else {
				return confidence, err
			}
		}
		confidence.AddSubConfidenceLevel(currentConfidenceLevel, true)
	}

	// Did we have insufficient information with all restrictions? If so, return this.
	if len(insufficientInformationErrors) == len(algorithmRestrictions) {
		return confidence, goerrors.Join(insufficientInformationErrors...)
	} else {
		return confidence, nil
	}
}

// Evaluates if a single component is allowed based on a single restriction; returns true if the component is allowed, false otherwise;
// Follows the [JDK implementation]
//
// [JDK implementation]: https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/sun/security/util/DisabledAlgorithmConstraints.java
func (javaSecurityAlgorithmRestriction AlgorithmRestriction) evaluate(component cdx.Component) (*confidenceLevel.ConfidenceLevel, error) {
	slog.Debug("Evaluating component with restriction", "component", component.Name, "restriction_name", javaSecurityAlgorithmRestriction.name, "restriction_operator", javaSecurityAlgorithmRestriction.keySizeOperator, "restriction_value", javaSecurityAlgorithmRestriction.keySize)

	if component.CryptoProperties == nil {
		return nil, fmt.Errorf("cannot evaluate components other than algorithm or protocol for applying restrictions")
	}

	if component.CryptoProperties.AssetType != cdx.CryptoAssetTypeAlgorithm {
		return nil, fmt.Errorf("cannot evaluate components other than algorithm for applying restrictions")
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
			confidence := confidenceLevel.New()
			// start low
			confidence.Modify(confidenceLevel.NegativeMedium)

			if component.CryptoProperties.AlgorithmProperties == nil {
				return confidence, nil // No algorithm properties set
			}

			// There is no need to test further if the component does not provide a keySize
			if component.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier == "" {
				if javaSecurityAlgorithmRestriction.keySizeOperator != keySizeOperatorNone {
					confidence.Modify(confidenceLevel.PositiveMedium)
					return confidence, scannererrors.GetInsufficientInformationError(fmt.Sprintf("missing key size parameter in BOM for rule affecting %v", javaSecurityAlgorithmRestriction.name), "java.security Plugin", "component", component.Name) // We actually need a keySize so we cannot go on here
				} else {
					confidence.Modify(confidenceLevel.NegativeHigh)
					return confidence, nil // Names match, and we do not need a keySize --> The algorithm is not allowed!
				}
			}

			// Parsing the key size
			param, err := strconv.Atoi(component.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier)
			if err != nil {
				return confidence, scannererrors.GetInsufficientInformationError(fmt.Sprintf("missing key size parameter in BOM for rule affecting %v", javaSecurityAlgorithmRestriction.name), "java.security Plugin", "component", component.Name) // We actually need a keySize so we cannot go on here
			}

			if param <= 0 || param > 2147483647 {
				confidence.Modify(confidenceLevel.NegativeMedium)
				// Following Java reference implementation
				// (see https://github.com/openjdk/jdk/blob/4f1a10f84bcfadef263a0890b6834ccd3d5bb52f/src/java.base/share/classes/sun/security/util/DisabledAlgorithmConstraints.java#L944 and https://github.com/openjdk/jdk/blob/4f1a10f84bcfadef263a0890b6834ccd3d5bb52f/src/java.base/share/classes/sun/security/util/DisabledAlgorithmConstraints.java#L843)
			}

			var allowed bool
			switch javaSecurityAlgorithmRestriction.keySizeOperator {
			case keySizeOperatorLowerEqual:
				allowed = !(param <= javaSecurityAlgorithmRestriction.keySize)
			case keySizeOperatorLower:
				allowed = !(param < javaSecurityAlgorithmRestriction.keySize)
			case keySizeOperatorEqual:
				allowed = !(param == javaSecurityAlgorithmRestriction.keySize)
			case keySizeOperatorNotEqual:
				allowed = !(param != javaSecurityAlgorithmRestriction.keySize)
			case keySizeOperatorGreaterEqual:
				allowed = !(param >= javaSecurityAlgorithmRestriction.keySize)
			case keySizeOperatorGreater:
				allowed = !(param > javaSecurityAlgorithmRestriction.keySize)
			case keySizeOperatorNone:
				allowed = false
			default:
				confidence.Modify(confidenceLevel.PositiveMedium)
				return confidence, fmt.Errorf("invalid keySizeOperator in JavaSecurityAlgorithmRestriction: %v", javaSecurityAlgorithmRestriction.keySizeOperator)
			}

			if !allowed {
				confidence.Modify(confidenceLevel.NegativeMedium)
				return confidence, err
			}
		}
	}
	return nil, fmt.Errorf("no restriction found for component %s", component.Name)
}
