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
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/IBM/cbomkit-theia/provider/filesystem"
	advancedcomponentslice "github.com/IBM/cbomkit-theia/scanner/componentwithconfidenceslice"
	scannererrors "github.com/IBM/cbomkit-theia/scanner/errors"

	cdx "github.com/CycloneDX/cyclonedx-go"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/magiconair/properties"
)

/*
=======
General
=======
*/

// Checks whether the current file at a path is a java.security config file
func (*Plugin) isConfigFile(path string) bool {
	// Check if this file is the java.security file and if that is the case extract the path of the active crypto.policy files
	dir, _ := filepath.Split(path)
	dir = filepath.Clean(dir)

	// Check the correct directory
	if !(strings.HasSuffix(dir, filepath.Join("jre", "lib", "security")) ||
		strings.HasSuffix(dir, filepath.Join("conf", "security"))) {
		return false
	}

	// Check a file extension
	ext := filepath.Ext(path)
	if ext != ".security" {
		return false
	}

	// If all checks passed, return true
	return true
}

/*
=======
java.security related
=======
*/

// JavaSecurity represents the java.security file(s) found on the system
type JavaSecurity struct {
	*properties.Properties
	tlsDisabledAlgorithms []AlgorithmRestriction
}

func newJavaSecurity(properties *properties.Properties, fs filesystem.Filesystem) (JavaSecurity, error) {
	additionalSecurityProperties, override, err := checkConfig(properties, fs)
	if err != nil {
		return JavaSecurity{}, err
	}

	if !override {
		if additionalSecurityProperties != nil {
			properties.Merge(additionalSecurityProperties)
		}
	} else {
		properties = additionalSecurityProperties
	}

	restrictions, err := extractTLSRules(properties)
	if err != nil {
		return JavaSecurity{}, err
	}

	return JavaSecurity{
		properties,
		restrictions,
	}, err
}

// Assesses if the component is from a source affected by this type of config (e.g., a java file),
// requires "Evidence" and "Occurrences" to be present in the BOM
func (*JavaSecurity) isComponentAffectedByConfig(component cdx.Component) (bool, error) {
	if component.Evidence == nil || component.Evidence.Occurrences == nil { // If there is no evidence telling us that whether this component comes from a java file, we cannot assess it
		return false, scannererrors.GetInsufficientInformationError("cannot evaluate due to missing evidence/occurrences in BOM", "java.security Plugin", "component", component.Name)
	}

	for _, occurrence := range *component.Evidence.Occurrences {
		if filepath.Ext(occurrence.Location) == ".java" {
			return true, nil
		}
	}
	return false, nil
}

// Update a single component; returns nil if component is not allowed
func (javaSecurity *JavaSecurity) updateComponent(index int, advancedComponentSlice *advancedcomponentslice.ComponentWithConfidenceSlice) (err error) {
	ok, err := javaSecurity.isComponentAffectedByConfig(*advancedComponentSlice.GetByIndex(index).Component)

	if ok {
		advancedComponentSlice.GetByIndex(index).SetPrintConfidenceLevel(true)
	} else {
		if goerrors.Is(err, scannererrors.ErrInsufficientInformation) {
			return err
		}
	}

	switch advancedComponentSlice.GetByIndex(index).CryptoProperties.AssetType {
	case cdx.CryptoAssetTypeProtocol:
		return javaSecurity.updateProtocolComponent(index, advancedComponentSlice)
	default:
		return nil
	}
}

var errNilProperties = fmt.Errorf("scanner java: properties are nil")

// Remove a single item by index s from a slice
func removeFromSlice[T interface{}](slice []T, s int) []T {
	return append(slice[:s], slice[s+1:]...)
}

// Recursively get all comma-separated values of the property key. Recursion is necessary since values can include
// "include" directives which refer to other properties and include them in this property.
func getPropertyValuesRecursively(properties *properties.Properties, key string) (values []string, err error) {
	if properties == nil {
		return values, errNilProperties
	}

	fullString, ok := properties.Get(key)
	if ok {
		values = strings.Split(fullString, ",")
		for i, value := range values {
			values[i] = strings.TrimSpace(value)
		}
	}
	toBeRemoved := []int{} // Remember they include directives and remove them later
	for i, value := range values {
		if strings.HasPrefix(value, "include") {
			toBeRemoved = append(toBeRemoved, i)
			split := strings.Split(value, " ")
			if len(split) > 1 {
				includedValues, err := getPropertyValuesRecursively(properties, split[1])
				if err != nil {
					return includedValues, err
				}
				values = append(values, includedValues...)
			}
		}
	}
	for _, remove := range toBeRemoved {
		values = removeFromSlice(values, remove)
	}
	return values, nil
}

// Parses the TLS Rules from the java.security file
// Returns a joined list of errors which occurred during parsing of algorithms
func extractTLSRules(securityProperties *properties.Properties) (restrictions []AlgorithmRestriction, err error) {
	slog.Debug("Extracting TLS rules")

	securityPropertiesKey := "jdk.tls.disabledAlgorithms"
	algorithms, err := getPropertyValuesRecursively(securityProperties, securityPropertiesKey)

	if goerrors.Is(err, errNilProperties) {
		slog.Warn("Properties of javaSecurity object are nil. This should not happen. Continuing anyway.")
	} else if err != nil {
		return restrictions, err
	}

	var algorithmParsingErrors []error

	if len(algorithms) > 0 {
		for _, algorithm := range algorithms {
			keySize := 0
			keySizeOperator := keySizeOperatorNone
			name := algorithm

			if strings.Contains(algorithm, "jdkCA") ||
				strings.Contains(algorithm, "denyAfter") ||
				strings.Contains(algorithm, "usage") {
				slog.Warn("found constraint in java.security that is not supported in this version of CBOMkit-theia", "algorithm", algorithm)
				continue
			}

			if strings.Contains(algorithm, "keySize") {
				split := strings.Split(algorithm, "keySize")
				if len(split) > 2 {
					algorithmParsingErrors = append(algorithmParsingErrors,
						fmt.Errorf("scanner java: sanity check failed, %v contains too many elements (%v)", split, algorithm))
					continue
				}
				name = strings.TrimSpace(split[0])
				split[1] = strings.TrimSpace(split[1])
				keyRestrictions := strings.Split(split[1], " ")

				switch keyRestrictions[0] {
				case "<=":
					keySizeOperator = keySizeOperatorLowerEqual
				case "<":
					keySizeOperator = keySizeOperatorLower
				case "==":
					keySizeOperator = keySizeOperatorEqual
				case "!=":
					keySizeOperator = keySizeOperatorNotEqual
				case ">=":
					keySizeOperator = keySizeOperatorGreaterEqual
				case ">":
					keySizeOperator = keySizeOperatorGreater
				case "":
					keySizeOperator = keySizeOperatorNone
				default:
					algorithmParsingErrors = append(algorithmParsingErrors,
						fmt.Errorf("scanner java: could not parse the following keySizeOperator %v (%v)", keyRestrictions[0], algorithm))
					continue
				}

				keySize, err = strconv.Atoi(keyRestrictions[1])
				if err != nil {
					algorithmParsingErrors = append(algorithmParsingErrors,
						fmt.Errorf("scanner java: (%v) %w", algorithm, err))
					continue
				}
			}

			restrictions = append(restrictions, AlgorithmRestriction{
				name:            name,
				keySize:         keySize,
				keySizeOperator: keySizeOperator,
			})
		}
	} else {
		slog.Debug("No disabled algorithms specified!", "key", securityPropertiesKey)
	}

	return restrictions, goerrors.Join(algorithmParsingErrors...)
}

/*
=======
container image related
=======
*/

const SecurityCmdArgument = "-Djava.security.properties="

// Tries to get a config from the fs and checks the Config for potentially relevant information
func checkConfig(securityProperties *properties.Properties, fs filesystem.Filesystem) (additionalSecurityProperties *properties.Properties, override bool, err error) {
	slog.Debug("Checking filesystem config for additional security properties")

	imageConfig, ok := fs.GetConfig()
	if !ok {
		slog.Debug("Filesystem did not provide a config. This can be normal if the specified filesystem is not a docker image layer.", "fs", fs.GetIdentifier())
		return additionalSecurityProperties, override, nil
	}

	additionalSecurityProperties, override, err = checkForAdditionalSecurityFilesCMDParameter(imageConfig, securityProperties, fs)

	if goerrors.Is(err, errNilProperties) {
		slog.Warn("Properties of javaSecurity object are nil. This should not happen. Continuing anyway.", "fs", fs.GetIdentifier())
		return additionalSecurityProperties, override, nil
	}

	return additionalSecurityProperties, override, err
}

// Searches the image config for potentially relevant CMD parameters and potentially adds new properties
func checkForAdditionalSecurityFilesCMDParameter(config v1.Config, securityProperties *properties.Properties, fs filesystem.Filesystem) (additionalSecurityProperties *properties.Properties, override bool, err error) {
	// We have to check if adding additional security files via CMD is even allowed via the java.security file (security.overridePropertiesFile property)

	if securityProperties == nil { // We do not have a security file
		return securityProperties, override, errNilProperties
	}

	allowAdditionalFiles := securityProperties.GetBool("security.overridePropertiesFile", true)
	if !allowAdditionalFiles {
		slog.Debug("Security properties don't allow additional security files. Stopping searching directly.", "fs", fs.GetIdentifier())
		return additionalSecurityProperties, override, nil
	}

	// Now, let's check for additional files added via CMD
	var value string
	var ok bool

	for _, command := range append(config.Cmd, config.Entrypoint...) {
		value, override, ok = getJavaFlagValue(command, SecurityCmdArgument)

		if ok {
			slog.Debug("Found command that specifies new properties", "command", command)

			readCloser, err := fs.Open(value)
			if err != nil {
				if strings.Contains(err.Error(), "could not find file path in Tree") {
					slog.Warn("failed to read file specified via a command flag in the image configuration (e.g. Dockerfile); the image or image config is probably malformed; continuing without adding it.", "file", value)
					return additionalSecurityProperties, override, nil
				} else {
					return additionalSecurityProperties, override, err
				}
			}
			content, err := filesystem.ReadAllClose(readCloser)
			if err != nil {
				slog.Warn("failed to read file specified via a command flag in the image configuration (e.g. Dockerfile); the image or image config is probably malformed; continuing without adding it.", "file", value)
				return additionalSecurityProperties, override, nil
			}
			additionalSecurityProperties, err = properties.LoadString(string(content))
			return additionalSecurityProperties, override, err
		}
	}

	return additionalSecurityProperties, override, err
}

// Tries to extract the value of a flag in command;
// returns ok if found; returns overwrite if double equals signs were used (==)
func getJavaFlagValue(command string, flag string) (value string, overwrite bool, ok bool) {
	split := strings.Split(command, flag)
	if len(split) == 2 {
		split = strings.Fields(split[1])
		value = split[0]
		if strings.HasPrefix(value, "=") {
			overwrite = true
			value = value[1:]
		}
		return value, overwrite, true
	}
	return value, overwrite, false
}
