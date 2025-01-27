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
	"github.com/IBM/cbomkit-theia/provider/cyclonedx"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/IBM/cbomkit-theia/provider/filesystem"
	scannererrors "github.com/IBM/cbomkit-theia/scanner/errors"
	"github.com/IBM/cbomkit-theia/scanner/plugins"

	cdx "github.com/CycloneDX/cyclonedx-go"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/magiconair/properties"
)

// Plugin Represents the java security plugin in a specific scanning context
// Implements the config/ConfigPlugin interface
type Plugin struct{}

// NewJavaSecurityPlugin Creates underlying data structure for evaluation
func NewJavaSecurityPlugin() (plugins.Plugin, error) {
	return &Plugin{}, nil
}

// GetName Get the name of the plugin for debugging purposes
func (*Plugin) GetName() string {
	return "java.security Plugin"
}

func (*Plugin) GetExplanation() string {
	return "Verify the excitability of cryptographic assets from Java code\nAdds a confidence level (0-100) to the CBOM components to show how likely it is that this component is actually executable"
}

// GetType Get the type of the plugin
func (*Plugin) GetType() plugins.PluginType {
	return plugins.PluginTypeVerify
}

// UpdateBOM High-level function to update a list of components
// (e.g., remove components and add new ones) based on the underlying filesystem
func (plugin *Plugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	slog.Warn("java.security: current version does not take dynamic changes of java javaSecurity properties (e.g. via System.setProperty) into account.")
	javaSecurityFiles, err := plugin.findJavaSecurityFiles(fs)
	if err != nil {
		return err
	}

	if len(javaSecurityFiles) == 0 {
		slog.Warn("java.security: no java.javaSecurity files detected.")
		return nil
	}

	var javaSecurityFile *JavaSecurity
	if dockerConfig, ok := fs.GetConfig(); ok {
		javaSecurityFile = plugin.selectJavaSecurityFile(javaSecurityFiles, &dockerConfig)
	} else {
		javaSecurityFile = plugin.selectJavaSecurityFile(javaSecurityFiles, nil)
	}

	// log java.security file
	slog.Debug("java.security:", "content", javaSecurityFile.properties.String())

	err = javaSecurityFile.analyse(fs)
	if err != nil {
		slog.Error("java.security: could not analyse java.security file", "error", err)
		return err
	}

	var insufficientInformationErrors []error
	components := cyclonedx.ExtendFrom(*bom.Components)
	for _, component := range components.Components {
		if component.Component.Type != cdx.ComponentTypeCryptographicAsset {
			continue
		}
		if component.Component.CryptoProperties == nil {
			slog.Warn("java.security: component is a cryptographic asset but has empty properties", "component", component.Component.Name)
			continue
		}

		err := javaSecurityFile.updateComponent(component, components)
		if err != nil {
			if goerrors.Is(err, scannererrors.ErrInsufficientInformation) {
				insufficientInformationErrors = append(insufficientInformationErrors, err)
			} else {
				return fmt.Errorf("java.security: error while updating component %v\n%w", component.Component.Name, err)
			}
		}
	}
	// errors
	joinedInsufficientInformationErrors := goerrors.Join(insufficientInformationErrors...)
	if joinedInsufficientInformationErrors != nil {
		slog.Warn("java.security: analysis finished with insufficient information errors", "errors", goerrors.Join(insufficientInformationErrors...).Error())
	}

	*bom.Components = components.GetComponentSlice()
	slog.Info("java.security: analysis done!")
	return nil
}

func (plugin *Plugin) findJavaSecurityFiles(fs filesystem.Filesystem) ([]JavaSecurity, error) {
	var javaSecurityFiles []JavaSecurity
	if err := fs.WalkDir(
		func(path string) (err error) {
			if plugin.isConfigFile(path) {
				readCloser, err := fs.Open(path)
				if err != nil {
					return scannererrors.GetParsingFailedAlthoughCheckedError(err, plugin.GetName())
				}
				content, err := filesystem.ReadAllAndClose(readCloser)
				if err != nil {
					return scannererrors.GetParsingFailedAlthoughCheckedError(err, plugin.GetName())
				}
				config, err := properties.LoadString(string(content))
				if err != nil {
					return scannererrors.GetParsingFailedAlthoughCheckedError(err, plugin.GetName())
				}
				if config == nil {
					return fmt.Errorf("java.security: there are no java.security properties")
				}
				slog.Info("java.security: file found", "path", path)
				javaSecurityFiles = append(javaSecurityFiles, New(*config, path))
			}
			return nil
		}); err != nil {
		slog.Error("java.security: error while trying to find java.security files", "error", err)
		return nil, err
	}
	return javaSecurityFiles, nil
}

func (plugin *Plugin) selectJavaSecurityFile(javaSecurityFiles []JavaSecurity, dockerConfig *v1.Config) *JavaSecurity {
	if dockerConfig == nil {
		return plugin.chooseFirstConfiguration(javaSecurityFiles)
	}

	jdkPath, ok := getJDKPath(*dockerConfig)
	if !ok {
		return plugin.chooseFirstConfiguration(javaSecurityFiles)
	}
	for _, file := range javaSecurityFiles {
		if strings.HasPrefix(file.path, jdkPath) {
			slog.Info("java.security: selected java.security file", "path", file.path)
			return &file
		}
	}
	return plugin.chooseFirstConfiguration(javaSecurityFiles)
}

// Choose the first one
func (*Plugin) chooseFirstConfiguration(javaSecurityFiles []JavaSecurity) *JavaSecurity {
	for _, file := range javaSecurityFiles {
		slog.Info("java.security: selected java.security file", "path", file.path)
		return &file
	}
	return nil
}

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

func getJDKPath(dockerConfig v1.Config) (value string, ok bool) {
	jdkPath, ok := getJDKPathFromEnvironmentVariables(dockerConfig.Env)
	if ok {
		return jdkPath, true
	}

	jdkPath, ok = getJDKPathFromRunCommand(dockerConfig)
	if ok {
		return jdkPath, true
	}

	return "", false
}

func getJDKPathFromEnvironmentVariables(envVariables []string) (value string, ok bool) {
	for _, env := range envVariables {
		keyAndValue := strings.Split(env, "=")
		key := keyAndValue[0]
		value := keyAndValue[1]

		switch key {
		case "JAVA_HOME", "JDK_HOME":
			return value, true
		case "JRE_HOME":
			return filepath.Dir(value), true
		default:
			continue
		}
	}
	return "", false
}

func getJDKPathFromRunCommand(dockerConfig v1.Config) (value string, ok bool) {
	const lineSeparator = "/"
	for _, s := range append(dockerConfig.Cmd, dockerConfig.Entrypoint...) {
		if strings.Contains(s, "java") {
			// Try to extract only the binary path
			fields := strings.Fields(s)
			if len(fields) > 0 {
				path := fields[0]
				pathList := strings.Split(path, lineSeparator)
				for i, pathElement := range pathList {
					if strings.Contains(pathElement, "jdk") {
						return lineSeparator + filepath.Join(pathList[:i+1]...), true
					}
				}
			}
		}
	}
	return "", false
}

// JavaSecurity represents the java.security file(s) found on the system
type JavaSecurity struct {
	properties            properties.Properties
	path                  string
	tlsDisabledAlgorithms []AlgorithmRestriction
}

func New(p properties.Properties, path string) JavaSecurity {
	return JavaSecurity{properties: p, path: path}
}

func (javaSecurity *JavaSecurity) analyse(fs filesystem.Filesystem) error {
	// environment
	additionalSecurityProperties, overridden, err := javaSecurity.checkForEnvironmentConfigurations(fs)
	if err != nil {
		return err
	}
	if overridden && additionalSecurityProperties != nil {
		javaSecurity.properties.Merge(additionalSecurityProperties)
	}
	// tls and algorithm restriction
	restrictions, err := javaSecurity.extractTLSRules()
	if err != nil {
		return err
	}
	javaSecurity.tlsDisabledAlgorithms = restrictions

	return nil
}

// Assesses if the component is from a source affected by this type of config (e.g., a java file),
// requires "Evidence" and "Occurrences" to be present in the BOM
func (*JavaSecurity) isComponentAffectedByConfig(component cdx.Component) (bool, error) {
	if component.Evidence == nil || component.Evidence.Occurrences == nil { // If there is no evidence telling us that whether this component comes from a java file,
		// we cannot assess it
		return false, scannererrors.GetInsufficientInformationError("java.security: cannot evaluate due to missing evidence/occurrences in BOM", "java.security Plugin", "component", component.Name)
	}

	for _, occurrence := range *component.Evidence.Occurrences {
		if filepath.Ext(occurrence.Location) == ".java" {
			return true, nil
		}
	}
	return false, nil
}

// Update a single component; returns nil if component is not allowed
func (javaSecurity *JavaSecurity) updateComponent(component cyclonedx.ComponentWithConfidence, components *cyclonedx.ComponentsWithConfidenceSlice) error {
	ok, err := javaSecurity.isComponentAffectedByConfig(*component.Component)
	if !ok {
		return err
	}

	assetType := component.Component.CryptoProperties.AssetType
	switch assetType {
	case cdx.CryptoAssetTypeProtocol:
		return javaSecurity.updateProtocolComponent(component, components)
	default:
		return nil
	}
}

// Recursively get all comma-separated values of the property key. Recursion is necessary since values can include
// "include" directives which refer to other properties and include them in this property.
func (javaSecurity *JavaSecurity) extractValuesForKey(key string) (values []string, err error) {
	fullString, ok := javaSecurity.properties.Get(key)
	if ok {
		values = strings.Split(fullString, ",")
		for i, value := range values {
			values[i] = strings.TrimSpace(value)
		}
	}
	/*
		var toBeRemoved []int // Remember they include directives and remove them later
		for i, value := range values {
			if strings.HasPrefix(value, "include") {
				toBeRemoved = append(toBeRemoved, i)
				split := strings.Split(value, " ")
				if len(split) > 1 {
					includedValues, err := javaSecurity.extractValuesForKey(split[1])
					if err != nil {
						return includedValues, err
					}
					values = append(values, includedValues...)
				}
			}
		}
		for _, remove := range toBeRemoved {
			values = utils.RemoveFromSlice(values, remove)
		}*/
	return values, nil
}

// Parses the TLS Rules from the java.security file
// Returns a joined list of errors which occurred during parsing of algorithms
func (javaSecurity *JavaSecurity) extractTLSRules() ([]AlgorithmRestriction, error) {
	slog.Debug("java.security: extracting TLS rules from")

	algorithms, err := javaSecurity.extractValuesForKey("jdk.tls.disabledAlgorithms")
	if err != nil {
		return nil, err
	}

	if len(algorithms) == 0 {
		return nil, err
	}

	var algorithmRestriction []AlgorithmRestriction
	for _, algorithm := range algorithms {
		keySize := 0
		operator := keySizeOperatorNone
		name := algorithm

		if strings.Contains(algorithm, "jdkCA") ||
			strings.Contains(algorithm, "denyAfter") ||
			strings.Contains(algorithm, "usage") {
			slog.Warn("java.security: found constraint in java.security that is not supported in this version: ", "algorithm=", algorithm)
			continue
		}

		if strings.Contains(algorithm, "keySize") {
			split := strings.Split(algorithm, "keySize")
			if len(split) > 2 {
				slog.Warn(fmt.Sprintf("java.security: keySize check failed; too many elements (%v)", algorithm))
				continue
			}
			name = strings.TrimSpace(split[0])
			split[1] = strings.TrimSpace(split[1])
			keyRestrictions := strings.Split(split[1], " ")

			switch keyRestrictions[0] {
			case "<=":
				operator = keySizeOperatorLowerEqual
			case "<":
				operator = keySizeOperatorLower
			case "==":
				operator = keySizeOperatorEqual
			case "!=":
				operator = keySizeOperatorNotEqual
			case ">=":
				operator = keySizeOperatorGreaterEqual
			case ">":
				operator = keySizeOperatorGreater
			case "":
				operator = keySizeOperatorNone
			default:
				slog.Warn(fmt.Sprintf("java.security: could not analyse the following keySizeOperator %v (%v)", keyRestrictions[0], algorithm))
				continue
			}

			keySize, err = strconv.Atoi(keyRestrictions[1])
			if err != nil {
				slog.Warn(fmt.Sprintf("java.security: could dnot extraxt keysize (%v)", algorithm))
				continue
			}
		}

		algorithmRestriction = append(algorithmRestriction, AlgorithmRestriction{
			name:            name,
			keySize:         keySize,
			keySizeOperator: operator,
		})
	}
	return algorithmRestriction, nil
}

// Tries to get a config from the fs and checks the Config for potentially relevant information
func (javaSecurity *JavaSecurity) checkForEnvironmentConfigurations(fs filesystem.Filesystem) (*properties.Properties, bool, error) {
	slog.Debug("java.security: checking filesystem config for additional security properties")
	configuration, ok := fs.GetConfig()
	if !ok {
		slog.Debug("java.security: filesystem did not provide a config", "fs", fs.GetIdentifier())
		return nil, false, nil
	}
	additionalSecurityProperties, overridden, err := javaSecurity.checkForAdditionalSecurityFilesInDockerConfig(configuration, fs)
	return additionalSecurityProperties, overridden, err
}

// Searches the image config for potentially relevant CMD parameters and potentially adds new properties
func (javaSecurity *JavaSecurity) checkForAdditionalSecurityFilesInDockerConfig(config v1.Config, fs filesystem.Filesystem) (*properties.Properties, bool, error) {
	// We have to check if adding additional security files via CMD is even allowed via the java.security file (security.overridePropertiesFile property)
	overridePropertiesFile := javaSecurity.properties.GetBool("security.overridePropertiesFile", true)
	if !overridePropertiesFile {
		slog.Debug("java.security: properties don't allow additional security files. Stopping searching directly.", "fs", fs.GetIdentifier())
		return nil, false, nil
	}

	const securityCmdArgument = "-Djava.security.properties="
	// check for additional files added via CMD
	for _, command := range append(config.Cmd, config.Entrypoint...) {
		value, overridden, ok := extractFlagValue(command, securityCmdArgument)
		if !ok {
			continue
		}
		slog.Debug("java.security: found command that specifies new properties", "command", command)
		readCloser, err := fs.Open(value)
		if err != nil {
			slog.Warn("java.security: failed to read file specified via a command flag in the image configuration (e.g. Dockerfile); the image or image config is probably malformed; continuing without adding it.", "file", value)
			continue
		}
		content, err := filesystem.ReadAllAndClose(readCloser)
		if err != nil {
			slog.Warn("java.security: failed to read file specified via a command flag in the image configuration (e.g. Dockerfile); the image or image config is probably malformed; continuing without adding it.", "file", value)
			continue
		}
		additionalSecurityProperties, err := properties.LoadString(string(content))
		return additionalSecurityProperties, overridden, err
	}
	return nil, false, nil
}

// Tries to extract the value of a flag in command;
// returns ok if found; returns overwrite if double equals signs were used (==)
func extractFlagValue(command string, flag string) (string, bool, bool) {
	split := strings.Split(command, flag)
	if len(split) != 2 {
		return "", false, false
	}
	split = strings.Fields(split[1])
	value := split[0]
	if strings.HasPrefix(value, "=") {
		value = value[1:]
		return value, true, true
	}
	return value, false, true
}
