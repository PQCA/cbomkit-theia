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
	"os"
	"path/filepath"
	"strings"

	"github.com/IBM/cbomkit-theia/provider/filesystem"
	advancedcomponentslice "github.com/IBM/cbomkit-theia/scanner/componentwithconfidenceslice"
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
	return "Verify the executability of cryptographic assets from Java code\nAdds a confidence level (0-100) to the CBOM components to show how likely it is that this component is actually executable"
}

// GetType Get the type of the plugin
func (*Plugin) GetType() plugins.PluginType {
	return plugins.PluginTypeVerify
}

// UpdateBOM High-level function to update a list of components
// (e.g., remove components and add new ones) based on the underlying filesystem
func (javaSecurityPlugin *Plugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	slog.Warn("Current version of CBOMkit-theia does not take dynamic changes of java security properties (e.g. via System.setProperty) into account. Use with caution!")

	if bom.Components == nil {
		return nil
	}

	properties.ErrorHandler = func(err error) {
		slog.Error("Fatal error occurred during parsing of the java.security file", "err", err.Error())
		os.Exit(1)
	}

	configurations := make(map[string]*properties.Properties)

	err := fs.WalkDir(
		func(path string) (err error) {
			if javaSecurityPlugin.isConfigFile(path) {
				slog.Info("Adding java.security config file", "path", path)
				readCloser, err := fs.Open(path)
				if err != nil {
					return scannererrors.GetParsingFailedAlthoughCheckedError(err, javaSecurityPlugin.GetName())
				}
				content, err := filesystem.ReadAllClose(readCloser)
				if err != nil {
					return scannererrors.GetParsingFailedAlthoughCheckedError(err, javaSecurityPlugin.GetName())
				}
				config, err := properties.LoadString(string(content))
				if err != nil {
					return scannererrors.GetParsingFailedAlthoughCheckedError(err, javaSecurityPlugin.GetName())
				}

				configurations[path] = config
			}

			return err
		})

	if err != nil {
		return err
	}

	dockerConfig, ok := fs.GetConfig()
	var configuration *properties.Properties
	if ok && len(configurations) > 1 {
		configuration = javaSecurityPlugin.chooseMostLikelyConfiguration(configurations, dockerConfig)
	} else {
		configuration = chooseFirstConfiguration(configurations)
	}

	security, err := newJavaSecurity(configuration, fs)

	if err != nil {
		return err
	}

	insufficientInformationErrors := []error{}

	advancedCompSlice := advancedcomponentslice.FromComponentSlice(*bom.Components)

	for i, comp := range *bom.Components {
		if comp.Type == cdx.ComponentTypeCryptographicAsset {
			if comp.CryptoProperties != nil {
				err := security.updateComponent(i, advancedCompSlice)
				if err != nil {
					if goerrors.Is(err, scannererrors.ErrInsufficientInformation) {
						insufficientInformationErrors = append(insufficientInformationErrors, err)
					} else {
						return fmt.Errorf("scanner java: error while updating component %v\n%w", advancedCompSlice.GetByIndex(i).Name, err)
					}
				}

				slog.Debug("Component has been analyzed and confidence has been set", "component", advancedCompSlice.GetByIndex(i).Name, "confidence", advancedCompSlice.GetByIndex(i).Confidence.GetValue())
			} else {
				slog.Debug("Component is a crypto asset but has empty properties. Cannot evaluate that. Continuing.", "component", advancedCompSlice.GetByIndex(i).Name)
			}
		}
	}

	joinedInsufficientInformationErrors := goerrors.Join(insufficientInformationErrors...)
	if joinedInsufficientInformationErrors != nil {
		slog.Warn("Run finished with insufficient information errors", "errors", goerrors.Join(insufficientInformationErrors...).Error())
	}

	*bom.Components = advancedCompSlice.GetComponentSlice()

	return nil
}

func chooseFirstConfiguration(configurations map[string]*properties.Properties) *properties.Properties {
	// Choose the first one
	for _, prop := range configurations {
		return prop
	}

	return nil
}

func (*Plugin) chooseMostLikelyConfiguration(configurations map[string]*properties.Properties, dockerConfig v1.Config) (chosenProp *properties.Properties) {
	jdkPath, ok := getJDKPath(dockerConfig)
	if !ok {
		return chooseFirstConfiguration(configurations)
	}

	for path, conf := range configurations {
		if strings.HasPrefix(path, jdkPath) {
			return conf
		}
	}

	return chooseFirstConfiguration(configurations)
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

const LineSeparator = "/"

func getJDKPathFromRunCommand(dockerConfig v1.Config) (value string, ok bool) {
	for _, s := range append(dockerConfig.Cmd, dockerConfig.Entrypoint...) {
		if strings.Contains(s, "java") {
			// Try to extract only the binary path
			fields := strings.Fields(s)
			if len(fields) > 0 {
				path := fields[0]
				pathList := strings.Split(path, LineSeparator)
				for i, pathElement := range pathList {
					if strings.Contains(pathElement, "jdk") {
						return LineSeparator + filepath.Join(pathList[:i+1]...), true
					}
				}
			}
		}
	}

	return "", false
}
