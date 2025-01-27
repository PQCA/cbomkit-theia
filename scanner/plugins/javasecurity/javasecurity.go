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
	cyclonedx "github.com/IBM/cbomkit-theia/provider/cyclonedx"
	log "github.com/sirupsen/logrus"
	"path/filepath"
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
	log.Warn("Current version does not take dynamic changes of java javaSecurity properties (e.g. via System.setProperty) into account.")

	javaSecurityFiles, err := plugin.findJavaSecurityFiles(fs)
	if err != nil {
		return err
	}

	if len(javaSecurityFiles) == 0 {
		log.Warn("No java.javaSecurity files detected.")
		return nil
	}

	var javaSecurityFile *JavaSecurity
	if dockerConfig, ok := fs.GetConfig(); ok {
		javaSecurityFile = plugin.selectJavaSecurityFile(javaSecurityFiles, &dockerConfig)
	} else {
		javaSecurityFile = plugin.selectJavaSecurityFile(javaSecurityFiles, nil)
	}

	javaSecurityFilePrint := fmt.Sprintf("content:\n%+v\n", javaSecurityFile)
	log.Info(javaSecurityFilePrint)

	err = javaSecurityFile.analyse(fs)
	if err != nil {
		log.Error("could not analyse java.security file: ", err)
		return err
	}

	var insufficientInformationErrors []error
	components := cyclonedx.ExtendFrom(*bom.Components)
	for _, component := range components.Components {
		if component.Component.Type != cdx.ComponentTypeCryptographicAsset {
			continue
		}
		if component.Component.CryptoProperties == nil {
			log.Warn("component is a cryptographic asset but has empty properties: ", component.Component.Name)
			continue
		}

		err := javaSecurityFile.updateComponent(component, components)
		if err != nil {
			if goerrors.Is(err, scannererrors.ErrInsufficientInformation) {
				insufficientInformationErrors = append(insufficientInformationErrors, err)
			} else {
				return fmt.Errorf("error while updating component %v\n%w", component.Component.Name, err)
			}
		}
	}
	// errors
	joinedInsufficientInformationErrors := goerrors.Join(insufficientInformationErrors...)
	if joinedInsufficientInformationErrors != nil {
		log.Warn("java.javaSecurity analysis finished with insufficient information errors:", goerrors.Join(insufficientInformationErrors...).Error())
	}

	*bom.Components = components.GetComponentSlice()
	log.Info("java.javaSecurity scan done!")
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
				log.Info("java.security file found: ", path)
				javaSecurityFiles = append(javaSecurityFiles, New(*config, path))
			}
			return nil
		}); err != nil {
		log.Error("Error while trying to find java.security files: ", err)
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
			log.Info("selected java.security file: ", file.path)
			return &file
		}
	}
	return plugin.chooseFirstConfiguration(javaSecurityFiles)
}

// Choose the first one
func (*Plugin) chooseFirstConfiguration(javaSecurityFiles []JavaSecurity) *JavaSecurity {
	for _, file := range javaSecurityFiles {
		log.Info("selected java.security file: ", file.path)
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
