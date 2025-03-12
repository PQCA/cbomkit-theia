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

package keys

import (
	"encoding/pem"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/IBM/cbomkit-theia/provider/filesystem"
	pemlib "github.com/IBM/cbomkit-theia/scanner/pem"
	pluginpackage "github.com/IBM/cbomkit-theia/scanner/plugins"

	cdx "github.com/CycloneDX/cyclonedx-go"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// KeysPlugin implements the Plugin interface
type KeysPlugin struct{}

// NewKeysPlugin returns a new instance of the KeysPlugin
func NewKeysPlugin() (pluginpackage.Plugin, error) {
	return &KeysPlugin{}, nil
}

// GetName returns the name of the plugin
func (p *KeysPlugin) GetName() string {
	return "Private Keys Scanner"
}

// GetExplanation returns an explanation of what the plugin does
func (p *KeysPlugin) GetExplanation() string {
	return "Scans for private keys in the filesystem and adds them to the BOM"
}

// GetType returns the type of the plugin
func (p *KeysPlugin) GetType() pluginpackage.PluginType {
	return pluginpackage.PluginTypeAppend
}

// Private key extensions to search for
var privateKeyExtensions = []string{
	".pem", ".key", ".pkcs8", ".p8", ".pkcs12", ".p12", ".pfx", ".keystore", ".jks",
}

// UpdateBOM implements the Plugin interface
func (p *KeysPlugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	log.Info("Looking for private keys...")

	var files []string

	// Walk the filesystem looking for files with potential private key extensions
	err := fs.WalkDir(func(path string) error {
		ext := strings.ToLower(filepath.Ext(path))
		for _, keyExt := range privateKeyExtensions {
			if ext == keyExt {
				files = append(files, path)
				break
			}
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to walk filesystem: %w", err)
	}

	// Process each file that might contain private keys
	for _, filePath := range files {
		// Skip large files
		maxFileSize := viper.GetInt64("keys.max_file_size")
		if maxFileSize <= 0 {
			maxFileSize = 1024 * 1024 // Default to 1MB
		}

		// Open and read the file
		reader, err := fs.Open(filePath)
		if err != nil {
			log.WithError(err).Warnf("Failed to open file %s", filePath)
			continue
		}

		data, err := filesystem.ReadAllAndClose(reader)
		if err != nil {
			log.WithError(err).Warnf("Failed to read file %s", filePath)
			continue
		}

		// Skip large files
		if int64(len(data)) > maxFileSize {
			log.Warnf("Skipping large file: %s (size: %d bytes)", filePath, len(data))
			continue
		}

		// Filter for private keys only
		privateKeyFilter := pemlib.Filter{
			FilterType: pemlib.PEMTypeFilterTypeAllowlist,
			List: []pemlib.PEMBlockType{
				pemlib.PEMBlockTypePrivateKey,
				pemlib.PEMBlockTypeEncryptedPrivateKey,
				pemlib.PEMBlockTypeRSAPrivateKey,
				pemlib.PEMBlockTypeECPrivateKey,
				pemlib.PEMBlockTypeOPENSSHPrivateKey,
			},
		}

		// Parse PEM blocks
		blocks := pemlib.ParsePEMToBlocksWithTypeFilter(data, privateKeyFilter)
		if len(blocks) == 0 {
			continue
		}

		log.Infof("Found %d private key(s) in %s", len(blocks), filePath)

		// Add each key to the BOM
		for block, blockType := range blocks {
			components, err := processPrivateKeyBlock(block, blockType, filePath)
			if err != nil {
				log.WithError(err).Warnf("Failed to process private key in %s", filePath)
				continue
			}

			// Add the components to the BOM
			*bom.Components = append(*bom.Components, components...)
		}
	}

	return nil
}

// Process a private key block and return components
func processPrivateKeyBlock(block *pem.Block, blockType pemlib.PEMBlockType, filePath string) ([]cdx.Component, error) {
	components, err := pemlib.GenerateComponentsFromPEMKeyBlock(block)
	if err != nil {
		return nil, err
	}

	// Enhance components with additional metadata
	for i := range components {
		if components[i].CryptoProperties != nil &&
			components[i].CryptoProperties.RelatedCryptoMaterialProperties != nil &&
			components[i].CryptoProperties.RelatedCryptoMaterialProperties.Type == cdx.RelatedCryptoMaterialTypePrivateKey {

			// Add a file path as external reference
			if components[i].ExternalReferences == nil {
				components[i].ExternalReferences = &[]cdx.ExternalReference{}
			}
			*components[i].ExternalReferences = append(*components[i].ExternalReferences, cdx.ExternalReference{
				Type:    "other",
				URL:     fmt.Sprintf("file://%s", filePath),
				Comment: "File containing the private key",
			})

			// Add confidence level as property
			if components[i].Properties == nil {
				components[i].Properties = &[]cdx.Property{}
			}
			*components[i].Properties = append(*components[i].Properties, cdx.Property{
				Name:  "confidence.level",
				Value: "1.0", // High confidence
			})

			// Add warning property
			*components[i].Properties = append(*components[i].Properties, cdx.Property{
				Name:  "security.warning",
				Value: "Private key detected - Handle with care",
			})
		}
	}

	return components, nil
}
