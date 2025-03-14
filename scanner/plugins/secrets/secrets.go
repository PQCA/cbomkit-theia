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

package secrets

import (
	log "github.com/sirupsen/logrus"
	"strings"

	"github.com/IBM/cbomkit-theia/provider/filesystem"
	pemutility "github.com/IBM/cbomkit-theia/scanner/pem"
	"github.com/IBM/cbomkit-theia/scanner/plugins"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/gabriel-vasile/mimetype"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

func NewSecretsPlugin() (plugins.Plugin, error) {
	return &Plugin{}, nil
}

type Plugin struct{}

func (*Plugin) GetName() string {
	return "Secret Detection Plugin"
}

func (*Plugin) GetExplanation() string {
	return "Find Secrets & Keys"
}

func (*Plugin) GetType() plugins.PluginType {
	return plugins.PluginTypeAppend
}

type findingWithMetadata struct {
	report.Finding
	mime string
	raw  []byte
}

func (*Plugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	detector, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return err
	}

	// Detect findings
	findings := make([]findingWithMetadata, 0)
	if err = fs.WalkDir(func(path string) error {
		readCloser, err := fs.Open(path)
		if err != nil {
			return nil // skip and continue
		}

		mime, err := mimetype.DetectReader(readCloser)
		if err != nil {
			return nil // skip and continue
		}

		if !(strings.HasPrefix(mime.String(), "text") || mime.Parent() != nil && strings.HasPrefix(mime.Parent().String(), "text")) {
			return nil // skip and continue
		}

		content, err := filesystem.ReadAllAndClose(readCloser)
		if err != nil {
			log.WithField("path", path).Warn("Unable to read file")
			return nil
		}

		fragment := detect.Fragment{
			Raw:      string(content),
			FilePath: path,
		}

		for _, finding := range detector.Detect(fragment) {
			findings = append(findings, findingWithMetadata{
				Finding: finding,
				mime:    strings.Split(mime.String(), ";")[0],
				raw:     content,
			})
			log.WithFields(log.Fields{
				"type": finding.RuleID,
				"file": finding.File,
			}).Info("Secret detected")
		}
		return nil
	}); err != nil {
		log.WithError(err).Error("Error while trying to scan for secrets")
		return err
	}

	if len(findings) == 0 {
		log.Info("No secrets found.")
		return nil
	}

	// Create CDX Components
	components := make([]cdx.Component, 0)
	for _, finding := range findings {
		currentComponents, err := finding.getComponents()
		if err != nil {
			log.WithError(err).Warn("Could not add secret finding to BOM component")
			continue
		}
		components = append(components, currentComponents...)
	}
	// Write  bom
	*bom.Components = append(*bom.Components, components...)
	return nil
}

func (finding findingWithMetadata) getComponents() ([]cdx.Component, error) {
	switch finding.RuleID {
	case "private-key":
		blocks := pemutility.ParsePEMToBlocksWithTypeFilter(finding.raw, pemutility.Filter{
			FilterType: pemutility.PEMTypeFilterTypeAllowlist,
			List:       []pemutility.PEMBlockType{pemutility.PEMBlockTypePrivateKey, pemutility.PEMBlockTypeECPrivateKey, pemutility.PEMBlockTypeRSAPrivateKey, pemutility.PEMBlockTypeOPENSSHPrivateKey},
		})

		// Fallback
		if len(blocks) == 0 {
			return []cdx.Component{finding.getGenericSecretComponent()}, nil
		}

		for block := range blocks {
			currentComponents, err := pemutility.GenerateComponentsFromPEMKeyBlock(block)
			if err != nil {
				return []cdx.Component{}, err
			}

			for i := range currentComponents {
				if currentComponents[i].Description != "" {
					currentComponents[i].Description += "; "
				}
				currentComponents[i].Description += finding.Description
				currentComponents[i].MIMEType = finding.mime
				currentComponents[i].Evidence = &cdx.Evidence{
					Occurrences: &[]cdx.EvidenceOccurrence{
						{
							Location: finding.File,
							Line:     &finding.StartLine,
						},
					},
				}
			}
			return currentComponents, nil
		}
	}

	return []cdx.Component{finding.getGenericSecretComponent()}, nil
}

func (finding findingWithMetadata) getGenericSecretComponent() cdx.Component {
	return cdx.Component{
		Name:        finding.RuleID,
		Description: finding.Description,
		Type:        cdx.ComponentTypeCryptographicAsset,
		MIMEType:    finding.mime,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type: getRelatedCryptoAssetTypeFromRuleID(finding.RuleID),
			},
		},
		Evidence: &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{
				{
					Location: finding.File,
					Line:     &finding.StartLine,
				},
			},
		},
	}
}

func getRelatedCryptoAssetTypeFromRuleID(id string) cdx.RelatedCryptoMaterialType {
	switch {
	case id == "private-key":
		return cdx.RelatedCryptoMaterialTypePrivateKey
	case strings.Contains(id, "token") || strings.Contains(id, "jwt"):
		return cdx.RelatedCryptoMaterialTypeToken
	case strings.Contains(id, "key"):
		return cdx.RelatedCryptoMaterialTypeKey
	case strings.Contains(id, "password"):
		return cdx.RelatedCryptoMaterialTypePassword
	default:
		return cdx.RelatedCryptoMaterialTypeUnknown
	}
}
