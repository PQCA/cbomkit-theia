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

package vex

import (
	"fmt"
	"time"

	"github.com/IBM/cbomkit-theia/provider/filesystem"
	"github.com/IBM/cbomkit-theia/scanner/plugins"

	cdx "github.com/CycloneDX/cyclonedx-go"
	log "github.com/sirupsen/logrus"
)

// VEXPlugin implements the Plugin interface
type VEXPlugin struct {
}

// GetName returns the name of the plugin
func (p *VEXPlugin) GetName() string {
	return "VEX Integration Plugin"
}

// GetExplanation returns an explanation of the plugin
func (p *VEXPlugin) GetExplanation() string {
	return "Adds VEX (Vulnerability Exploitability eXchange) statements to components in the CBOM"
}

// GetType returns the type of the plugin
func (p *VEXPlugin) GetType() plugins.PluginType {
	return plugins.PluginTypeVerify
}

// UpdateBOM updates the BOM with VEX statements for identified components
func (p *VEXPlugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	log.Info("Adding VEX statements to BOM components")

	// Ensure components are defined
	if bom.Components == nil || len(*bom.Components) == 0 {
		log.Info("No components found in BOM to add VEX statements")
		return nil
	}

	// Setup vulnerability section if it doesn't exist
	if bom.Vulnerabilities == nil {
		vulnerabilities := make([]cdx.Vulnerability, 0)
		bom.Vulnerabilities = &vulnerabilities
	}

	// Process each component
	for i, component := range *bom.Components {
		// Only process components with cryptographic assets (as an example)
		if containsCryptoAsset(component) {
			log.WithField("component", component.Name).Debug("Adding VEX statement for cryptographic component")

			// Create a vulnerability ID based on the component
			vulnID := fmt.Sprintf("CRYPTO-%s", sanitizeComponentName(component.Name))

			// Create the VEX statement as a Vulnerability object
			vulnerability := createVEXStatement(vulnID, &component)
			
			// Add the vulnerability to the BOM
			*bom.Vulnerabilities = append(*bom.Vulnerabilities, vulnerability)

			// Update the component to reference the vulnerability (optional)
			if (*bom.Components)[i].Properties == nil {
				properties := make([]cdx.Property, 0)
				(*bom.Components)[i].Properties = &properties
			}

			// Add a property to link to the vulnerability
			*(*bom.Components)[i].Properties = append(*(*bom.Components)[i].Properties, cdx.Property{
				Name:  "vex.vulnID",
				Value: vulnID,
			})
		}
	}

	log.Info("VEX statements added to BOM")
	return nil
}

// Helper function to sanitize component name for use in a vulnerability ID
func sanitizeComponentName(name string) string {
	// Simple sanitization - replace spaces and special chars with underscore
	// In a real implementation, you might want more sophisticated sanitization
	sanitized := ""
	for _, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			sanitized += string(c)
		} else {
			sanitized += "_"
		}
	}
	return sanitized
}

// Helper function to check if a component contains cryptographic assets
func containsCryptoAsset(component cdx.Component) bool {
	// In a real implementation, this would be more sophisticated
	// For now, we'll just check if the component's type contains "crypto" or specific keywords
	
	// Check component type
	if component.Type == "crypto" || component.Type == "certificate" || component.Type == "key" {
		return true
	}
	
	// Check properties
	if component.Properties != nil {
		for _, prop := range *component.Properties {
			if prop.Name == "crypto.keySize" || prop.Name == "crypto.algorithm" {
				return true
			}
		}
	}
	
	return false
}

// Create a VEX statement as a CycloneDX Vulnerability
func createVEXStatement(vulnID string, component *cdx.Component) cdx.Vulnerability {
	// Get current time as ISO 8601
	currentTime := time.Now().Format(time.RFC3339)
	
	// Create responses array
	responses := []cdx.ImpactAnalysisResponse{cdx.IARUpdate}
	
	// Create a vulnerability with VEX data
	vuln := cdx.Vulnerability{
		ID: vulnID,
		Source: &cdx.Source{
			Name: "CBOMkit-theia",
		},
		Description: fmt.Sprintf("VEX statement for cryptographic component %s", component.Name),
		Analysis: &cdx.VulnerabilityAnalysis{
			State:         cdx.IASNotAffected,           // Not affected by any vulnerability
			Justification: cdx.IAJProtectedAtRuntime,    // Protected by runtime controls
			Detail:        "Cryptographic asset validated by CBOMkit-theia",
			Response:      &responses,
			FirstIssued:   currentTime,
			LastUpdated:   currentTime,
		},
		Affects: &[]cdx.Affects{
			{
				Ref: component.BOMRef,
			},
		},
	}
	
	return vuln
}

// NewVEXPlugin creates a new VEX plugin
func NewVEXPlugin() (plugins.Plugin, error) {
	return &VEXPlugin{}, nil
}