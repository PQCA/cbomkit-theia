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

package cyclonedx

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/IBM/cbomkit-theia/scanner/confidenceLevel"
)

// ComponentWithConfidence CycloneDX component bundled with according ConfidenceLevel
type ComponentWithConfidence struct {
	Component  *cdx.Component
	Confidence *confidenceLevel.ConfidenceLevel
}

// ComponentsWithConfidenceSlice Slice of componentWithConfidence with a map mapping BOMReference to index in the component slice;
// bomRefMap can be used to access members of components by BOMReference without searching for the BOMReference in the structs itself
type ComponentsWithConfidenceSlice struct {
	Components []ComponentWithConfidence
	bomRefMap  map[cdx.BOMReference]int
}

func NewComponentWithConfidence(component *cdx.Component) *ComponentWithConfidence {
	return &ComponentWithConfidence{Component: component, Confidence: confidenceLevel.New()}
}

func NewComponentsWithConfidenceSlice() *ComponentsWithConfidenceSlice {
	return &ComponentsWithConfidenceSlice{Components: make([]ComponentWithConfidence, 0), bomRefMap: make(map[cdx.BOMReference]int)}
}

// Transform Generate a AdvancedComponentSlice from a slice of components
func Transform(slice []cdx.Component) *ComponentsWithConfidenceSlice {
	advancedComponentSlice := ComponentsWithConfidenceSlice{
		Components: make([]ComponentWithConfidence, 0, len(slice)),
		bomRefMap:  make(map[cdx.BOMReference]int),
	}

	for i, comp := range slice {
		advancedComponentSlice.Components = append(advancedComponentSlice.Components, ComponentWithConfidence{
			Component:  &comp,
			Confidence: confidenceLevel.New(),
		})

		if comp.BOMRef != "" {
			advancedComponentSlice.bomRefMap[cdx.BOMReference(comp.BOMRef)] = i
		}
	}
	return &advancedComponentSlice
}

// GetByIndex Get member of AdvancedComponentSlice by index
func (advancedComponentSlice *ComponentsWithConfidenceSlice) GetByIndex(i int) *ComponentWithConfidence {
	return &advancedComponentSlice.Components[i]
}

// GetByRef Get member of AdvancedComponentSlice by BOMReference
func (advancedComponentSlice *ComponentsWithConfidenceSlice) GetByRef(ref cdx.BOMReference) (*ComponentWithConfidence, bool) {
	i, ok := advancedComponentSlice.bomRefMap[ref]
	if !ok {
		return &ComponentWithConfidence{}, false
	} else {
		return &advancedComponentSlice.Components[i], true
	}
}

// GetComponentSlice Generate CycloneDX Components from this AdvancedComponentSlice; automatically sets the confidence_level property
func (advancedComponentSlice *ComponentsWithConfidenceSlice) GetComponentSlice() []cdx.Component {
	components := make([]cdx.Component, 0, len(advancedComponentSlice.Components))
	for _, component := range advancedComponentSlice.Components {
		if component.Confidence != nil {
			addPropertyOrCreateNew(component.Component, component.Confidence.GetProperty())
		}
		components = append(components, *component.Component)
	}
	return components
}

func addPropertyOrCreateNew(comp *cdx.Component, prop cdx.Property) {
	if comp.Properties == nil {
		comp.Properties = new([]cdx.Property)
	}
	*comp.Properties = append(*comp.Properties, prop)
}
