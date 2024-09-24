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

package confidencelevel

import (
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// ConfidenceLevel A confidence level represents a level of confidence
// Example:
// A ConfidenceLevel could be used to represent the confidence that an algorithm is executable in a certain environment.
type ConfidenceLevel struct {
	count int
	sum   int
	value int
}

// Modifier ConfidenceLevelModifier Modifiers for the ConfidenceLevel
type Modifier int

// Constant value that can be used for the modification of a ConfidenceLevel
const (
	confidenceLevelMax              = 100
	confidenceLevelDefault          = 50
	confidenceLevelMin              = 0
	PositiveExtreme        Modifier = 50
	PositiveHigh           Modifier = 30
	PositiveMedium         Modifier = 15
	PositiveLow            Modifier = 5
	NegativeExtreme        Modifier = -50
	NegativeHigh           Modifier = -30
	NegativeMedium         Modifier = -15
	NegativeLow            Modifier = -5
)

// New Get a new ConfidenceLevel; default value is confidenceLevelDefault
func New() *ConfidenceLevel {
	return &ConfidenceLevel{
		count: 0,
		sum:   0,
		value: confidenceLevelDefault,
	}
}

// GetValue Get the value of the ConfidenceLevel
func (confidenceLevel *ConfidenceLevel) GetValue() int {
	return confidenceLevel.value
}

// GetProperty Generate a CycloneDX component property from this confidence
func (confidenceLevel *ConfidenceLevel) GetProperty() cdx.Property {
	return cdx.Property{
		Name:  "confidence_level",
		Value: fmt.Sprint(confidenceLevel.value),
	}
}

// Modify the confidence level using one of the predefined ConfidenceLevelModifier values
func (confidenceLevel *ConfidenceLevel) Modify(modifier Modifier) {
	confidenceLevel.value += int(modifier)

	if confidenceLevel.value < confidenceLevelMin {
		confidenceLevel.value = confidenceLevelMin
	} else if confidenceLevel.value > confidenceLevelMax {
		confidenceLevel.value = confidenceLevelMax
	}
}

/*
	Sets the value of this ConfidenceLevel to the average of all sub ConfidenceLevels; set ignoreDefaultConfidence to ignore sub ConfidenceLevels with value confidenceLevelDefault

Example:

	a, b, c := New(), New(),  New()
	a.AddSubConfidenceLevel(b, false)
	a.AddSubConfidenceLevel(c, false)

Now a.GetValue() returns the average of b.GetValue() and c.GetValue(). (a.value = (b.value+c.value)/2)

Warning: a, b and c are not permanently linked by this. AddSubConfidenceLevel just calculates the average once this function is called
*/
func (confidenceLevel *ConfidenceLevel) AddSubConfidenceLevel(sub ConfidenceLevel, ignoreDefaultConfidence bool) {
	if ignoreDefaultConfidence && sub.value == confidenceLevelDefault {
		return
	}
	confidenceLevel.count++
	confidenceLevel.sum += sub.value
	confidenceLevel.value = confidenceLevel.sum / confidenceLevel.count
}
