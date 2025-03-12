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
	"testing"

	pluginpackage "github.com/IBM/cbomkit-theia/scanner/plugins"
	"github.com/stretchr/testify/assert"
)

func TestKeysPlugin_GetName(t *testing.T) {
	plugin, err := NewKeysPlugin()
	assert.NoError(t, err)
	assert.Equal(t, "Private Keys Scanner", plugin.GetName())
}

func TestKeysPlugin_GetExplanation(t *testing.T) {
	plugin, err := NewKeysPlugin()
	assert.NoError(t, err)
	assert.Equal(t, "Scans for private keys in the filesystem and adds them to the BOM", plugin.GetExplanation())
}

func TestKeysPlugin_GetType(t *testing.T) {
	plugin, err := NewKeysPlugin()
	assert.NoError(t, err)
	assert.Equal(t, pluginpackage.PluginTypeAppend, plugin.GetType())
}