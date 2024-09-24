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

package bomdag

import (
	"github.com/IBM/cbomkit-theia/scanner/hash"

	"github.com/dominikbraun/graph"
)

type bomDAGVertexType string

const (
	bomDAGVertexTypeRoot       bomDAGVertexType = "root"
	bomDAGVertexTypeComponent  bomDAGVertexType = "component"
	bomDAGVertexTypeOccurrence bomDAGVertexType = "occurrence"
)

type bomDAGVertex interface {
	getType() bomDAGVertexType
	string() string
}

func hashBOMDAGVertex(bomDAGVertex bomDAGVertex) VertexHash {
	switch bomDAGVertex.getType() {
	case bomDAGVertexTypeComponent:
		return hash.CdxComponentWithoutRefs(bomDAGVertex.(vertexComponent).Component)
	case bomDAGVertexTypeRoot:
		return VertexHash{0}
	case bomDAGVertexTypeOccurrence:
		return hash.Struct8Byte(bomDAGVertex.(vertexOccurrence))
	default:
		panic("Unsupported BOM DAG Vertex Type!")
	}
}

func getLabelForBOMDAGVertex(bomDAGVertex bomDAGVertex) func(*graph.VertexProperties) {
	return graph.VertexAttribute("label", bomDAGVertex.string())
}
