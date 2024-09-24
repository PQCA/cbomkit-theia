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
	"encoding/hex"
	"errors"
	"fmt"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/dominikbraun/graph"
	"log/slog"
)

// VertexHash BomDAGVertexHash Type that holds the hash of a BomDAG vertex
type VertexHash = [8]byte

// BomDAG represents a directed, acyclic graph of several interconnected components
type BomDAG struct {
	graph.Graph[VertexHash, bomDAGVertex]
	Root VertexHash // Hash of the root component
}

func NewBomDAG() BomDAG {
	rootComponent := vertexRoot{}
	rootHash := hashBOMDAGVertex(rootComponent)
	g := graph.New(hashBOMDAGVertex, graph.Acyclic(), graph.Directed(), graph.PreventCycles(), graph.Rooted())
	err := g.AddVertex(rootComponent, getLabelForBOMDAGVertex(rootComponent))
	if err != nil {
		return BomDAG{}
	}
	return BomDAG{
		Graph: g,
		Root:  rootHash,
	}
}

// BomDAGDependencyType Type defining the different types of dependencies that components can have in the BomDAG
type BomDAGDependencyType string

const (
	DependencyTypeDependsOn                                            BomDAGDependencyType = "dependsOn"
	DependencyTypeCertificatePropertiesSignatureAlgorithmRef           BomDAGDependencyType = "CertificatePropertiesSignatureAlgorithmRef"
	DependencyTypeCertificatePropertiesSubjectPublicKeyRef             BomDAGDependencyType = "CertificatePropertiesSubjectPublicKeyRef"
	DependencyTypeRelatedCryptoMaterialPropertiesAlgorithmRef          BomDAGDependencyType = "RelatedCryptoMaterialPropertiesAlgorithmRef"
	DependencyTypeRelatedCryptoMaterialPropertiesSecuredByAlgorithmRef BomDAGDependencyType = "RelatedCryptoMaterialPropertiessecuredByAlgorithmRef"
	DependencyTypeProtocolPropertiesCryptoRefArrayElement              BomDAGDependencyType = "protocolPropertiescryptoRefArray"
	DependencyTypeOccurrence                                           BomDAGDependencyType = "occurrence"
)

func EdgeDependencyType(dependencyType BomDAGDependencyType) func(*graph.EdgeProperties) {
	return func(e *graph.EdgeProperties) {
		e.Attributes[string(dependencyType)] = ""
		if _, ok := e.Attributes["label"]; !ok {
			e.Attributes["label"] = string(dependencyType)
		} else {
			e.Attributes["label"] = fmt.Sprintf("%v; %v", e.Attributes["label"], string(dependencyType))
		}
	}
}

// GetCDXComponents Generate slice of cyclonedx-go components from the graph; also return a map of dependencies (e.g. "bomref1" depends on "bomref2" and "bomref3")
func (bomDAG *BomDAG) GetCDXComponents() ([]cdx.Component, map[cdx.BOMReference][]string, error) {
	components := make([]cdx.Component, 0)
	dependencyMap := make(map[cdx.BOMReference][]string, 0)

	adjacencyMap, err := bomDAG.AdjacencyMap()

	if err != nil {
		return components, dependencyMap, err
	}

	for compHash, compOutgoingEdges := range adjacencyMap {
		bomDAGVertex, _ := bomDAG.Vertex(compHash)

		if bomDAGVertex.getType() != bomDAGVertexTypeComponent {
			continue
		}

		component := bomDAGVertex.(vertexComponent).Component

		component.BOMRef = hex.EncodeToString(compHash[:])

		for _, edge := range compOutgoingEdges {
			targetBomRef := cdx.BOMReference(hex.EncodeToString(edge.Target[:]))
			for edgeType := range edge.Properties.Attributes {
				switch edgeType {
				case string(DependencyTypeDependsOn):
					if _, ok := dependencyMap[cdx.BOMReference(component.BOMRef)]; !ok {
						dependencyMap[cdx.BOMReference(component.BOMRef)] = make([]string, 0)
					}
					dependencyMap[cdx.BOMReference(component.BOMRef)] = append(dependencyMap[cdx.BOMReference(component.BOMRef)], string(targetBomRef))
				case string(DependencyTypeCertificatePropertiesSignatureAlgorithmRef):
					component.CryptoProperties.CertificateProperties.SignatureAlgorithmRef = targetBomRef
				case string(DependencyTypeCertificatePropertiesSubjectPublicKeyRef):
					component.CryptoProperties.CertificateProperties.SubjectPublicKeyRef = targetBomRef
				case string(DependencyTypeRelatedCryptoMaterialPropertiesAlgorithmRef):
					component.CryptoProperties.RelatedCryptoMaterialProperties.AlgorithmRef = targetBomRef
				case string(DependencyTypeRelatedCryptoMaterialPropertiesSecuredByAlgorithmRef):
					component.CryptoProperties.RelatedCryptoMaterialProperties.SecuredBy.AlgorithmRef = targetBomRef
				case string(DependencyTypeProtocolPropertiesCryptoRefArrayElement):
					if component.CryptoProperties.ProtocolProperties.CryptoRefArray == nil {
						component.CryptoProperties.ProtocolProperties.CryptoRefArray = new([]cdx.BOMReference)
					}
					*component.CryptoProperties.ProtocolProperties.CryptoRefArray = append(*component.CryptoProperties.ProtocolProperties.CryptoRefArray, targetBomRef)
				case string(DependencyTypeOccurrence):
					targetVertex, _ := bomDAG.Vertex(edge.Target)
					*component.Evidence.Occurrences = append(*component.Evidence.Occurrences, targetVertex.(vertexOccurrence).EvidenceOccurrence)
				}
			}
		}
		components = append(components, component)
	}

	return components, dependencyMap, nil
}

// Merge other into the BomDag this method was called on
func (bomDAG *BomDAG) Merge(other BomDAG) error {
	adjacencyMap, err := other.AdjacencyMap()
	if err != nil {
		return fmt.Errorf("failed to get adjacency map: %w", err)
	}

	for hash := range adjacencyMap {
		vertex, properties, err := other.VertexWithProperties(hash)
		if err != nil {
			return fmt.Errorf("failed to get vertex %v: %w", hash, err)
		}

		if err = bomDAG.AddVertex(vertex, copyVertexProperties(properties)); err != nil {
			continue
		}
	}

	edges, err := other.Edges()
	if err != nil {
		return fmt.Errorf("failed to get edges: %w", err)
	}

	for _, otherEdge := range edges {
		if err := bomDAG.AddEdge(copyEdge(otherEdge)); err == graph.ErrEdgeAlreadyExists {
			if err := bomDAG.mergeEdgePropertyAttributes(otherEdge); err != nil {
				return fmt.Errorf("failed to add (%v, %v): %w", otherEdge.Source, otherEdge.Target, err)
			}
		} else if err != nil {
			return fmt.Errorf("failed to add (%v, %v): %w", otherEdge.Source, otherEdge.Target, err)
		}
	}

	return nil
}

func (bomDAG *BomDAG) mergeEdgePropertyAttributes(otherEdge graph.Edge[VertexHash]) error {
	mainEdge, err := bomDAG.Edge(otherEdge.Source, otherEdge.Target)

	if err != nil {
		return err
	}

	if mainEdge.Properties.Data != otherEdge.Properties.Data ||
		mainEdge.Properties.Weight != otherEdge.Properties.Weight {
		return fmt.Errorf("both edges should have the same source, target, data and weight to merge their edge attributes")
	}

	for key, otherValue := range otherEdge.Properties.Attributes {
		mainValue, ok := mainEdge.Properties.Attributes[key]
		if ok {
			if mainValue != otherValue {
				return fmt.Errorf("attribute %v cannot be merged (both are set and cannot merge strings); mainValue: %v, otherValue: %v", key, mainValue, otherValue)
			}
		} else {
			err = bomDAG.UpdateEdge(otherEdge.Source, otherEdge.Target, graph.EdgeAttribute(key, otherValue))
			if err != nil {
				slog.Error(err.Error())
			}
		}
	}

	return nil
}

// Function taken from [graph] (had to copy since it is private);
// Credit goes to [Dominik Braun]
//
// [graph]: https://github.com/dominikbraun/graph/blob/a999520a23a8fc232bfe3ef40f69a6f7d9f5bfde/directed.go#L305
// [Dominik Braun]: https://github.com/dominikbraun
func copyEdge[K comparable](edge graph.Edge[K]) (K, K, func(properties *graph.EdgeProperties)) {
	copyProperties := func(p *graph.EdgeProperties) {
		for k, v := range edge.Properties.Attributes {
			p.Attributes[k] = v
		}
		p.Weight = edge.Properties.Weight
		p.Data = edge.Properties.Data
	}

	return edge.Source, edge.Target, copyProperties
}

// Function taken from [graph] (had to copy since it is private);
// Credit goes to [Dominik Braun]
//
// [graph]: https://github.com/dominikbraun/graph/blob/a999520a23a8fc232bfe3ef40f69a6f7d9f5bfde/sets.go#L117
// [Dominik Braun]: https://github.com/dominikbraun
func copyVertexProperties(source graph.VertexProperties) func(*graph.VertexProperties) {
	return func(p *graph.VertexProperties) {
		for k, v := range source.Attributes {
			p.Attributes[k] = v
		}
		p.Weight = source.Weight
	}
}

// AddCDXComponent Add a component to this graph;
// This should be mainly used to add components to the graph
func (bomDAG *BomDAG) AddCDXComponent(value cdx.Component, options ...func(*graph.VertexProperties)) (valueHash VertexHash, err error) {
	// Extract the occurrence component
	var occurrenceHashes []VertexHash
	if value.Evidence != nil && value.Evidence.Occurrences != nil && len(*value.Evidence.Occurrences) > 0 {
		occurrenceHashes = make([]VertexHash, len(*value.Evidence.Occurrences))
		for i, occurrence := range *value.Evidence.Occurrences {
			hash, err := bomDAG.getVertexOrAddNew(vertexOccurrence{occurrence})
			if err != nil {
				return VertexHash{}, err
			}
			occurrenceHashes[i] = hash
		}

		// Clean it all up
		value.Evidence.Occurrences = new([]cdx.EvidenceOccurrence)
	}

	// Create the component and link to occurrences
	valueHash, err = bomDAG.getVertexOrAddNew(vertexComponent{value}, options...)
	if err != nil {
		return valueHash, err
	}

	for _, occurrenceHash := range occurrenceHashes {
		err = bomDAG.AddEdge(valueHash, occurrenceHash, EdgeDependencyType(DependencyTypeOccurrence))
		if err != nil {
			slog.Error(err.Error())
		}
	}

	return valueHash, nil
}

func (bomDAG *BomDAG) getVertexOrAddNew(value bomDAGVertex, options ...func(*graph.VertexProperties)) (hash VertexHash, err error) {
	hash = hashBOMDAGVertex(value)

	// Does the component already exist?
	_, err = bomDAG.Vertex(hash)
	if !errors.Is(err, graph.ErrVertexNotFound) {
		return hash, nil
	}

	err = bomDAG.AddVertex(value, append(options, getLabelForBOMDAGVertex(value))...)
	return hash, err
}
