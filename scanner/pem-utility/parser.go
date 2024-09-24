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

package pemutility

import (
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"

	"golang.org/x/crypto/ssh"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
)

// Filter that describes which PEMBlockTypes to allow
type Filter struct {
	FilterType PEMTypeFilterType
	List       []PEMBlockType
}

// PEMTypeFilterType Used to specify whether a filter is an allow- or blocklist
type PEMTypeFilterType bool

const (
	PEMTypeFilterTypeAllowlist PEMTypeFilterType = true  // Allowlist
	PEMTypeFilterTypeBlocklist PEMTypeFilterType = false // Blocklist
)

// PEMBlockType A not complete list of PEMBlockTypes that can be detected currently
type PEMBlockType string

const (
	PEMBlockTypeCertificate         PEMBlockType = "CERTIFICATE"
	PEMBlockTypePrivateKey          PEMBlockType = "PRIVATE KEY"
	PEMBlockTypeEncryptedPrivateKey PEMBlockType = "ENCRYPTED PRIVATE KEY"
	PEMBlockTypePublicKey           PEMBlockType = "PUBLIC KEY"
	PEMBlockTypeECPrivateKey        PEMBlockType = "EC PRIVATE KEY"
	PEMBlockTypeRSAPrivateKey       PEMBlockType = "RSA PRIVATE KEY"
	PEMBlockTypeRSAPublicKey        PEMBlockType = "RSA PUBLIC KEY"
	PEMBlockTypeOPENSSHPrivateKey   PEMBlockType = "OPENSSH PRIVATE KEY"
)

func parsePEMToBlocks(raw []byte) []*pem.Block {
	rest := raw
	var blocks []*pem.Block
	for len(rest) != 0 {
		var newBlock *pem.Block
		newBlock, rest = pem.Decode(rest)
		if newBlock != nil {
			blocks = append(blocks, newBlock)
		} else {
			break
		}
	}
	return blocks
}

// ParsePEMToBlocksWithTypes Parse the []byte of a PEM file to a map
// containing the *pem.Block and a PEMBlockType for each block
func ParsePEMToBlocksWithTypes(raw []byte) map[*pem.Block]PEMBlockType {
	blocks := parsePEMToBlocks(raw)

	blocksWithType := make(map[*pem.Block]PEMBlockType, len(blocks))

	for _, block := range blocks {
		blocksWithType[block] = PEMBlockType(block.Type)
	}

	return blocksWithType
}

// ParsePEMToBlocksWithTypeFilter Just like ParsePEMToBlocksWithTypes but uses a filter for filtering
func ParsePEMToBlocksWithTypeFilter(raw []byte, filter Filter) map[*pem.Block]PEMBlockType {
	blocksWithType := ParsePEMToBlocksWithTypes(raw)
	filteredBlocksWithType := make(map[*pem.Block]PEMBlockType)

	for block, t := range blocksWithType {
		if slices.Contains(filter.List, t) == bool(filter.FilterType) {
			filteredBlocksWithType[block] = t
		}
	}

	return filteredBlocksWithType
}

var errUnknownKeyAlgorithm = errors.New("key block uses unknown algorithm")

// GenerateComponentsFromPEMKeyBlock Generate cyclone-go components from a block containing a key
func GenerateComponentsFromPEMKeyBlock(block *pem.Block) ([]cdx.Component, error) {
	switch PEMBlockType(block.Type) {

	case PEMBlockTypePrivateKey:
		genericKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return []cdx.Component{}, err
		}
		return GenerateComponentsFromKey(genericKey)

	case PEMBlockTypeECPrivateKey:
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return []cdx.Component{}, err
		}
		return []cdx.Component{getECDSAPrivateKeyComponent(key), getECDSAPublicKeyComponent(&key.PublicKey)}, nil

	case PEMBlockTypeRSAPrivateKey:
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return []cdx.Component{}, err
		}
		return []cdx.Component{getRSAPrivateKeyComponent(), getRSAPublicKeyComponent(&key.PublicKey)}, nil

	case PEMBlockTypePublicKey:
		genericKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return []cdx.Component{}, err
		}
		return GenerateComponentsFromKey(genericKey)

	case PEMBlockTypeRSAPublicKey:
		key, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return []cdx.Component{}, err
		}
		return []cdx.Component{getRSAPublicKeyComponent(key)}, nil

	case PEMBlockTypeOPENSSHPrivateKey:
		genericKey, err := ssh.ParseRawPrivateKey(pem.EncodeToMemory(block))
		if err != nil {
			return []cdx.Component{}, err
		}
		return GenerateComponentsFromKey(genericKey)

	default:
		return []cdx.Component{}, fmt.Errorf("could not generate cyclone-dx component from pem: pem file block type is unknown or not a key")
	}
}

func GenerateComponentsFromKey(genericKey any) ([]cdx.Component, error) {
	switch key := genericKey.(type) {
	case *rsa.PublicKey:
		return []cdx.Component{getRSAPublicKeyComponent(key)}, nil
	case *dsa.PublicKey:
		return []cdx.Component{getDSAPublicKeyComponent(key)}, nil
	case *ecdsa.PublicKey:
		return []cdx.Component{getECDSAPublicKeyComponent(key)}, nil
	case *ed25519.PublicKey:
		return []cdx.Component{getED25519PublicKeyComponent(*key)}, nil
	case *ecdh.PublicKey:
		return []cdx.Component{getECDHPublicKeyComponent(key)}, nil
	case *rsa.PrivateKey:
		return []cdx.Component{getRSAPrivateKeyComponent(), getRSAPublicKeyComponent(&key.PublicKey)}, nil
	case *ecdsa.PrivateKey:
		return []cdx.Component{getECDSAPrivateKeyComponent(key), getECDSAPublicKeyComponent(&key.PublicKey)}, nil
	case ed25519.PrivateKey:
		return []cdx.Component{getED25519PrivateKeyComponent(), getED25519PublicKeyComponent(key.Public().(ed25519.PublicKey))}, nil
	case *ecdh.PrivateKey:
		return []cdx.Component{getECDHPrivateKeyComponent(), getECDHPublicKeyComponent(key.Public().(*ecdh.PublicKey))}, nil
	default:
		return []cdx.Component{}, errUnknownKeyAlgorithm
	}
}

func getGenericKeyComponent() cdx.Component {
	return cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		BOMRef: uuid.New().String(),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Format: "PEM",
			},
		},
	}
}

func getGenericPublicKeyComponent() cdx.Component {
	c := getGenericKeyComponent()
	c.CryptoProperties.RelatedCryptoMaterialProperties.Type = cdx.RelatedCryptoMaterialTypePublicKey
	return c
}

func getGenericPrivateKeyComponent() cdx.Component {
	c := getGenericKeyComponent()
	c.CryptoProperties.RelatedCryptoMaterialProperties.Type = cdx.RelatedCryptoMaterialTypePrivateKey
	return c
}

func getRSAPublicKeyComponent(key *rsa.PublicKey) cdx.Component {
	c := getGenericPublicKeyComponent()
	size := key.Size() * 8
	c.Name = fmt.Sprintf("RSA-%v", size)
	c.CryptoProperties.RelatedCryptoMaterialProperties.Size = &size
	c.CryptoProperties.OID = "1.2.840.113549.1.1.1"
	keyValue, err := x509.MarshalPKIXPublicKey(key)
	if err == nil {
		c.CryptoProperties.RelatedCryptoMaterialProperties.Value = base64.StdEncoding.EncodeToString(keyValue)
	}
	return c
}

func getRSAPrivateKeyComponent() cdx.Component {
	c := getGenericPrivateKeyComponent()
	c.Name = "RSA"
	c.CryptoProperties.OID = "1.2.840.113549.1.1.1"
	return c
}

func getECDSAPublicKeyComponent(key *ecdsa.PublicKey) cdx.Component {
	c := getGenericPublicKeyComponent()
	c.Name = "ECDSA"
	c.Description = fmt.Sprintf("Curve: %v", key.Curve.Params().Name)
	c.CryptoProperties.OID = "1.2.840.10045.2.1"
	keyValue, err := x509.MarshalPKIXPublicKey(key)
	if err == nil {
		c.CryptoProperties.RelatedCryptoMaterialProperties.Value = base64.StdEncoding.EncodeToString(keyValue)
	}
	return c
}

func getECDSAPrivateKeyComponent(key *ecdsa.PrivateKey) cdx.Component {
	c := getGenericPrivateKeyComponent()
	c.Name = "ECDSA"
	c.Description = fmt.Sprintf("Curve: %v", key.Curve.Params().Name)
	return c
}

func getED25519PublicKeyComponent(key ed25519.PublicKey) cdx.Component {
	c := getGenericPublicKeyComponent()
	c.Name = "ED25519"
	size := len([]byte(key)) * 8
	c.CryptoProperties.RelatedCryptoMaterialProperties.Size = &size
	keyValue, err := x509.MarshalPKIXPublicKey(key)
	if err == nil {
		c.CryptoProperties.RelatedCryptoMaterialProperties.Value = base64.StdEncoding.EncodeToString(keyValue)
	}
	return c
}

func getED25519PrivateKeyComponent() cdx.Component {
	c := getGenericPrivateKeyComponent()
	c.Name = "ED25519"
	return c
}

func getECDHPublicKeyComponent(key *ecdh.PublicKey) cdx.Component {
	c := getGenericPublicKeyComponent()
	c.Name = "ECDH"
	size := len(key.Bytes()) * 8
	c.CryptoProperties.RelatedCryptoMaterialProperties.Size = &size
	c.CryptoProperties.OID = "1.2.840.10045.2.1"
	keyValue, err := x509.MarshalPKIXPublicKey(key)
	if err == nil {
		c.CryptoProperties.RelatedCryptoMaterialProperties.Value = base64.StdEncoding.EncodeToString(keyValue)
	}
	return c
}

func getECDHPrivateKeyComponent() cdx.Component {
	c := getGenericPrivateKeyComponent()
	c.Name = "ECDH"
	return c
}

func getDSAPublicKeyComponent(key *dsa.PublicKey) cdx.Component {
	c := getGenericPublicKeyComponent()
	c.Name = "DSA"
	size := key.Y.BitLen()
	c.CryptoProperties.RelatedCryptoMaterialProperties.Size = &size
	c.CryptoProperties.OID = "1.3.14.3.2.12"
	return c
}
