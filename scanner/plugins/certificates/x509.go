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

package certificates

import (
	"crypto/x509"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	pemutility "github.com/IBM/cbomkit-theia/scanner/pem"

	"github.com/google/uuid"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// An X.509 certificate with additional metadata that is not part of the x509.Certificate struct
type x509CertificateWithMetadata struct {
	*x509.Certificate
	path   string
	format string
}

// During parsing of the x509.Certificate an unknown algorithm was found
var errX509UnknownAlgorithm = errors.New("x.509 certificate has unknown algorithm")

// Create a new x509CertificateWithMetadata from a x509.Certificate and a path
func newX509CertificateWithMetadata(cert *x509.Certificate, path string) (*x509CertificateWithMetadata, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is nil")
	}
	return &x509CertificateWithMetadata{
		cert,
		path,
		"X.509",
	}, nil
}

// Convenience function to parse der bytes into a slice of x509CertificateWithMetadata
func parseCertificatesToX509CertificateWithMetadata(der []byte, path string) ([]*x509CertificateWithMetadata, error) {
	certs, err := x509.ParseCertificates(der)
	if err != nil {
		return make([]*x509CertificateWithMetadata, 0), err
	}

	certsWithMetadata := make([]*x509CertificateWithMetadata, 0, len(certs))

	for _, cert := range certs {
		certWithMetadata, err := newX509CertificateWithMetadata(cert, path)
		if err != nil {
			return certsWithMetadata, err
		}
		certsWithMetadata = append(certsWithMetadata, certWithMetadata)
	}

	return certsWithMetadata, err
}

func (x509CertificateWithMetadata *x509CertificateWithMetadata) GetCDXComponents() (*[]cdx.Component, *map[cdx.BOMReference][]string, error) {
	// Creating BOM Components
	components := make([]cdx.Component, 0)
	dependencyMap := make(map[cdx.BOMReference][]string)
	// get certificate algorithm as cdx component
	certificate := x509CertificateWithMetadata.getCertificateComponent()
	// get signature algorithm as cdx component
	signatureAlgorithm, err := x509CertificateWithMetadata.getSignatureAlgorithmComponent()
	if err != nil {
		return nil, nil, err
	}
	if signatureAlgorithm.signature != nil {
		if signatureAlgorithm.pke != nil {
			dependencyMap[cdx.BOMReference(signatureAlgorithm.signature.BOMRef)] = append(dependencyMap[cdx.BOMReference(signatureAlgorithm.signature.BOMRef)], signatureAlgorithm.pke.BOMRef)
			components = append(components, *signatureAlgorithm.pke)
		}
		if signatureAlgorithm.hash != nil {
			dependencyMap[cdx.BOMReference(signatureAlgorithm.signature.BOMRef)] = append(dependencyMap[cdx.BOMReference(signatureAlgorithm.signature.BOMRef)], signatureAlgorithm.hash.BOMRef)
			components = append(components, *signatureAlgorithm.hash)
		}
		certificate.CryptoProperties.CertificateProperties.SignatureAlgorithmRef = cdx.BOMReference(signatureAlgorithm.signature.BOMRef)
		components = append(components, *signatureAlgorithm.signature)
	}
	// add public key algorithm
	publicKeyAlgorithm, err := x509CertificateWithMetadata.getPublicKeyAlgorithmComponent()
	if err != nil {
		return nil, nil, err
	}
	components = append(components, publicKeyAlgorithm)
	// add public key
	publicKey, err := x509CertificateWithMetadata.getPublicKeyComponent()
	if err != nil {
		return nil, nil, err
	}
	// add dependency to public key algorithm
	publicKey.CryptoProperties.RelatedCryptoMaterialProperties.AlgorithmRef = cdx.BOMReference(publicKeyAlgorithm.BOMRef)
	// add certificate dependency to public key
	certificate.CryptoProperties.CertificateProperties.SubjectPublicKeyRef = cdx.BOMReference(publicKey.BOMRef)
	components = append(components, publicKey)
	components = append(components, certificate)

	return &components, &dependencyMap, nil
}

// Generate the CycloneDX component for the certificate
func (x509CertificateWithMetadata *x509CertificateWithMetadata) getCertificateComponent() cdx.Component {
	return cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   x509CertificateWithMetadata.Subject.CommonName,
		BOMRef: uuid.New().String(),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeCertificate,
			CertificateProperties: &cdx.CertificateProperties{
				SubjectName:          x509CertificateWithMetadata.Subject.CommonName,
				IssuerName:           x509CertificateWithMetadata.Issuer.CommonName,
				NotValidBefore:       x509CertificateWithMetadata.NotBefore.Format(time.RFC3339),
				NotValidAfter:        x509CertificateWithMetadata.NotAfter.Format(time.RFC3339),
				CertificateFormat:    x509CertificateWithMetadata.format,
				CertificateExtension: filepath.Ext(x509CertificateWithMetadata.path),
			},
		},
		Evidence: &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{
				{
					Location: x509CertificateWithMetadata.path,
				}},
		},
	}
}

type signatureAlgorithmResult struct {
	signature *cdx.Component
	hash      *cdx.Component
	pke       *cdx.Component
}

// Generate the CycloneDX component for the signature algorithm
func (x509CertificateWithMetadata *x509CertificateWithMetadata) getSignatureAlgorithmComponent() (signatureAlgorithmResult, error) {
	switch x509CertificateWithMetadata.SignatureAlgorithm {
	case x509.MD2WithRSA:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		comp.CryptoProperties.OID = "1.3.14.7.2.3.1"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "MD2"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "2"
		hash.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingOther

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "RSA"

		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.MD5WithRSA:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		comp.CryptoProperties.OID = "1.3.14.3.2.3"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "MD5"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "5"

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "RSA"

		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.SHA1WithRSA:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "160"
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		comp.CryptoProperties.OID = "1.2.840.113549.1.1.5"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "SHA1"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "1"

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "RSA"

		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.SHA256WithRSA:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		comp.CryptoProperties.OID = "1.2.840.113549.1.1.11"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "SHA256"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "RSA"

		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.SHA384WithRSA:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "384"
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		comp.CryptoProperties.OID = "1.2.840.113549.1.1.12"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "SHA384"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "384"

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "RSA"

		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.SHA512WithRSA:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "512"
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		comp.CryptoProperties.OID = "1.2.840.113549.1.1.13"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "SHA512"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "512"

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "RSA"

		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.DSAWithSHA1:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "160"
		comp.CryptoProperties.OID = "1.3.14.3.2.27"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "SHA1"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "1"

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "DSA"

		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.DSAWithSHA256:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"
		comp.CryptoProperties.OID = "2.16.840.1.101.3.4.3.2"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "SHA256"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "DSA"
		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.ECDSAWithSHA1:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "160"
		comp.CryptoProperties.OID = "1.2.840.10045.4.1"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "SHA1"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "1"

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "ECDSA"
		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.ECDSAWithSHA256:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"
		comp.CryptoProperties.OID = "1.2.840.10045.4.3.2"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "SHA256"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "ECDSA"
		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.ECDSAWithSHA384:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "384"
		comp.CryptoProperties.OID = "1.2.840.10045.4.3.3"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "SHA384"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "384"

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "ECDSA"
		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.ECDSAWithSHA512:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "512"
		comp.CryptoProperties.OID = "1.2.840.10045.4.3.4"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "SHA512"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "512"

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "ECDSA"
		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.SHA256WithRSAPSS:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingOther
		comp.CryptoProperties.OID = "1.2.840.113549.1.1.11"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "SHA256"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "RSA-PSS"
		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.SHA384WithRSAPSS:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "384"
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingOther
		comp.CryptoProperties.OID = "1.2.840.113549.1.1.12"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "SHA384"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "384"

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "RSA-PSS"
		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.SHA512WithRSAPSS:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "512"
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingOther
		comp.CryptoProperties.OID = "1.2.840.113549.1.1.13"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "SHA512"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "512"

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "RSA-PSS"
		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.PureEd25519:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.Curve = "Ed25519" // https://datatracker.ietf.org/doc/html/rfc8032
		comp.CryptoProperties.OID = "1.3.101.112"
		return signatureAlgorithmResult{
			signature: &comp,
			hash:      nil, // No Hash, see: https://datatracker.ietf.org/doc/html/rfc8032#section-4
			pke:       nil,
		}, nil
	default:
		return signatureAlgorithmResult{
			signature: nil,
			hash:      nil,
			pke:       nil,
		}, errX509UnknownAlgorithm
	}
}

// Generate a generic CycloneDX component for the signature algorithm
func getGenericSignatureAlgorithmComponent(algo x509.SignatureAlgorithm, path string) cdx.Component {
	return cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   algo.String(),
		BOMRef: uuid.New().String(),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
				Primitive:       cdx.CryptoPrimitiveSignature,
				CryptoFunctions: &[]cdx.CryptoFunction{cdx.CryptoFunctionSign},
			},
		},
		Evidence: &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{
				{
					Location: path,
				}},
		},
	}
}

// Generate a generic CycloneDX component for a hash algorithm
func getGenericHashAlgorithmComponent(path string) cdx.Component {
	return cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		BOMRef: uuid.New().String(),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
				Primitive:       cdx.CryptoPrimitiveHash,
				CryptoFunctions: &[]cdx.CryptoFunction{cdx.CryptoFunctionDigest},
			},
		},
		Evidence: &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{
				{
					Location: path,
				}},
		},
	}
}

// Generate a generic CycloneDX component for a hash algorithm
func getGenericPKEAlgorithmComponent(path string) cdx.Component {
	return cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		BOMRef: uuid.New().String(),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
				Primitive:       cdx.CryptoPrimitivePKE,
				CryptoFunctions: &[]cdx.CryptoFunction{cdx.CryptoFunctionSign},
			},
		},
		Evidence: &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{
				{
					Location: path,
				}},
		},
	}
}

// Generate the CycloneDX component for the public key
func (x509CertificateWithMetadata *x509CertificateWithMetadata) getPublicKeyComponent() (cdx.Component, error) {
	comps, err := pemutility.GenerateComponentsFromKey(x509CertificateWithMetadata.PublicKey)
	if err != nil {
		return cdx.Component{}, err
	}

	if len(comps) > 1 {
		return cdx.Component{}, fmt.Errorf("certificate plugin: parsed several components from a single key. this should not happen. Check if getPublicKeyComponent gets only public keys")
	}

	comp := comps[0]
	comp.Evidence = &cdx.Evidence{
		Occurrences: &[]cdx.EvidenceOccurrence{
			{Location: x509CertificateWithMetadata.path},
		},
	}

	return comp, nil
}

// Generate the CycloneDX component for the public key algorithm
func (x509CertificateWithMetadata *x509CertificateWithMetadata) getPublicKeyAlgorithmComponent() (cdx.Component, error) {
	switch x509CertificateWithMetadata.PublicKeyAlgorithm {
	case x509.RSA:
		comp := getGenericPublicKeyAlgorithmComponent(x509CertificateWithMetadata.PublicKeyAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.OID = "1.2.840.113549.1.1.1"
		return comp, nil
	case x509.DSA:
		comp := getGenericPublicKeyAlgorithmComponent(x509CertificateWithMetadata.PublicKeyAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.OID = "1.3.14.3.2.12"
		return comp, nil
	case x509.ECDSA:
		comp := getGenericPublicKeyAlgorithmComponent(x509CertificateWithMetadata.PublicKeyAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.OID = "1.2.840.10045.2.1"
		return comp, nil
	case x509.Ed25519:
		comp := getGenericPublicKeyAlgorithmComponent(x509CertificateWithMetadata.PublicKeyAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.Curve = "Ed25519" // https://datatracker.ietf.org/doc/html/rfc8032
		comp.CryptoProperties.OID = "1.3.101.112"
		return comp, nil
	default:
		return getGenericPublicKeyAlgorithmComponent(x509CertificateWithMetadata.PublicKeyAlgorithm, x509CertificateWithMetadata.path), errX509UnknownAlgorithm
	}
}

// Generate a generic CycloneDX component for the public key algorithm
func getGenericPublicKeyAlgorithmComponent(algo x509.PublicKeyAlgorithm, path string) cdx.Component {
	return cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   algo.String(),
		BOMRef: uuid.New().String(),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
				Primitive:              cdx.CryptoPrimitivePKE,
				ExecutionEnvironment:   cdx.CryptoExecutionEnvironmentUnknown,
				ImplementationPlatform: cdx.ImplementationPlatformUnknown,
				CertificationLevel:     &[]cdx.CryptoCertificationLevel{cdx.CryptoCertificationLevelUnknown},
				CryptoFunctions:        &[]cdx.CryptoFunction{cdx.CryptoFunctionEncapsulate, cdx.CryptoFunctionDecapsulate},
			},
		},
		Evidence: &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{
				{
					Location: path,
				}},
		},
	}
}
