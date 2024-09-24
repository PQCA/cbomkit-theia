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
	"encoding/pem"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/IBM/cbomkit-theia/provider/filesystem"
	scannererrors "github.com/IBM/cbomkit-theia/scanner/errors"
	pemutility "github.com/IBM/cbomkit-theia/scanner/pem-utility"
	"github.com/IBM/cbomkit-theia/scanner/plugins"

	"go.mozilla.org/pkcs7"

	bomdag "github.com/IBM/cbomkit-theia/scanner/bom-dag"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Plugin to parse certificates from the filesystem
type Plugin struct{}

// GetName Get the name of the plugin
func (*Plugin) GetName() string {
	return "Certificate File Plugin"
}

func (*Plugin) GetExplanation() string {
	return "Find x.509 certificates"
}

// GetType Get the type of the plugin
func (*Plugin) GetType() plugins.PluginType {
	return plugins.PluginTypeAppend
}

// NewCertificatePlugin Parse all certificates from the given filesystem
func NewCertificatePlugin() (plugins.Plugin, error) {
	return &Plugin{}, nil
}

// UpdateBOM Add the found certificates to the slice of components
func (certificatesPlugin *Plugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	var certificates []*x509CertificateWithMetadata

	// Set GODEBUG to allow negative serial numbers (see https://github.com/golang/go/commit/db13584baedce4909915cb4631555f6dbd7b8c38)
	err := setX509NegativeSerial()
	if err != nil {
		slog.Error(err.Error())
	}

	err = fs.WalkDir(
		func(path string) (err error) {
			switch filepath.Ext(path) {
			case ".pem", ".cer", ".cert", ".der", ".ca-bundle", ".crt":
				readCloser, err := fs.Open(path)
				if err != nil {
					return err
				}
				raw, err := filesystem.ReadAllClose(readCloser)
				if err != nil {
					return err
				}
				certs, err := certificatesPlugin.parsex509CertFromPath(raw, path)
				if err != nil {
					return scannererrors.GetParsingFailedAlthoughCheckedError(err, certificatesPlugin.GetName())
				}
				certificates = append(certificates, certs...)
			case ".p7a", ".p7b", ".p7c", ".p7r", ".p7s", ".spc":
				readCloser, err := fs.Open(path)
				if err != nil {
					return err
				}
				raw, err := filesystem.ReadAllClose(readCloser)
				if err != nil {
					return err
				}
				certs, err := certificatesPlugin.parsePKCS7FromPath(raw, path)
				if err != nil {
					return scannererrors.GetParsingFailedAlthoughCheckedError(err, certificatesPlugin.GetName())
				}
				certificates = append(certificates, certs...)
			default:
				return nil
			}

			return nil
		})

	if err != nil {
		return err
	}

	// Set GODEBUG to old setting
	err = removeX509NegativeSerial()
	if err != nil {
		slog.Error(err.Error())
	}

	slog.Debug("Certificate searching done", "count", len(certificates))

	dag := bomdag.NewBomDAG()

	for _, cert := range certificates {
		certDAG, err := cert.generateDAG()
		if errors.Is(err, errX509UnknownAlgorithm) {
			slog.Info("X.509 certs contained unknown algorithms. Continuing anyway", "errors", err)
		} else if err != nil {
			return err
		}

		if err := dag.Merge(certDAG); err != nil {
			slog.Error("Merging of DAGs failed", "certificate path", cert.path)
			return err
		}
	}

	components, dependencyMap, err := dag.GetCDXComponents()

	if err != nil {
		return err
	}

	// Set the components
	if len(components) > 0 {
		if bom.Components == nil {
			comps := make([]cdx.Component, 0, len(components))
			bom.Components = &comps
		}
		*bom.Components = append(*bom.Components, components...)
	}

	// Set the dependency map
	if len(dependencyMap) > 0 {
		if bom.Dependencies == nil {
			deps := make([]cdx.Dependency, 0, len(dependencyMap))
			bom.Dependencies = &deps
		}
		*bom.Dependencies = MergeDependencyStructSlice(*bom.Dependencies, dependencyMapToStructSlice(dependencyMap))
	}

	return nil
}

// Parse a X.509 certificate from the given path (in base64 PEM or binary DER)
func (certificatesPlugin *Plugin) parsex509CertFromPath(raw []byte, path string) ([]*x509CertificateWithMetadata, error) {
	blocks := pemutility.ParsePEMToBlocksWithTypeFilter(raw, pemutility.Filter{
		FilterType: pemutility.PEMTypeFilterTypeAllowlist,
		List:       []pemutility.PEMBlockType{pemutility.PEMBlockTypeCertificate},
	})

	if len(blocks) == 0 {
		return parseCertificatesToX509CertificateWithMetadata(raw, path)
	}

	certs := make([]*x509CertificateWithMetadata, 0, len(blocks))

	for block := range blocks {
		moreCerts, err := parseCertificatesToX509CertificateWithMetadata(block.Bytes, path)
		if err != nil {
			return moreCerts, err
		}
		certs = append(certs, moreCerts...)
	}

	return certs, nil
}

// Parse X.509 certificates from a PKCS7 file (base64 PEM format)
func (certificatesPlugin *Plugin) parsePKCS7FromPath(raw []byte, path string) ([]*x509CertificateWithMetadata, error) {
	block, _ := pem.Decode(raw)

	pkcs7Object, err := pkcs7.Parse(block.Bytes)
	if err != nil || pkcs7Object == nil {
		return make([]*x509CertificateWithMetadata, 0), err
	}

	certsWithMetadata := make([]*x509CertificateWithMetadata, 0, len(pkcs7Object.Certificates))

	for _, cert := range pkcs7Object.Certificates {
		certWithMetadata, err := newX509CertificateWithMetadata(cert, path)
		if err != nil {
			return make([]*x509CertificateWithMetadata, 0), err
		}
		certsWithMetadata = append(certsWithMetadata, certWithMetadata)
	}

	return certsWithMetadata, nil
}

func dependencyMapToStructSlice(dependencyMap map[cdx.BOMReference][]string) []cdx.Dependency {
	dependencies := make([]cdx.Dependency, 0)

	for ref, dependsOn := range dependencyMap {
		dependencies = append(dependencies, cdx.Dependency{
			Ref:          string(ref),
			Dependencies: &dependsOn,
		})
	}

	return dependencies
}

func MergeDependencyStructSlice(a []cdx.Dependency, b []cdx.Dependency) []cdx.Dependency {
	for _, bStruct := range b {
		i := IndexBomRefInDependencySlice(a, cdx.BOMReference(bStruct.Ref))
		if i != -1 {
			// Merge
			for _, s := range *bStruct.Dependencies {
				if !slices.Contains(*a[i].Dependencies, s) {
					*a[i].Dependencies = append(*a[i].Dependencies, s)
				}
			}
		} else {
			a = append(a, bStruct)
		}
	}
	return a
}

// IndexBomRefInDependencySlice Return index in slice if bomRef is found in slice or -1 if not present
func IndexBomRefInDependencySlice(slice []cdx.Dependency, bomRef cdx.BOMReference) int {
	for i, dep := range slice {
		if dep.Ref == string(bomRef) {
			return i
		}
	}

	return -1
}

// Set x509negativeserial=1 in the GODEBUG environment variable.
func setX509NegativeSerial() error {
	godebug := os.Getenv("GODEBUG")
	var newGodebug string

	if strings.Contains(godebug, "x509negativeserial=") {
		// Replace the existing x509negativeserial value with 1
		newGodebug = strings.ReplaceAll(godebug, "x509negativeserial=0", "x509negativeserial=1")
	} else {
		// Append x509negativeserial=1 to the GODEBUG variable
		if godebug != "" {
			newGodebug = godebug + ",x509negativeserial=1"
		} else {
			newGodebug = "x509negativeserial=1"
		}
	}

	// Set the modified GODEBUG environment variable
	return os.Setenv("GODEBUG", newGodebug)
}

// Remove x509negativeserial from the GODEBUG environment variable.
func removeX509NegativeSerial() error {
	godebug := os.Getenv("GODEBUG")
	if godebug == "" {
		return nil // GODEBUG is not set, nothing to remove
	}

	// Split the GODEBUG variable by commas
	parts := strings.Split(godebug, ",")
	var newParts []string

	for _, part := range parts {
		// Skip the part that contains x509negativeserial
		if !strings.HasPrefix(part, "x509negativeserial=") {
			newParts = append(newParts, part)
		}
	}

	// Join the remaining parts back together
	newGodebug := strings.Join(newParts, ",")

	// Set the modified GODEBUG environment variable
	return os.Setenv("GODEBUG", newGodebug)
}
