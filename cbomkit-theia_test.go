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

package main

import (
	"bytes"
	"io"
	"path/filepath"
	"testing"

	"github.com/IBM/cbomkit-theia/provider/cyclonedx"
	"github.com/IBM/cbomkit-theia/provider/docker"
	"github.com/IBM/cbomkit-theia/provider/filesystem"
	"github.com/IBM/cbomkit-theia/scanner"
	"github.com/stretchr/testify/assert"
	"go.uber.org/dig"
)

var testfileFolder string = "./testdata"
var outputExtension string = "/out/bom.json"
var bomFolderExtension string = "/in/bom.json"
var dirExtension string = "/dir"

type testType int

const (
	testTypeDir testType = iota + 1
	testTypeImage
)

var tests = []struct {
	testType       testType
	additionalInfo string
	in             string
	err            bool
}{
	{testTypeImage, "busybox", "/0_empty", false},
	{testTypeDir, "", "/4_unknown_keySize", false},
	{testTypeDir, "", "/5_single_certificate", false},
	{testTypeDir, "", "/6_malformed_java_security", false},
	{testTypeDir, "", "/7_private_key", false},
	{testTypeDir, "", "/8_secrets", false},
}

func TestScan(t *testing.T) {
	for _, test := range tests {
		t.Run(test.in+", BOM: "+test.in, func(t *testing.T) {
			tempTarget := new(bytes.Buffer)

			var runErr error

			container := dig.New()

			if err := container.Provide(func() string {
				return testfileFolder + test.in + bomFolderExtension
			}, dig.Name("bomFilePath")); err != nil {
				panic(err)
			}

			if err := container.Provide(func() io.Writer {
				return tempTarget
			}); err != nil {
				panic(err)
			}

			for _, pluginConstructor := range scanner.GetAllPluginConstructors() {
				if err := container.Provide(pluginConstructor, dig.Group("plugins")); err != nil {
					panic(err)
				}
			}

			switch test.testType {
			case testTypeImage:
				image, err := docker.GetImage(test.additionalInfo)
				assert.NoError(t, err)
				defer image.TearDown()
				err = container.Provide(func() filesystem.Filesystem {
					return docker.GetSquashedFilesystem(image)
				})
				assert.NoError(t, err)
				runErr = container.Invoke(scanner.ReadFilesAndRunScan)
			case testTypeDir:
				err := container.Provide(func() filesystem.Filesystem {
					return filesystem.NewPlainFilesystem(filepath.Join(testfileFolder, test.in, dirExtension))
				})
				assert.NoError(t, err)
				runErr = container.Invoke(scanner.ReadFilesAndRunScan)
			}

			if test.err {
				assert.Error(t, runErr, "scan did not fail although it should")
			} else {
				assert.NoError(t, runErr, "scan did fail although it should not")
			}

			bomCurrent, err := cyclonedx.ParseBOM(tempTarget)
			assert.NoError(t, err)

			// only check that bom is not empty
			assert.NotEmpty(t, *bomCurrent)

			/*assert.Empty(t, cmp.Diff(*bomTrue, *bomCurrent,
				cmpopts.SortSlices(func(a cdx.Service, b cdx.Service) bool {
					return a.Name < b.Name
				}),
				cmpopts.SortSlices(func(a cdx.Component, b cdx.Component) bool {
					aHash := hash.CdxComponentWithoutRefs(a)
					bHash := hash.CdxComponentWithoutRefs(b)
					return hex.EncodeToString(aHash[:]) < hex.EncodeToString(bHash[:])
				}),
				cmpopts.SortSlices(func(a cdx.EvidenceOccurrence, b cdx.EvidenceOccurrence) bool {
					if a.Location != b.Location {
						return a.Location < b.Location
					} else {
						return *a.Line < *b.Line
					}
				}),
				cmpopts.IgnoreTypes(cdx.Dependency{}),
				cmpopts.IgnoreFields(cdx.Component{},
					"BOMRef",
					"CryptoProperties.CertificateProperties.SignatureAlgorithmRef",
					"CryptoProperties.CertificateProperties.SubjectPublicKeyRef",
					"CryptoProperties.RelatedCryptoMaterialProperties.AlgorithmRef",
					"CryptoProperties.RelatedCryptoMaterialProperties.SecuredBy.AlgorithmRef",
					"CryptoProperties.ProtocolProperties.CryptoRefArray"),
			))*/
		})
	}
}
