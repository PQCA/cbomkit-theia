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
	"bytes"
	"fmt"
	"io"
	"os"

	"log/slog"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/xeipuuv/gojsonschema"
)

// WriteBOM Write bom to the file
func WriteBOM(bom *cdx.BOM, writer io.Writer) error {
	// Encode the BOM
	err := cdx.NewBOMEncoder(writer, cdx.BOMFileFormatJSON).
		SetPretty(true).
		Encode(bom)
	if err != nil {
		return err
	}
	return nil
}

// ParseBOM Parse and validate a CycloneDX BOM from path using the schema under schemaPath
func ParseBOM(bomReader io.Reader, schemaReader io.Reader) (*cdx.BOM, error) {
	bomBytes, err := io.ReadAll(bomReader)
	if err != nil {
		return new(cdx.BOM), err
	}

	// JSON Validation via Schema
	schema, _ := io.ReadAll(schemaReader)
	schemaLoader := gojsonschema.NewBytesLoader(schema) // Tried it with NewReaderLoader(schemaReader) but this failed for whatever reason
	documentLoader := gojsonschema.NewBytesLoader(bomBytes)

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return new(cdx.BOM), fmt.Errorf("json schema validator failed: %w", err)
	}

	if result.Valid() {
		slog.Info("Provided BOM is valid.")
	} else {
		slog.Error("The BOM is not valid. see errors:")
		for _, desc := range result.Errors() {
			_, err = fmt.Fprintf(os.Stderr, "- %s\n", desc)
			if err != nil {
				slog.Error(err.Error())
			}
		}
		return new(cdx.BOM), fmt.Errorf("provider: bom is not valid due to schema")
	}

	// Decode BOM from JSON
	slog.Debug("Decoding BOM from JSON to GO object")
	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(bytes.NewReader(bomBytes), cdx.BOMFileFormatJSON)
	err = decoder.Decode(bom)
	if err != nil {
		return new(cdx.BOM), err
	}

	return bom, nil
}
