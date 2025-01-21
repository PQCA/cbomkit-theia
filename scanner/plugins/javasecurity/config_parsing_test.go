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

package javasecurity

import (
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/IBM/cbomkit-theia/provider/docker"

	"github.com/magiconair/properties"
	"github.com/stretchr/testify/assert"
)

/*
=======
java.security related
=======
*/

func setUpExtractionOfRule(javaSecurityContent string) *properties.Properties {
	filesystem, err := os.MkdirTemp("", "cbomkit-theia_CMD_ARGUMENT_TEST")
	if err != nil {
		panic(err)
	}

	standardContent := javaSecurityContent + "\n"
	securityFile := filesystem + "/java.security"
	err = os.WriteFile(securityFile, []byte(standardContent), 0644)
	if err != nil {
		panic(err)
	}

	config := properties.MustLoadFile(securityFile, properties.UTF8)

	os.RemoveAll(filesystem)

	return config
}

func TestExtractTLSRules(t *testing.T) {
	config := setUpExtractionOfRule("jdk.tls.disabledAlgorithms=SHA384, RSA keySize == 3")

	t.Run("Extracting TLS Rules from security file", func(t *testing.T) {
		restrictions, err := extractTLSRules(config)
		javaSecurity := JavaSecurity{
			config,
			restrictions,
		}
		assert.NoError(t, err)
		assert.Len(t, javaSecurity.tlsDisabledAlgorithms, 2)
		for _, res := range javaSecurity.tlsDisabledAlgorithms {
			switch res.name {
			case "RSA":
				assert.Equal(t, res.keySizeOperator, keySizeOperatorEqual)
				assert.Equal(t, res.keySize, 3)
			case "SHA384":
				assert.Equal(t, res.keySizeOperator, keySizeOperatorNone)
				assert.Equal(t, res.keySize, 0)
			default:
				assert.FailNow(t, fmt.Sprintf("%v is not a possible algo name", res.name))
			}
		}
	})
}

func TestExtractTLSRulesNotSupported(t *testing.T) {
	config := setUpExtractionOfRule("jdk.tls.disabledAlgorithms=SHA384, RSA jdkCA")

	t.Run("Extracting TLS Rules from security file", func(t *testing.T) {
		restrictions, err := extractTLSRules(config)
		javaSecurity := JavaSecurity{
			config,
			restrictions,
		}
		assert.NoError(t, err)
		assert.Len(t, javaSecurity.tlsDisabledAlgorithms, 1)
		for _, res := range javaSecurity.tlsDisabledAlgorithms {
			switch res.name {
			case "SHA384":
				assert.Equal(t, res.keySizeOperator, keySizeOperatorNone)
				assert.Equal(t, res.keySize, 0)
			default:
				assert.FailNow(t, fmt.Sprintf("%v is not a possible algo name", res.name))
			}
		}
	})
}

func TestExtractTLSRulesIllegalValue1(t *testing.T) {
	config := setUpExtractionOfRule("jdk.tls.disabledAlgorithms=SHA384, RSA keySize keySize")

	t.Run("Extracting TLS Rules from security file", func(t *testing.T) {
		_, err := extractTLSRules(config)
		assert.Error(t, err)
	})
}

func TestExtractTLSRulesIllegalValue2(t *testing.T) {
	config := setUpExtractionOfRule("jdk.tls.disabledAlgorithms=SHA384, RSA keySize | 234")

	t.Run("Extracting TLS Rules from security file", func(t *testing.T) {
		_, err := extractTLSRules(config)
		assert.Error(t, err)
	})
}

func TestExtractTLSRulesInclude(t *testing.T) {
	config := setUpExtractionOfRule("jdk.tls.disabledAlgorithms=SHA384, RSA keySize == 3, include my.new.property\nmy.new.property=DIDYOUGETME keySize >= 123")

	t.Run("Extracting TLS Rules from security file", func(t *testing.T) {
		restrictions, err := extractTLSRules(config)
		javaSecurity := JavaSecurity{
			config,
			restrictions,
		}
		assert.NoError(t, err)
		assert.Len(t, javaSecurity.tlsDisabledAlgorithms, 3)
		for _, res := range javaSecurity.tlsDisabledAlgorithms {
			switch res.name {
			case "RSA":
				assert.Equal(t, res.keySizeOperator, keySizeOperatorEqual)
				assert.Equal(t, res.keySize, 3)
			case "SHA384":
				assert.Equal(t, res.keySizeOperator, keySizeOperatorNone)
				assert.Equal(t, res.keySize, 0)
			case "DIDYOUGETME":
				assert.Equal(t, res.keySizeOperator, keySizeOperatorGreaterEqual)
				assert.Equal(t, res.keySize, 123)
			default:
				assert.FailNow(t, fmt.Sprintf("%v is not a possible algo name", res.name))
			}
		}
	})
}

/*
=======
container image related
=======
*/

func setUpCMD(originalKey string, originalValue string, newKey string, newValue string, dockerArgument string, dockerCommand string, securityOverridePropertiesFileValue bool) (*properties.Properties, []string, docker.ActiveImage) {
	filesystem, err := os.MkdirTemp("", "cbomkit-theia_CMD_ARGUMENT_TEST")
	if err != nil {
		panic(err)
	}

	content := []byte{}
	if newKey != "" && newValue != "" {
		content = []byte(newKey + "=" + newValue + "\n")
	}
	additionalFilePath := filesystem + "/test.security"
	err = os.WriteFile(additionalFilePath, content, 0644)
	if err != nil {
		panic(err)
	}

	standardContent := "security.overridePropertiesFile=" + string(strconv.FormatBool(securityOverridePropertiesFileValue)) + "\n"
	if originalKey != "" && originalValue != "" {
		standardContent += originalKey + "=" + originalValue + "\n"
	}
	securityFile := filesystem + "/java.security"
	err = os.WriteFile(securityFile, []byte(standardContent), 0644)
	if err != nil {
		panic(err)
	}

	dockercontent := []byte(
		"FROM busybox\n" +
			"COPY . /app\n" +
			dockerCommand + " [\"bash\", \"-c\", \"java " + dockerArgument +
			"/app/test.security" +
			" RemoteRMIServer\"\n")

	dockerfile := filesystem + "/Dockerfile"
	err = os.WriteFile(dockerfile, []byte(dockercontent), 0644)
	if err != nil {
		panic(err)
	}

	config := properties.MustLoadFile(securityFile, properties.UTF8)

	image, err := docker.BuildNewImage(dockerfile)
	if err != nil {
		panic(err)
	}

	filesToDelete := []string{filesystem, dockerfile}

	return config, filesToDelete, image
}

func tearDown(filesToDelete []string, image docker.ActiveImage) {
	image.TearDown()
	for _, file := range filesToDelete {
		os.RemoveAll(file)
	}
}

func TestCMDArgumentAdditionalCMD(t *testing.T) {
	config, filesToDelete, image := setUpCMD("originalkey", "originalvalue", "mynewtestproperty", "mynewtestvalue", "-Djava.security.properties=", "CMD", true)
	defer tearDown(filesToDelete, image)

	t.Run("Additional java.security files via CMD", func(t *testing.T) {
		javaSecurity, err := newJavaSecurity(config, docker.GetSquashedFilesystem(image))
		assert.NoError(t, err, "checkConfig failed")

		value1, ok1 := javaSecurity.Get("mynewtestproperty")
		value2, ok2 := javaSecurity.Get("originalkey")
		assert.True(t, ok1)
		assert.True(t, ok2)
		assert.Equal(t, value1, "mynewtestvalue")
		assert.Equal(t, value2, "originalvalue")
	})
}

func TestCMDArgumentAdditionalENTRYPOINT(t *testing.T) {
	config, filesToDelete, image := setUpCMD("originalkey", "originalvalue", "mynewtestproperty", "mynewtestvalue", "-Djava.security.properties=", "ENTRYPOINT", true)
	defer tearDown(filesToDelete, image)

	t.Run("Additional java.security files via CMD", func(t *testing.T) {

		javaSecurity, err := newJavaSecurity(config, docker.GetSquashedFilesystem(image))
		assert.NoError(t, err, "checkConfig failed")

		value1, ok1 := javaSecurity.Get("mynewtestproperty")
		value2, ok2 := javaSecurity.Get("originalkey")
		assert.True(t, ok1)
		assert.True(t, ok2)
		assert.Equal(t, value1, "mynewtestvalue")
		assert.Equal(t, value2, "originalvalue")
	})
}

func TestCMDArgumentOverride(t *testing.T) {
	config, filesToDelete, image := setUpCMD("mynewtestproperty", "THISSHOULDNOTBEHERE", "mynewtestproperty", "mynewtestvalue", "-Djava.security.properties==", "CMD", true)
	defer tearDown(filesToDelete, image)

	t.Run("Additional java.security files via CMD", func(t *testing.T) {

		javaSecurity, err := newJavaSecurity(config, docker.GetSquashedFilesystem(image))
		assert.NoError(t, err, "checkConfig failed")

		value1, ok1 := javaSecurity.Get("mynewtestproperty")
		assert.True(t, ok1)
		assert.NotEqual(t, value1, "THISSHOULDNOTBEHERE")
		assert.Equal(t, value1, "mynewtestvalue")
	})
}

func TestCMDArgumentNoArgument(t *testing.T) {
	config, filesToDelete, image := setUpCMD("mynewtestproperty", "THISSHOULDNOTBEHERE", "mynewtestproperty", "mynewtestvalue", "", "CMD", true)
	defer tearDown(filesToDelete, image)

	t.Run("Additional java.security files via CMD", func(t *testing.T) {

		javaSecurity, err := newJavaSecurity(config, docker.GetSquashedFilesystem(image))
		assert.NoError(t, err, "checkConfig failed")

		value1, ok1 := javaSecurity.Get("mynewtestproperty")
		assert.True(t, ok1)
		assert.Equal(t, value1, "THISSHOULDNOTBEHERE")
		assert.NotEqual(t, value1, "mynewtestvalue")
	})
}

func TestCMDArgumentNotAllowed(t *testing.T) {
	config, filesToDelete, image := setUpCMD("mynewtestproperty", "THISSHOULDNOTBEHERE", "mynewtestproperty", "mynewtestvalue", "-Djava.security.properties==", "CMD", false)
	defer tearDown(filesToDelete, image)

	t.Run("Additional java.security files via CMD", func(t *testing.T) {

		javaSecurity, err := newJavaSecurity(config, docker.GetSquashedFilesystem(image))
		assert.NoError(t, err, "checkConfig failed")

		value1, ok1 := javaSecurity.Get("mynewtestproperty")
		assert.True(t, ok1)
		assert.Equal(t, value1, "THISSHOULDNOTBEHERE")
		assert.NotEqual(t, value1, "mynewtestvalue")
	})
}
