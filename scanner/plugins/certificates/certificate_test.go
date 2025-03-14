package certificates

import (
	"crypto/x509"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/IBM/cbomkit-theia/provider/cyclonedx"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestIssue56(t *testing.T) {
	t.Run("Issue 56", func(t *testing.T) {
		EcdsaSha256RawCert := []byte("-----BEGIN CERTIFICATE-----\n" +
			"MIIB3DCCAYOgAwIBAgINAgPlfvU/k/2lCSGypjAKBggqhkjOPQQDAjBQMSQwIgYD\n" +
			"VQQLExtHbG9iYWxTaWduIEVDQyBSb290IENBIC0gUjQxEzARBgNVBAoTCkdsb2Jh\n" +
			"bFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMTIxMTEzMDAwMDAwWhcNMzgw\n" +
			"MTE5MDMxNDA3WjBQMSQwIgYDVQQLExtHbG9iYWxTaWduIEVDQyBSb290IENBIC0g\n" +
			"UjQxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wWTAT\n" +
			"BgcqhkjOPQIBBggqhkjOPQMBBwNCAAS4xnnTj2wlDp8uORkcA6SumuU5BwkWymOx\n" +
			"uYb4ilfBV85C+nOh92VC/x7BALJucw7/xyHlGKSq2XE/qNS5zowdo0IwQDAOBgNV\n" +
			"HQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUVLB7rUW44kB/\n" +
			"+wpu+74zyTyjhNUwCgYIKoZIzj0EAwIDRwAwRAIgIk90crlgr/HmnKAWBVBfw147\n" +
			"bmF0774BxL4YSFlhgjICICadVGNA3jdgUM/I2O2dgq43mLyjj0xMqTQrbO/7lZsm\n" +
			"-----END CERTIFICATE-----")
		EcdsaSha256Certs, err := parseX509CertFromPath(EcdsaSha256RawCert, "EcdsaSha256Cert.pem")
		if err != nil {
			t.Fail()
		}
		assert.Len(t, EcdsaSha256Certs, 1)
		EcdsaSha256Cert := EcdsaSha256Certs[0]
		assert.Equal(t, EcdsaSha256Cert.SignatureAlgorithm, x509.ECDSAWithSHA256)

		EcdsaSha384RawCert := []byte("-----BEGIN CERTIFICATE-----\n" +
			"MIICHjCCAaSgAwIBAgIRYFlJ4CYuu1X5CneKcflK2GwwCgYIKoZIzj0EAwMwUDEk\n" +
			"MCIGA1UECxMbR2xvYmFsU2lnbiBFQ0MgUm9vdCBDQSAtIFI1MRMwEQYDVQQKEwpH\n" +
			"bG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTEyMTExMzAwMDAwMFoX\n" +
			"DTM4MDExOTAzMTQwN1owUDEkMCIGA1UECxMbR2xvYmFsU2lnbiBFQ0MgUm9vdCBD\n" +
			"QSAtIFI1MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWdu\n" +
			"MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAER0UOlvt9Xb/pOdEh+J8LttV7HpI6SFkc\n" +
			"8GIxLcB6KP4ap1yztsyX50XUWPrRd21DosCHZTQKH3rd6zwzocWdTaRvQZU4f8ke\n" +
			"hOvRnkmSh5SHDDqFSmafnVmTTZdhBoZKo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYD\n" +
			"VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUPeYpSJvqB8ohREom3m7e0oPQn1kwCgYI\n" +
			"KoZIzj0EAwMDaAAwZQIxAOVpEslu28YxuglB4Zf4+/2a4n0Sye18ZNPLBSWLVtmg\n" +
			"515dTguDnFt2KaAJJiFqYgIwcdK1j1zqO+F4CYWodZI7yFz9SO8NdCKoCOJuxUnO\n" +
			"xwy8p2Fp8fc74SrL+SvzZpA3\n" +
			"-----END CERTIFICATE-----")
		EcdsaSha384Certs, err := parseX509CertFromPath(EcdsaSha384RawCert, "EcdsaSha384Cert.pem")
		if err != nil {
			t.Fail()
		}
		assert.Len(t, EcdsaSha384Certs, 1)
		EcdsaSha384Cert := EcdsaSha384Certs[0]
		assert.Equal(t, EcdsaSha384Cert.SignatureAlgorithm, x509.ECDSAWithSHA384)

		bom := cdx.NewBOM()
		components, dependencyMap, err := EcdsaSha256Cert.GetCDXComponents()
		if err != nil {
			t.Fail()
		}
		cyclonedx.AddComponents(bom, *components)
		cyclonedx.AddDependencies(bom, *dependencyMap)

		components, dependencyMap, err = EcdsaSha384Cert.GetCDXComponents()
		if err != nil {
			t.Fail()
		}
		cyclonedx.AddComponents(bom, *components)
		cyclonedx.AddDependencies(bom, *dependencyMap)

		collectedSignatureAlgorithms := make(map[string]bool)
		for _, component := range *bom.Components {
			if component.CryptoProperties.AssetType == cdx.CryptoAssetTypeCertificate {
				assert.Equal(t, component.Name, "GlobalSign")
				signatureAlgorithm := cyclonedx.GetByBomRef(component.CryptoProperties.CertificateProperties.SignatureAlgorithmRef, bom.Components)
				if signatureAlgorithm == nil {
					t.Fail()
				}
				collectedSignatureAlgorithms[signatureAlgorithm.Name] = true
			}
		}

		assert.Len(t, collectedSignatureAlgorithms, 2)
		err = cdx.NewBOMEncoder(os.Stdout, cdx.BOMFileFormatJSON).SetPretty(true).Encode(bom)
		if err != nil {
			t.Fail()
		}
	})
}
