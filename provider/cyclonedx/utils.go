package cyclonedx

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/IBM/cbomkit-theia/utils"
)

func GetByBomRef(ref cdx.BOMReference, components *[]cdx.Component) *cdx.Component {
	for _, component := range *components {
		if cdx.BOMReference(component.BOMRef) == ref {
			return &component
		}
	}
	return nil
}

type cleaner struct {
	set   func(comp *cdx.Component, value any)
	unset func(comp *cdx.Component) any
}

func CdxComponentWithoutRefs(a cdx.Component) [8]byte {
	cleaners := []cleaner{
		{
			set: func(comp *cdx.Component, value any) {
				comp.BOMRef = value.(string)
			},
			unset: func(comp *cdx.Component) any {
				temp := comp.BOMRef
				comp.BOMRef = ""
				return temp
			},
		},
		{
			set: func(comp *cdx.Component, value any) {
				if comp.CryptoProperties != nil && comp.CryptoProperties.CertificateProperties != nil {
					comp.CryptoProperties.CertificateProperties.SignatureAlgorithmRef = value.(cdx.BOMReference)
				}
			},
			unset: func(comp *cdx.Component) any {
				if comp.CryptoProperties != nil && comp.CryptoProperties.CertificateProperties != nil {
					temp := comp.CryptoProperties.CertificateProperties.SignatureAlgorithmRef
					comp.CryptoProperties.CertificateProperties.SignatureAlgorithmRef = ""
					return temp
				}
				return nil
			},
		},
		{
			set: func(comp *cdx.Component, value any) {
				if comp.CryptoProperties != nil && comp.CryptoProperties.CertificateProperties != nil {
					comp.CryptoProperties.CertificateProperties.SubjectPublicKeyRef = value.(cdx.BOMReference)
				}
			},
			unset: func(comp *cdx.Component) any {
				if comp.CryptoProperties != nil && comp.CryptoProperties.CertificateProperties != nil {
					temp := comp.CryptoProperties.CertificateProperties.SubjectPublicKeyRef
					comp.CryptoProperties.CertificateProperties.SubjectPublicKeyRef = ""
					return temp
				}
				return nil
			},
		},
		{
			set: func(comp *cdx.Component, value any) {
				if comp.CryptoProperties != nil && comp.CryptoProperties.RelatedCryptoMaterialProperties != nil {
					comp.CryptoProperties.RelatedCryptoMaterialProperties.AlgorithmRef = value.(cdx.BOMReference)
				}
			},
			unset: func(comp *cdx.Component) any {
				if comp.CryptoProperties != nil && comp.CryptoProperties.RelatedCryptoMaterialProperties != nil {
					temp := comp.CryptoProperties.RelatedCryptoMaterialProperties.AlgorithmRef
					comp.CryptoProperties.RelatedCryptoMaterialProperties.AlgorithmRef = ""
					return temp
				}
				return nil
			},
		},
		{
			set: func(comp *cdx.Component, value any) {
				if comp.CryptoProperties != nil && comp.CryptoProperties.RelatedCryptoMaterialProperties != nil && comp.CryptoProperties.RelatedCryptoMaterialProperties.SecuredBy != nil {
					comp.CryptoProperties.RelatedCryptoMaterialProperties.SecuredBy.AlgorithmRef = value.(cdx.BOMReference)
				}
			},
			unset: func(comp *cdx.Component) any {
				if comp.CryptoProperties != nil && comp.CryptoProperties.RelatedCryptoMaterialProperties != nil && comp.CryptoProperties.RelatedCryptoMaterialProperties.SecuredBy != nil {
					temp := comp.CryptoProperties.RelatedCryptoMaterialProperties.SecuredBy.AlgorithmRef
					comp.CryptoProperties.RelatedCryptoMaterialProperties.SecuredBy.AlgorithmRef = ""
					return temp
				}
				return nil
			},
		},
		{
			set: func(comp *cdx.Component, value any) {
				if comp.CryptoProperties != nil && comp.CryptoProperties.ProtocolProperties != nil && comp.CryptoProperties.ProtocolProperties.CryptoRefArray != nil {
					comp.CryptoProperties.ProtocolProperties.CryptoRefArray = value.(*[]cdx.BOMReference)
				}
			},
			unset: func(comp *cdx.Component) any {
				if comp.CryptoProperties != nil && comp.CryptoProperties.ProtocolProperties != nil && comp.CryptoProperties.ProtocolProperties.CryptoRefArray != nil {
					temp := comp.CryptoProperties.ProtocolProperties.CryptoRefArray
					comp.CryptoProperties.ProtocolProperties.CryptoRefArray = new([]cdx.BOMReference)
					return temp
				}
				return nil
			},
		},
	}

	temp := make([]any, len(cleaners))

	for i, cleaner := range cleaners {
		temp[i] = cleaner.unset(&a)
	}

	defer func(cleaners []cleaner, a cdx.Component, temp []any) {
		for i, cleaner := range cleaners {
			temp[i] = cleaner.unset(&a)
		}
	}(cleaners, a, temp)

	return utils.Struct8Byte(a)
}
