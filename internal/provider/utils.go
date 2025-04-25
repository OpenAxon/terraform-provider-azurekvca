package provider

import (
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
)

func toKeyUsageType(value azcertificates.KeyUsageType) *azcertificates.KeyUsageType {
	return &value
}

func ParseKeyUsageType(s string) azcertificates.KeyUsageType {
	switch s {
	case string(azcertificates.KeyUsageTypeCRLSign):
		return azcertificates.KeyUsageTypeCRLSign
	case string(azcertificates.KeyUsageTypeDataEncipherment):
		return azcertificates.KeyUsageTypeDataEncipherment
	case string(azcertificates.KeyUsageTypeDecipherOnly):
		return azcertificates.KeyUsageTypeDecipherOnly
	case string(azcertificates.KeyUsageTypeDigitalSignature):
		return azcertificates.KeyUsageTypeDigitalSignature
	case string(azcertificates.KeyUsageTypeEncipherOnly):
		return azcertificates.KeyUsageTypeEncipherOnly
	case string(azcertificates.KeyUsageTypeKeyAgreement):
		return azcertificates.KeyUsageTypeKeyAgreement
	case string(azcertificates.KeyUsageTypeKeyCertSign):
		return azcertificates.KeyUsageTypeKeyCertSign
	case string(azcertificates.KeyUsageTypeKeyEncipherment):
		return azcertificates.KeyUsageTypeKeyEncipherment
	case string(azcertificates.KeyUsageTypeNonRepudiation):
		return azcertificates.KeyUsageTypeNonRepudiation
	default:
		return ""
	}
}
