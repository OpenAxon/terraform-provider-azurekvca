package provider

import (
	"crypto/x509"
	"os"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

func TestMapX509ToAzureSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		input    x509.SignatureAlgorithm
		expected azkeys.SignatureAlgorithm
	}{
		{"SHA256WithRSA maps to RS256", x509.SHA256WithRSA, azkeys.SignatureAlgorithmRS256},
		{"SHA384WithRSA maps to RS384", x509.SHA384WithRSA, azkeys.SignatureAlgorithmRS384},
		{"SHA512WithRSA maps to RS512", x509.SHA512WithRSA, azkeys.SignatureAlgorithmRS512},
		{"Unknown defaults to RS256", x509.UnknownSignatureAlgorithm, azkeys.SignatureAlgorithmRS256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapX509ToAzureSignatureAlgorithm(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestCertificateResourceUsesDynamicAlgorithm(t *testing.T) {
	content, err := os.ReadFile("certificate_resource.go")
	if err != nil {
		t.Fatalf("Failed to read certificate_resource.go: %v", err)
	}

	source := string(content)

	// Verify dynamic algorithm detection is used
	if !strings.Contains(source, "mapX509ToAzureSignatureAlgorithm(parsedCACert.SignatureAlgorithm)") {
		t.Error("certificate_resource.go must use mapX509ToAzureSignatureAlgorithm to dynamically detect signature algorithm")
	}

	// Ensure hardcoded RS256/RS384/RS512 is not used in NewAzureKVSigner call
	if strings.Contains(source, "NewAzureKVSigner") && strings.Contains(source, "azkeys.SignatureAlgorithmRS256,") {
		t.Error("NewAzureKVSigner should not use hardcoded SignatureAlgorithmRS256")
	}
	if strings.Contains(source, "NewAzureKVSigner") && strings.Contains(source, "azkeys.SignatureAlgorithmRS384,") {
		t.Error("NewAzureKVSigner should not use hardcoded SignatureAlgorithmRS384")
	}
}
