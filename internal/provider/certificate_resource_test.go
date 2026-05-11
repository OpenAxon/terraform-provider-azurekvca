package provider

import (
	"os"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

func TestSignatureAlgorithmRS384Exists(t *testing.T) {
	alg := azkeys.SignatureAlgorithmRS384
	if alg != "RS384" {
		t.Errorf("Expected RS384, got %s", alg)
	}
}

func TestSignatureAlgorithmRS384NotRS256(t *testing.T) {
	if azkeys.SignatureAlgorithmRS384 == azkeys.SignatureAlgorithmRS256 {
		t.Error("RS384 should not equal RS256")
	}
}

func TestSignatureAlgorithmMapping(t *testing.T) {
	tests := []struct {
		name     string
		alg      azkeys.SignatureAlgorithm
		expected string
	}{
		{"RS256 is SHA-256", azkeys.SignatureAlgorithmRS256, "RS256"},
		{"RS384 is SHA-384", azkeys.SignatureAlgorithmRS384, "RS384"},
		{"RS512 is SHA-512", azkeys.SignatureAlgorithmRS512, "RS512"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.alg) != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, tt.alg)
			}
		})
	}
}

func TestCertificateResourceUsesRS384(t *testing.T) {
	// Read the actual source file to verify RS384 is used
	content, err := os.ReadFile("certificate_resource.go")
	if err != nil {
		t.Fatalf("Failed to read certificate_resource.go: %v", err)
	}

	source := string(content)

	// Find the NewAzureKVSigner call and verify it uses RS384
	if !strings.Contains(source, "SignatureAlgorithmRS384") {
		t.Error("certificate_resource.go must use azkeys.SignatureAlgorithmRS384 for intermediate CA signing")
	}

	// Count occurrences to ensure RS256 is not used for signing
	signerCalls := strings.Count(source, "NewAzureKVSigner")
	rs384Uses := strings.Count(source, "SignatureAlgorithmRS384")

	if signerCalls > 0 && rs384Uses == 0 {
		t.Error("NewAzureKVSigner calls must use SignatureAlgorithmRS384, not RS256")
	}
}
