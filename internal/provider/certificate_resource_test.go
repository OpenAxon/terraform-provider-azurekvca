package provider

import (
	"os"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)



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
