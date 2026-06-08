package provider

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

type ecdsaSignature struct {
	R, S *big.Int
}

// p1363ToDER converts an IEEE P1363 ECDSA signature (r||s) to ASN.1 DER format,
// which is required by Go's x509 package. Azure Key Vault returns P1363 for EC keys.
func p1363ToDER(sig []byte) ([]byte, error) {
	if len(sig)%2 != 0 {
		return nil, fmt.Errorf("invalid P1363 signature length %d", len(sig))
	}
	n := len(sig) / 2
	r := new(big.Int).SetBytes(sig[:n])
	s := new(big.Int).SetBytes(sig[n:])
	return asn1.Marshal(ecdsaSignature{r, s})
}

func NewAzureKVSigner(ctx context.Context, cred azcore.TokenCredential, vaultURL string, keyName string, signatureAlgorithm azkeys.SignatureAlgorithm, publicKey crypto.PublicKey) (a *AzureKVSigner, err error) {
	return &AzureKVSigner{
		cred:               cred,
		ctx:                ctx,
		keyName:            keyName,
		publicKey:          publicKey,
		signatureAlgorithm: signatureAlgorithm,
		vaultURL:           vaultURL,
	}, nil
}

type AzureKVSigner struct {
	cred               azcore.TokenCredential
	ctx                context.Context
	keyName            string
	publicKey          crypto.PublicKey
	signatureAlgorithm azkeys.SignatureAlgorithm
	vaultURL           string
}

func (a *AzureKVSigner) Public() crypto.PublicKey {
	return a.publicKey
}

func (a *AzureKVSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if a.keyName == "" {
		return make([]byte, 0), nil
	}

	keyClient, err := azkeys.NewClient(a.vaultURL, a.cred, nil)
	if err != nil {
		return nil, err
	}

	params := azkeys.SignParameters{
		Algorithm: &a.signatureAlgorithm,
		Value:     digest,
	}

	signResp, err := keyClient.Sign(a.ctx, a.keyName, "", params, nil)
	if err != nil {
		return signResp.Result, err
	}

	if _, ok := a.publicKey.(*ecdsa.PublicKey); ok {
		return p1363ToDER(signResp.Result)
	}

	return signResp.Result, nil
}
