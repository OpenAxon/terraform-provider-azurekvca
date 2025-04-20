package provider

import (
	"context"
	"crypto"
	"io"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

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

	return signResp.Result, nil
}
