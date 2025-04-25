# Terraform Provider for using Azure Key Vault as a CA

Traditionally using Azure Key Vault(KV) as a CA requires exporting the CA private key into terraform where it gets saved into state.

KV has support for a sign operation on stored keys regardless of their exportability. With a little work this sign operation can be used to generate certificates.

This provider encapsulates that functionality

# Example Usage

```hcl
terraform {
  required_providers {
    azurekvca = {
      source = "OpenAxon/azurekvca"
    }
  }
}

provider "azurekvca" {}

resource "azurekvca_certificate" "example" {
  vault_url = "https://something.vault.azure.net/"
  name      = "test-cert"

  key = {
    exportable = true
    key_size   = 2048
    key_type   = "RSA"
    reuse_key  = true
  }

  trigger = "Change me to trigger a recreate"
}

# Optionally mangle the CSR to add values not supported by Azure (URI SAN for example)
resource "azurekvca_signing_request" "example" {
  csr_pem_in = azurekvca_certificate.example.csr_pem

  names = {
    email = [
      "test@test.com",
    ]
    dns = [
      "test.com"
    ]
    ip = [
      "127.0.0.1"
    ]
    uri = [
      "spiffe://test"
    ]
  }
}

resource "azurekvca_signed_certificate" "example" {
  vault_url           = azurekvca_certificate.example.vault_url
  ca_name             = azurekvca_certificate.example.name
  validity_days       = 30
  signature_algorithm = "RS256"
  csr_pem             = azurekvca_signing_request.example.csr_pem_out
}

resource "azurekvca_merged_certificate" "example" {
  vault_url = azurekvca_certificate.example.vault_url
  name      = azurekvca_certificate.example.name
  cert_pem  = azurekvca_signed_certificate.example.signed_cert_pem
}
```

# TODO
* Create and Merge resources don't attempt to sync their state with the Azure
* Create doesn't support self-signed or CA certs for creating the CA itself
* Only support for PEM certs so far, no pkcs12
