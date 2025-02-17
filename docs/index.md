---
page_title: "Provider: AzureKVCA"
description: |-
  The Random provider is used to generate randomness.
---

# Terraform Provider for using Azure KeyVault as a CA

Traditionally using Azure KeyVault(KV) as a CA requires exporting the CA private key into terraform where it gets saved into state.

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

# Generate a new cert version (and cert if needed)
resource "azurekvca_create" "test" {
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
resource "azurekvca_request" "test" {
  csr_pem_in = azurekvca_create.test.csr_pem

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

# Sign CSR with CA cert in Key Vault. This does not check the CSR signature just blindly pulls the public key, subject and SAN from the request
resource "azurekvca_sign" "test" {
  vault_url           = "https://something.vault.azure.net/"
  ca_name             = "test-ca"
  validity_days       = 30
  signature_algorithm = "RS256"
  csr_pem             = azurekvca_request.test.csr_pem_out
}

# Merge the signed cert back into the original request
resource "azurekvca_merge" "test" {
  vault_url = azurekvca_create.test.vault_url
  name      = azurekvca_create.test.name
  cert_pem  = azurekvca_sign.test.signed_cert_pem
}

```

# TODO
* Create and Merge resources don't attempt to sync their state with the Azure
* Create doesn't support self-signed or CA certs for creating the CA itself
* Only support for PEM certs so far, no pkcs12
