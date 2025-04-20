resource "azurekvca_certificate" "example" {
  vault_url = azurerm_key_vault.example.vault_uri
  name      = "intermediate-ca-cloudnet1"

  key = {
    exportable = true
    key_size   = 2048
    key_type   = "RSA"
    reuse_key  = true
  }

  trigger = "Change me to trigger a recreate"
}

# # Optionally mangle the CSR to add values not supported by Azure (URI SAN for example)
# resource "azurekvca_signing_request" "example" {
#   csr_pem_in = azurekvca_certificate.example.csr_pem
#   # name       = azurekvca_certificate.example.name
#   name      = "root-ca"
#   vault_url = azurerm_key_vault.example.vault_uri
#
#   names = {
#     email = [
#       "locmai0201@gmail.com",
#     ]
#     dns = [
#       "cloudnet1.locmai.dev"
#     ]
#     ip = [
#       "127.0.0.1"
#     ]
#     uri = [
#       "spiffe://test"
#     ]
#   }
# }
#
# resource "azurekvca_signed_certificate" "example" {
#   vault_url           = azurekvca_certificate.example.vault_url
#   ca_name             = "root-ca"
#   validity_days       = 30
#   signature_algorithm = "RS256"
#   csr_pem             = azurekvca_signing_request.example.csr_pem_out
# }
#
# resource "azurekvca_merged_certificate" "example" {
#   vault_url = azurekvca_certificate.example.vault_url
#   name      = azurekvca_certificate.example.name
#   cert_pem  = azurekvca_signed_certificate.example.signed_cert_pem
# }

