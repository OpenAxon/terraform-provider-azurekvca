resource "azurerm_key_vault_certificate" "example" {
  name         = "locmai-dev-root-ca"
  key_vault_id = azurerm_key_vault.example.id

  certificate_policy {
    issuer_parameters {
      name = "Self"
    }

    key_properties {
      exportable = false
      key_size   = 2048
      key_type   = "RSA"
      reuse_key  = true
    }

    lifetime_action {
      action {
        action_type = "AutoRenew"
      }

      trigger {
        days_before_expiry = 30
      }
    }

    secret_properties {
      content_type = "application/x-pem-file"
    }

    x509_certificate_properties {
      key_usage = [
        "digitalSignature",
        "keyCertSign",
      ]

      subject            = "CN=locmai.dev"
      validity_in_months = 120
    }
  }
}

resource "azurekvca_certificate" "example" {
  vault_url = azurerm_key_vault.example.vault_uri
  name      = "locmai-intermediate-cert"
  ca_name   = azurerm_key_vault_certificate.example.name

  certificate_policy = {
    key_properties = {
      exportable = true
      key_size   = 2048
      key_type   = "RSA"
      reuse_key  = true
    }

    secret_properties = {
      content_type = "application/x-pem-file"
    }

    x509_certificate_properties = {
      key_usage = [
        "digitalSignature",
        "keyCertSign",
      ]

      subject = "CN=locmai.dev"
      subject_alternative_names = {
        dns_names = [
          "locmai.dev",
          "test.locmai.dev",
        ]
      }
      validity_in_months = 1
    }
  }
}
