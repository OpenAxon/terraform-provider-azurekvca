terraform {
  required_providers {
    azurekvca = {
      source  = "terraform.local/local/azurekvca"
      version = "0.0.1"
    }
  }
}

provider "azurekvca" {}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy    = true
      recover_soft_deleted_key_vaults = true
    }
  }
}

data "azurerm_client_config" "current" {}
