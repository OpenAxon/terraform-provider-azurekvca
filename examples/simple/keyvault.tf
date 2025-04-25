resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "East US"
}

resource "azurerm_key_vault" "example" {
  name                = "example-tfprovider-test"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  tenant_id = data.azurerm_client_config.current.tenant_id

  sku_name = "standard"

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    key_permissions = [
      "Get",
      "Sign",
      "Encrypt",
      "Decrypt",
      "List",
      "Create",
      "Verify",
      "Update",
      "Import",
      "Delete",
      "Recover",
      "Backup",
      "Restore",
      "GetRotationPolicy",
      "SetRotationPolicy",
      "Rotate",
    ]

    secret_permissions = [
      "Get",
    ]

    storage_permissions = [
      "Get",
    ]
    certificate_permissions = [
      "Get",
      "Create",
      "Import",
      "List",
      "ListIssuers",
      "ManageIssuers",
      "Delete",
      "DeleteIssuers",
      "Purge",
    ]
  }
}
