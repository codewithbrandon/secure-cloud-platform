#------------------------------------------------------------------------------
# KEY VAULT MODULE - OUTPUTS
#------------------------------------------------------------------------------

output "keyvault_id" {
  description = "Key Vault resource ID"
  value       = azurerm_key_vault.main.id
}

output "keyvault_name" {
  description = "Key Vault name"
  value       = azurerm_key_vault.main.name
}

output "keyvault_uri" {
  description = "Key Vault URI for SDK/CLI access"
  value       = azurerm_key_vault.main.vault_uri
}

output "keyvault_tenant_id" {
  description = "Azure AD tenant ID for Key Vault"
  value       = azurerm_key_vault.main.tenant_id
}
