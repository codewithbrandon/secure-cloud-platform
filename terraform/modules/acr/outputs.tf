#------------------------------------------------------------------------------
# ACR MODULE - OUTPUTS
#------------------------------------------------------------------------------

output "acr_id" {
  description = "Container Registry resource ID"
  value       = azurerm_container_registry.main.id
}

output "acr_name" {
  description = "Container Registry name"
  value       = azurerm_container_registry.main.name
}

output "acr_login_server" {
  description = "Container Registry login server URL"
  value       = azurerm_container_registry.main.login_server
}

output "acr_admin_username" {
  description = "Container Registry admin username (empty if admin disabled)"
  value       = azurerm_container_registry.main.admin_enabled ? azurerm_container_registry.main.admin_username : ""
  sensitive   = true
}

output "acr_admin_password" {
  description = "Container Registry admin password (empty if admin disabled)"
  value       = azurerm_container_registry.main.admin_enabled ? azurerm_container_registry.main.admin_password : ""
  sensitive   = true
}
