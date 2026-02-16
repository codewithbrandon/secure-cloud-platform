#------------------------------------------------------------------------------
# MONITORING MODULE - OUTPUTS
#------------------------------------------------------------------------------

output "workspace_id" {
  description = "Log Analytics workspace resource ID"
  value       = azurerm_log_analytics_workspace.main.id
}

output "workspace_name" {
  description = "Log Analytics workspace name"
  value       = azurerm_log_analytics_workspace.main.name
}

output "workspace_customer_id" {
  description = "Log Analytics workspace customer ID (for agent configuration)"
  value       = azurerm_log_analytics_workspace.main.workspace_id
}

output "primary_shared_key" {
  description = "Primary shared key for agent authentication"
  value       = azurerm_log_analytics_workspace.main.primary_shared_key
  sensitive   = true
}
