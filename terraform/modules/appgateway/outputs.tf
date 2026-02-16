#------------------------------------------------------------------------------
# APPLICATION GATEWAY MODULE - OUTPUTS
#------------------------------------------------------------------------------

output "appgw_id" {
  description = "Application Gateway resource ID"
  value       = azurerm_application_gateway.main.id
}

output "appgw_name" {
  description = "Application Gateway name"
  value       = azurerm_application_gateway.main.name
}

output "public_ip_address" {
  description = "Public IP address of Application Gateway"
  value       = azurerm_public_ip.appgw.ip_address
}

output "public_ip_fqdn" {
  description = "FQDN of Application Gateway public IP"
  value       = azurerm_public_ip.appgw.fqdn
}

output "backend_address_pool_id" {
  description = "Backend address pool ID"
  value       = tolist(azurerm_application_gateway.main.backend_address_pool)[0].id
}
