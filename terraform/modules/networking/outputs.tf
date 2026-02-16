#------------------------------------------------------------------------------
# NETWORKING MODULE - OUTPUTS
#------------------------------------------------------------------------------
# These outputs allow other modules to reference network resources
# without creating tight coupling between modules.
#------------------------------------------------------------------------------

output "vnet_id" {
  description = "Virtual network resource ID"
  value       = azurerm_virtual_network.main.id
}

output "vnet_name" {
  description = "Virtual network name"
  value       = azurerm_virtual_network.main.name
}

output "subnet_ids" {
  description = "Map of subnet IDs"
  value = {
    aks   = azurerm_subnet.aks.id
    appgw = azurerm_subnet.appgw.id
    data  = azurerm_subnet.data.id
    mgmt  = azurerm_subnet.mgmt.id
    acr   = azurerm_subnet.acr.id
  }
}

output "subnet_address_prefixes" {
  description = "Map of subnet address prefixes"
  value = {
    aks   = azurerm_subnet.aks.address_prefixes[0]
    appgw = azurerm_subnet.appgw.address_prefixes[0]
    data  = azurerm_subnet.data.address_prefixes[0]
    mgmt  = azurerm_subnet.mgmt.address_prefixes[0]
    acr   = azurerm_subnet.acr.address_prefixes[0]
  }
}

output "nsg_ids" {
  description = "Map of NSG IDs"
  value = {
    aks   = azurerm_network_security_group.aks.id
    appgw = azurerm_network_security_group.appgw.id
    data  = azurerm_network_security_group.data.id
    mgmt  = azurerm_network_security_group.mgmt.id
    acr   = azurerm_network_security_group.acr.id
  }
}
