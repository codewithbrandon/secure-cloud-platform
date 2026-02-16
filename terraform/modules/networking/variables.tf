#------------------------------------------------------------------------------
# NETWORKING MODULE - INPUT VARIABLES
#------------------------------------------------------------------------------

variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
}

variable "location" {
  description = "Azure region"
  type        = string
}

variable "vnet_name" {
  description = "Name of the virtual network"
  type        = string
}

variable "vnet_address_space" {
  description = "Address space for the VNet"
  type        = list(string)
}

variable "subnet_names" {
  description = "Map of subnet names"
  type        = map(string)
}

variable "subnet_prefixes" {
  description = "Map of subnet CIDR blocks"
  type = object({
    aks   = string
    appgw = string
    data  = string
    mgmt  = string
    acr   = string
  })
}

variable "nsg_names" {
  description = "Map of NSG names"
  type        = map(string)
}

variable "admin_ip_addresses" {
  description = "Admin IP addresses for management access"
  type        = list(string)
  sensitive   = true
}

variable "tags" {
  description = "Resource tags"
  type        = map(string)
  default     = {}
}
