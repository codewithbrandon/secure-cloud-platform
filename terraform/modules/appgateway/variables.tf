#------------------------------------------------------------------------------
# APPLICATION GATEWAY MODULE - INPUT VARIABLES
#------------------------------------------------------------------------------

variable "appgw_name" {
  description = "Name of the Application Gateway"
  type        = string
}

variable "location" {
  description = "Azure region"
  type        = string
}

variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
}

variable "subnet_id" {
  description = "Subnet ID for Application Gateway"
  type        = string
}

#------------------------------------------------------------------------------
# SKU CONFIGURATION
#------------------------------------------------------------------------------

variable "sku_name" {
  description = "Application Gateway SKU name (Standard_v2 or WAF_v2)"
  type        = string
  default     = "Standard_v2"

  validation {
    condition     = contains(["Standard_v2", "WAF_v2"], var.sku_name)
    error_message = "SKU must be Standard_v2 or WAF_v2."
  }
}

variable "sku_tier" {
  description = "Application Gateway SKU tier"
  type        = string
  default     = "Standard_v2"

  validation {
    condition     = contains(["Standard_v2", "WAF_v2"], var.sku_tier)
    error_message = "SKU tier must be Standard_v2 or WAF_v2."
  }
}

variable "min_capacity" {
  description = "Minimum autoscale capacity"
  type        = number
  default     = 1
}

variable "max_capacity" {
  description = "Maximum autoscale capacity"
  type        = number
  default     = 2
}

#------------------------------------------------------------------------------
# FRONTEND CONFIGURATION
#------------------------------------------------------------------------------

variable "domain_name_label" {
  description = "DNS label for public IP FQDN"
  type        = string
}

#------------------------------------------------------------------------------
# BACKEND CONFIGURATION
#------------------------------------------------------------------------------

variable "backend_ip_addresses" {
  description = "IP addresses of backend servers (AKS ingress)"
  type        = list(string)
  default     = []
}

variable "backend_host_name" {
  description = "Host name to use when connecting to backends"
  type        = string
  default     = "localhost"
}

variable "health_probe_path" {
  description = "Path for health probe"
  type        = string
  default     = "/health"
}

#------------------------------------------------------------------------------
# MONITORING
#------------------------------------------------------------------------------

variable "log_analytics_workspace_id" {
  description = "Log Analytics workspace ID for diagnostic settings"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Resource tags"
  type        = map(string)
  default     = {}
}
