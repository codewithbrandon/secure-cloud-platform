#------------------------------------------------------------------------------
# SQL MODULE - INPUT VARIABLES
#------------------------------------------------------------------------------

variable "server_name" {
  description = "Name of the SQL Server (must be globally unique)"
  type        = string
}

variable "database_name" {
  description = "Name of the SQL Database"
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

#------------------------------------------------------------------------------
# AUTHENTICATION
#------------------------------------------------------------------------------

variable "admin_username" {
  description = "SQL Server administrator username"
  type        = string

  validation {
    condition     = !contains(["admin", "administrator", "sa", "root", "dbmanager"], lower(var.admin_username))
    error_message = "Admin username cannot be a reserved name."
  }
}

variable "admin_password" {
  description = "SQL Server administrator password"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.admin_password) >= 16
    error_message = "Password must be at least 16 characters."
  }
}

variable "aad_admin_username" {
  description = "Azure AD administrator display name"
  type        = string
  default     = ""
}

variable "aad_admin_object_id" {
  description = "Azure AD administrator object ID"
  type        = string
  default     = ""
}

#------------------------------------------------------------------------------
# DATABASE CONFIGURATION
#------------------------------------------------------------------------------

variable "sku_name" {
  description = "SQL Database SKU (Basic, S0, S1, P1, etc.)"
  type        = string
  default     = "S0"
}

variable "max_size_gb" {
  description = "Maximum database size in GB"
  type        = number
  default     = 2
}

variable "zone_redundant" {
  description = "Enable zone redundancy (Premium/Business Critical only)"
  type        = bool
  default     = false
}

variable "backup_storage_redundancy" {
  description = "Backup storage redundancy (Local, Zone, Geo, GeoZone)"
  type        = string
  default     = "Local" # Cost optimization for portfolio

  validation {
    condition     = contains(["Local", "Zone", "Geo", "GeoZone"], var.backup_storage_redundancy)
    error_message = "Must be Local, Zone, Geo, or GeoZone."
  }
}

#------------------------------------------------------------------------------
# NETWORK ACCESS
#------------------------------------------------------------------------------

variable "allow_azure_services" {
  description = "Allow Azure services to access the database"
  type        = bool
  default     = true
}

variable "allowed_ip_addresses" {
  description = "IP addresses allowed to access SQL Server"
  type        = list(string)
  default     = []
}

variable "allowed_subnet_ids" {
  description = "Subnet IDs allowed to access SQL via service endpoints"
  type        = list(string)
  default     = []
}

variable "enable_private_endpoint" {
  description = "Enable private endpoint for SQL Server"
  type        = bool
  default     = false
}

variable "private_endpoint_subnet_id" {
  description = "Subnet ID for private endpoint"
  type        = string
  default     = ""
}

variable "vnet_id" {
  description = "VNet ID for private DNS zone link"
  type        = string
  default     = ""
}

#------------------------------------------------------------------------------
# AUDITING AND SECURITY
#------------------------------------------------------------------------------

variable "audit_storage_endpoint" {
  description = "Storage account endpoint for audit logs"
  type        = string
  default     = ""
}

variable "audit_storage_access_key" {
  description = "Storage account access key for audit logs"
  type        = string
  sensitive   = true
  default     = ""
}

variable "audit_retention_days" {
  description = "Audit log retention in days"
  type        = number
  default     = 30
}

variable "security_alert_emails" {
  description = "Email addresses for security alerts"
  type        = list(string)
  default     = []
}

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
