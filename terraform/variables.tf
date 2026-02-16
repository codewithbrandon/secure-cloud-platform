#------------------------------------------------------------------------------
# INPUT VARIABLES
#------------------------------------------------------------------------------
# Security Note: Sensitive variables should NEVER have default values.
# Use terraform.tfvars (git-ignored) or environment variables (TF_VAR_*).
# Mark sensitive variables to prevent them from appearing in logs/output.
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# GLOBAL CONFIGURATION
#------------------------------------------------------------------------------

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "seccloud"

  validation {
    condition     = can(regex("^[a-z0-9]{3,12}$", var.project_name))
    error_message = "Project name must be 3-12 lowercase alphanumeric characters."
  }
}

variable "environment" {
  description = "Environment name (prod, staging, dev)"
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["prod", "staging", "dev"], var.environment)
    error_message = "Environment must be prod, staging, or dev."
  }
}

variable "location" {
  description = "Azure region for resource deployment"
  type        = string
  default     = "eastus"
}

variable "tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default     = {}
}

#------------------------------------------------------------------------------
# NETWORK CONFIGURATION
#------------------------------------------------------------------------------

variable "vnet_address_space" {
  description = "Address space for the virtual network"
  type        = list(string)
  default     = ["10.0.0.0/16"]
}

variable "subnet_prefixes" {
  description = "Subnet CIDR blocks"
  type = object({
    aks   = string
    appgw = string
    data  = string
    mgmt  = string
    acr   = string
  })
  default = {
    aks   = "10.0.1.0/24"
    appgw = "10.0.2.0/24"
    data  = "10.0.3.0/24"
    mgmt  = "10.0.4.0/24"
    acr   = "10.0.5.0/24"
  }
}

#------------------------------------------------------------------------------
# ACCESS CONTROL
#------------------------------------------------------------------------------

variable "admin_ip_addresses" {
  description = "IP addresses allowed to access management resources (your IP)"
  type        = list(string)
  # Note: Removed sensitive flag to allow use in for_each

  validation {
    condition     = length(var.admin_ip_addresses) > 0
    error_message = "At least one admin IP address must be specified."
  }
}

variable "aks_authorized_ip_ranges" {
  description = "IP ranges authorized to access AKS API server"
  type        = list(string)
  default     = [] # Empty = restricted to VNet + admin IPs
}

#------------------------------------------------------------------------------
# AKS CONFIGURATION
#------------------------------------------------------------------------------

variable "aks_kubernetes_version" {
  description = "Kubernetes version for AKS cluster"
  type        = string
  default     = "1.28" # Use supported version
}

variable "aks_node_count" {
  description = "Number of nodes in the default node pool"
  type        = number
  default     = 2

  validation {
    condition     = var.aks_node_count >= 2
    error_message = "Minimum 2 nodes required for high availability."
  }
}

variable "aks_node_vm_size" {
  description = "VM size for AKS nodes"
  type        = string
  default     = "Standard_B2s" # Portfolio-friendly size
}

variable "aks_enable_auto_scaling" {
  description = "Enable cluster autoscaling"
  type        = bool
  default     = true
}

variable "aks_min_node_count" {
  description = "Minimum nodes when autoscaling enabled"
  type        = number
  default     = 2
}

variable "aks_max_node_count" {
  description = "Maximum nodes when autoscaling enabled"
  type        = number
  default     = 4
}

#------------------------------------------------------------------------------
# SQL DATABASE CONFIGURATION
#------------------------------------------------------------------------------

variable "sql_admin_username" {
  description = "SQL Server administrator username"
  type        = string
  default     = "sqladmin"

  validation {
    condition     = !contains(["admin", "administrator", "sa", "root"], lower(var.sql_admin_username))
    error_message = "SQL admin username cannot be a common/reserved name."
  }
}

variable "sql_admin_password" {
  description = "SQL Server administrator password"
  type        = string
  sensitive   = true # CRITICAL: Never log passwords

  validation {
    condition     = length(var.sql_admin_password) >= 16
    error_message = "SQL admin password must be at least 16 characters."
  }
}

variable "sql_database_sku" {
  description = "SQL Database SKU name"
  type        = string
  default     = "S0" # Portfolio-friendly tier
}

#------------------------------------------------------------------------------
# JENKINS CONFIGURATION
#------------------------------------------------------------------------------

variable "jenkins_vm_size" {
  description = "VM size for Jenkins server"
  type        = string
  default     = "Standard_B2s" # Portfolio-friendly size
}

variable "jenkins_admin_username" {
  description = "Admin username for Jenkins VM"
  type        = string
  default     = "jenkinsadmin"

  validation {
    condition     = !contains(["admin", "administrator", "root"], lower(var.jenkins_admin_username))
    error_message = "Jenkins admin username cannot be a common/reserved name."
  }
}

#------------------------------------------------------------------------------
# KEY VAULT CONFIGURATION
#------------------------------------------------------------------------------

variable "keyvault_sku" {
  description = "Key Vault SKU (standard or premium)"
  type        = string
  default     = "standard"

  validation {
    condition     = contains(["standard", "premium"], var.keyvault_sku)
    error_message = "Key Vault SKU must be standard or premium."
  }
}

#------------------------------------------------------------------------------
# APPLICATION GATEWAY CONFIGURATION
#------------------------------------------------------------------------------

variable "appgw_sku_name" {
  description = "Application Gateway SKU name"
  type        = string
  default     = "Standard_v2" # WAF_v2 for production
}

variable "appgw_sku_tier" {
  description = "Application Gateway SKU tier"
  type        = string
  default     = "Standard_v2" # WAF_v2 for production
}

variable "appgw_min_capacity" {
  description = "Minimum capacity for autoscaling"
  type        = number
  default     = 1
}

variable "appgw_max_capacity" {
  description = "Maximum capacity for autoscaling"
  type        = number
  default     = 2
}
