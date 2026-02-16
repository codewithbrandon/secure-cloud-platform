#------------------------------------------------------------------------------
# AKS MODULE - INPUT VARIABLES
#------------------------------------------------------------------------------

variable "cluster_name" {
  description = "Name of the AKS cluster"
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

variable "dns_prefix" {
  description = "DNS prefix for the cluster"
  type        = string
}

variable "kubernetes_version" {
  description = "Kubernetes version"
  type        = string
  default     = "1.28"
}

variable "sku_tier" {
  description = "AKS SKU tier (Free or Standard)"
  type        = string
  default     = "Free"

  validation {
    condition     = contains(["Free", "Standard"], var.sku_tier)
    error_message = "SKU tier must be Free or Standard."
  }
}

#------------------------------------------------------------------------------
# NODE POOL CONFIGURATION
#------------------------------------------------------------------------------

variable "node_vm_size" {
  description = "VM size for nodes"
  type        = string
  default     = "Standard_B2s"
}

variable "node_count" {
  description = "Number of nodes (when autoscaling disabled)"
  type        = number
  default     = 2
}

variable "enable_auto_scaling" {
  description = "Enable cluster autoscaler"
  type        = bool
  default     = true
}

variable "min_node_count" {
  description = "Minimum nodes when autoscaling enabled"
  type        = number
  default     = 2
}

variable "max_node_count" {
  description = "Maximum nodes when autoscaling enabled"
  type        = number
  default     = 4
}

#------------------------------------------------------------------------------
# NETWORK CONFIGURATION
#------------------------------------------------------------------------------

variable "subnet_id" {
  description = "Subnet ID for AKS nodes"
  type        = string
}

variable "service_cidr" {
  description = "Kubernetes service CIDR"
  type        = string
  default     = "10.1.0.0/16"
}

variable "dns_service_ip" {
  description = "Kubernetes DNS service IP"
  type        = string
  default     = "10.1.0.10"
}

variable "authorized_ip_ranges" {
  description = "IP ranges authorized to access API server"
  type        = list(string)
  default     = []
}

#------------------------------------------------------------------------------
# IDENTITY AND ACCESS
#------------------------------------------------------------------------------

variable "admin_group_ids" {
  description = "Azure AD group IDs for cluster admin access"
  type        = list(string)
  default     = []
}

variable "disable_local_accounts" {
  description = "Disable local Kubernetes accounts (Azure AD only)"
  type        = bool
  default     = false # Enable for portfolio; set true for production
}

#------------------------------------------------------------------------------
# INTEGRATIONS
#------------------------------------------------------------------------------

variable "acr_id" {
  description = "Azure Container Registry ID for AcrPull role assignment"
  type        = string
  default     = ""
}

variable "log_analytics_workspace_id" {
  description = "Log Analytics workspace ID for monitoring"
  type        = string
}

variable "tags" {
  description = "Resource tags"
  type        = map(string)
  default     = {}
}
