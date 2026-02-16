#------------------------------------------------------------------------------
# KEY VAULT MODULE - INPUT VARIABLES
#------------------------------------------------------------------------------

variable "keyvault_name" {
  description = "Name of the Key Vault (must be globally unique)"
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

variable "sku_name" {
  description = "Key Vault SKU (standard or premium)"
  type        = string
  default     = "standard"

  validation {
    condition     = contains(["standard", "premium"], var.sku_name)
    error_message = "SKU must be standard or premium."
  }
}

variable "allowed_ip_ranges" {
  description = "IP ranges allowed to access Key Vault"
  type        = list(string)
  default     = []
}

variable "allowed_subnet_ids" {
  description = "Subnet IDs allowed to access Key Vault via service endpoints"
  type        = list(string)
  default     = []
}

variable "aks_identity_principal_id" {
  description = "Principal ID of AKS managed identity for secrets access"
  type        = string
  default     = ""
}

variable "jenkins_identity_principal_id" {
  description = "Principal ID of Jenkins managed identity for secrets access"
  type        = string
  default     = ""
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
