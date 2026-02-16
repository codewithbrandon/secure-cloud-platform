#------------------------------------------------------------------------------
# JENKINS MODULE - INPUT VARIABLES
#------------------------------------------------------------------------------

variable "vm_name" {
  description = "Name of the Jenkins VM"
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
  description = "Subnet ID for Jenkins VM"
  type        = string
}

variable "vm_size" {
  description = "VM size"
  type        = string
  default     = "Standard_B2s"
}

variable "admin_username" {
  description = "Admin username for the VM"
  type        = string
  default     = "jenkinsadmin"

  validation {
    condition     = !contains(["admin", "administrator", "root"], lower(var.admin_username))
    error_message = "Admin username cannot be a reserved name."
  }
}

variable "domain_name_label" {
  description = "DNS label for public IP"
  type        = string
}

#------------------------------------------------------------------------------
# INTEGRATION
#------------------------------------------------------------------------------

variable "acr_id" {
  description = "ACR resource ID for push permissions"
  type        = string
  default     = ""
}

variable "aks_id" {
  description = "AKS resource ID for deployment permissions"
  type        = string
  default     = ""
}

variable "keyvault_id" {
  description = "Key Vault ID for storing SSH key"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Resource tags"
  type        = map(string)
  default     = {}
}
