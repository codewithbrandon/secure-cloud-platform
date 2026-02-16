#------------------------------------------------------------------------------
# MONITORING MODULE - INPUT VARIABLES
#------------------------------------------------------------------------------

variable "workspace_name" {
  description = "Name of the Log Analytics workspace"
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

variable "retention_days" {
  description = "Log retention in days (30-730)"
  type        = number
  default     = 30

  validation {
    condition     = var.retention_days >= 30 && var.retention_days <= 730
    error_message = "Retention must be between 30 and 730 days."
  }
}

variable "tags" {
  description = "Resource tags"
  type        = map(string)
  default     = {}
}
