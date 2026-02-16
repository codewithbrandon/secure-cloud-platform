#------------------------------------------------------------------------------
# TERRAFORM VERSION AND PROVIDER CONSTRAINTS
#------------------------------------------------------------------------------
# Security Note: Pinning provider versions prevents supply chain attacks where
# a compromised provider version could be automatically pulled. Always verify
# provider checksums via .terraform.lock.hcl in version control.
#------------------------------------------------------------------------------

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.47.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0.0"
    }
  }

  # PRODUCTION RECOMMENDATION: Use remote backend for state management
  # backend "azurerm" {
  #   resource_group_name  = "rg-terraform-state"
  #   storage_account_name = "stterraformstate"
  #   container_name       = "tfstate"
  #   key                  = "secure-cloud-platform.tfstate"
  #   use_azuread_auth     = true  # Use Azure AD auth instead of access keys
  # }
}

#------------------------------------------------------------------------------
# AZURE PROVIDER CONFIGURATION
#------------------------------------------------------------------------------
# Security Controls:
# - skip_provider_registration: Requires pre-registered providers (least privilege)
# - features block: Controls resource behavior on destroy
#------------------------------------------------------------------------------

provider "azurerm" {
  features {
    # Prevent accidental deletion of resources with data
    key_vault {
      purge_soft_delete_on_destroy    = false # Retain soft-deleted vaults
      recover_soft_deleted_key_vaults = true  # Recover instead of fail
    }

    resource_group {
      prevent_deletion_if_contains_resources = true # Safety net
    }

    virtual_machine {
      delete_os_disk_on_deletion     = true
      skip_shutdown_and_force_delete = false
    }
  }

  # Skip automatic provider registration - register manually if needed
  skip_provider_registration = true
}

provider "azuread" {
  # Uses Azure CLI or environment credentials
}
