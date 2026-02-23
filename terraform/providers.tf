# =============================================================================
# PROVIDERS.TF — Terraform Provider & Backend Configuration
# Project: Secure Cloud Platform
# =============================================================================
# WHY THIS FILE EXISTS:
#   Provider versions are pinned to prevent silent breaking changes from
#   upstream provider updates. In production CI/CD, unpinned providers
#   can cause "it worked yesterday" failures that are hard to diagnose.
#
# OIDC authentication replaces client-secret credentials so that no
# long-lived secrets exist in the pipeline environment. If a pipeline
# agent is compromised, OIDC tokens are short-lived and scope-limited.
# =============================================================================

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90"
      # WHY pinned to ~>3.90: AzureRM 4.x introduces breaking changes.
      # Minor-version range allows security patches while blocking major rewrites.
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.47"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # ---------------------------------------------------------------------------
  # REMOTE STATE — Azure Blob Storage with state locking
  # WHY: Local state is incompatible with CI/CD — multiple agents running
  # simultaneously would corrupt the state file. Azure Blob provides built-in
  # lease-based locking that prevents concurrent applies.
  #
  # SECURITY: The storage account should have:
  #   - Soft delete enabled (recover from accidental state wipes)
  #   - Versioning enabled (audit trail of state changes)
  #   - Private endpoint or service endpoint (no public blob access)
  #   - RBAC: pipeline SP gets "Storage Blob Data Contributor" on container only
  # ---------------------------------------------------------------------------
  backend "azurerm" {
    resource_group_name  = "rg-terraform-state"
    storage_account_name = "stterraformstate001"  # override via -backend-config in CI
    container_name       = "tfstate"
    key                  = "secure-cloud-platform.tfstate"

    # WHY use_oidc: Workload Identity Federation eliminates the need to store
    # ARM_CLIENT_SECRET in Jenkins credentials. The pipeline exchanges a
    # short-lived OIDC token for an Azure access token at runtime.
    use_oidc = true
  }
}

provider "azurerm" {
  # OIDC auth: ARM_CLIENT_ID, ARM_TENANT_ID, ARM_SUBSCRIPTION_ID set via env vars
  # ARM_CLIENT_SECRET is NOT needed when use_oidc = true
  use_oidc = true

  features {
    key_vault {
      # WHY: Prevents accidental permanent deletion of Key Vaults containing
      # production secrets. Soft-delete gives a 90-day recovery window.
      purge_soft_delete_on_destroy    = false
      recover_soft_deleted_key_vaults = true
    }

    resource_group {
      # WHY: Forces an explicit check before destroying a resource group.
      # Without this, `terraform destroy` silently deletes all child resources.
      # This is a defense-in-depth control against accidental data loss.
      prevent_deletion_if_contains_resources = true
    }

    virtual_machine {
      # WHY: Detaches and preserves OS disks on VM deletion.
      # Allows forensic analysis if a node is compromised before disk wipe.
      delete_os_disk_on_deletion = false
    }
  }
}

provider "azuread" {
  # Used for AKS AAD integration and service principal lookups
  use_oidc = true
}
