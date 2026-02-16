#------------------------------------------------------------------------------
# KEY VAULT MODULE - SECRETS MANAGEMENT
#------------------------------------------------------------------------------
# Security Purpose:
# - Centralized secrets storage (no secrets in code, config, or env vars)
# - HSM-backed encryption for sensitive data
# - Fine-grained access control via RBAC
# - Audit logging for compliance and threat detection
# - Soft-delete protection against accidental/malicious deletion
#
# Enterprise Relevance:
# - Required for PCI-DSS, HIPAA, SOC2 compliance
# - Enables secrets rotation without application changes
# - Supports certificate management for TLS
# - Integration with AKS via CSI driver for pod-level secrets
#
# Zero Trust Implementation:
# - Each identity gets explicit access to specific secrets
# - No shared credentials or admin accounts
# - All access is logged and auditable
#------------------------------------------------------------------------------

# Get current Azure client configuration for access policies
data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "main" {
  name                = var.keyvault_name
  location            = var.location
  resource_group_name = var.resource_group_name
  tenant_id           = data.azurerm_client_config.current.tenant_id

  # SKU: standard for software-protected keys, premium for HSM-protected
  sku_name = var.sku_name

  #----------------------------------------------------------------------------
  # SECURITY CONFIGURATIONS
  #----------------------------------------------------------------------------

  # RBAC Authorization: Modern approach using Azure RBAC instead of access policies
  # Benefits: Consistent with other Azure resources, better auditability
  enable_rbac_authorization = true

  # Soft Delete: Protects against accidental or malicious deletion
  # Deleted vaults/secrets are retained for recovery period
  soft_delete_retention_days = 90

  # Purge Protection: Once enabled, cannot be disabled
  # Prevents permanent deletion during soft-delete retention period
  # CRITICAL for production - protects against insider threats
  purge_protection_enabled = true

  # Network ACLs: Restrict access to specific networks
  # Default deny - only allow from specified subnets and IPs
  network_acls {
    default_action             = "Deny"
    bypass                     = "AzureServices" # Allow Azure trusted services
    ip_rules                   = var.allowed_ip_ranges
    virtual_network_subnet_ids = var.allowed_subnet_ids
  }

  # Disable public network access in favor of private endpoints (production)
  # For portfolio, we allow access from specific subnets via service endpoints
  public_network_access_enabled = true # Set to false when using private endpoints

  tags = var.tags
}

#------------------------------------------------------------------------------
# RBAC ROLE ASSIGNMENTS
#------------------------------------------------------------------------------
# Grant specific identities access to Key Vault using Azure RBAC
# This is more granular than legacy access policies
#------------------------------------------------------------------------------

# Grant the deploying user/service principal admin access
resource "azurerm_role_assignment" "deployer_admin" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Administrator"
  principal_id         = data.azurerm_client_config.current.object_id
}

# Grant AKS managed identity access to read secrets
# This enables pods to retrieve secrets via CSI driver
resource "azurerm_role_assignment" "aks_secrets_user" {
  count                = var.aks_identity_principal_id != "" ? 1 : 0
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = var.aks_identity_principal_id
}

# Grant Jenkins managed identity access to read secrets
# Jenkins needs secrets for deployment configurations
resource "azurerm_role_assignment" "jenkins_secrets_user" {
  count                = var.jenkins_identity_principal_id != "" ? 1 : 0
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = var.jenkins_identity_principal_id
}

#------------------------------------------------------------------------------
# DIAGNOSTIC SETTINGS
#------------------------------------------------------------------------------
# Send all Key Vault audit logs to Log Analytics for security monitoring
# Critical for detecting unauthorized access attempts
#------------------------------------------------------------------------------

resource "azurerm_monitor_diagnostic_setting" "keyvault" {
  name                       = "keyvault-diagnostics"
  target_resource_id         = azurerm_key_vault.main.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  # Audit logs capture all data plane operations
  enabled_log {
    category = "AuditEvent"
  }

  # Azure Policy audit logs
  enabled_log {
    category = "AzurePolicyEvaluationDetails"
  }

  # Metrics for performance monitoring
  metric {
    category = "AllMetrics"
    enabled  = true
  }
}
