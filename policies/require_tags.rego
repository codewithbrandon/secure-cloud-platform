# =============================================================================
# POLICY: Require Mandatory Resource Tags
# File: policies/require_tags.rego
# Engine: OPA / Conftest
# Applied to: terraform show -json tfplan output
# =============================================================================
#
# WHY TAGS MATTER FOR SECURITY:
#   1. INCIDENT RESPONSE: Owner tag = immediate contact at 2 AM.
#   2. COMPLIANCE: SOC 2/PCI-DSS require full asset inventory with ownership.
#   3. SHIFT-LEFT: OPA enforces tags at plan time, before any Azure API call.
#   4. DATA CLASSIFICATION: Drives encryption, backup, and access policy.
#
# CONFTEST USAGE:
#   conftest test tfplan.json --policy policies/ --namespace terraform.require_tags
# =============================================================================

package terraform.require_tags

import future.keywords.in

# ---------------------------------------------------------------------------
# REQUIRED TAGS
# ---------------------------------------------------------------------------
required_tags := {
  "Environment",
  "Team",
  "CostCenter",
  "Owner",
  "ManagedBy",
  "DataClassification",
}

# ---------------------------------------------------------------------------
# TAGGABLE resource types
# ---------------------------------------------------------------------------
taggable_resource_types := {
  "azurerm_resource_group",
  "azurerm_kubernetes_cluster",
  "azurerm_container_registry",
  "azurerm_log_analytics_workspace",
  "azurerm_key_vault",
  "azurerm_mssql_server",
  "azurerm_mssql_database",
  "azurerm_virtual_network",
  "azurerm_network_security_group",
  "azurerm_public_ip",
  "azurerm_application_gateway",
  "azurerm_linux_virtual_machine",
  "azurerm_storage_account",
}

valid_data_classifications := {"public", "internal", "confidential", "restricted"}

valid_managed_by_values := {"Terraform", "terraform"}

# ---------------------------------------------------------------------------
# RULE 1: Deny resources missing any required tag
# ---------------------------------------------------------------------------
deny[msg] {
  resource := input.resource_changes[_]
  resource.type in taggable_resource_types
  resource.change.actions[_] in ["create", "update"]
  after := resource.change.after

  required_tag := required_tags[_]
  not after.tags[required_tag]

  msg := sprintf(
    "[HIGH][COMPLIANCE] MISSING TAG: Resource '%s' (type: %s) is missing required tag '%s'. All resources must be tagged for incident response and compliance inventory.",
    [resource.address, resource.type, required_tag]
  )
}

# ---------------------------------------------------------------------------
# RULE 2: Deny invalid DataClassification values
#
# A typo silently disables downstream encryption and access policy decisions.
# ---------------------------------------------------------------------------
deny[msg] {
  resource := input.resource_changes[_]
  resource.type in taggable_resource_types
  resource.change.actions[_] in ["create", "update"]
  after := resource.change.after

  classification := after.tags.DataClassification
  classification != null
  not valid_data_classifications[lower(classification)]

  msg := sprintf(
    "[HIGH][COMPLIANCE] INVALID DATA CLASSIFICATION: '%s' has DataClassification = '%s'. Valid: public | internal | confidential | restricted",
    [resource.address, classification]
  )
}

# ---------------------------------------------------------------------------
# RULE 3: Deny resources with ManagedBy != "Terraform"
#
# Non-Terraform resources are outside version control, bypassing security
# scans and drift detection. This is a governance and audit finding.
# ---------------------------------------------------------------------------
deny[msg] {
  resource := input.resource_changes[_]
  resource.type in taggable_resource_types
  resource.change.actions[_] in ["create", "update"]
  after := resource.change.after

  managed_by := after.tags.ManagedBy
  managed_by != null
  not valid_managed_by_values[managed_by]

  msg := sprintf(
    "[MEDIUM][GOVERNANCE] UNMANAGED RESOURCE: '%s' has ManagedBy = '%s'. Only Terraform-managed resources are permitted in this environment.",
    [resource.address, managed_by]
  )
}

# ---------------------------------------------------------------------------
# RULE 4: Warn on Owner tags that are not email addresses
#
# Non-email owners cannot receive automated incident alerts.
# ---------------------------------------------------------------------------
warn[msg] {
  resource := input.resource_changes[_]
  resource.type in taggable_resource_types
  resource.change.actions[_] in ["create", "update"]
  after := resource.change.after

  owner := after.tags.Owner
  owner != null
  not contains(owner, "@")

  msg := sprintf(
    "[WARN][COMPLIANCE] OWNER TAG NOT EMAIL: Resource '%s' has Owner = '%s'. Owner must be a valid email address for automated incident alerting.",
    [resource.address, owner]
  )
}

# ---------------------------------------------------------------------------
# RULE 5: Deny invalid CostCenter format
#
# Finance requires CC-XXXX format for automated chargeback reconciliation.
# ---------------------------------------------------------------------------
deny[msg] {
  resource := input.resource_changes[_]
  resource.type in taggable_resource_types
  resource.change.actions[_] in ["create", "update"]
  after := resource.change.after

  cost_center := after.tags.CostCenter
  cost_center != null
  not regex.match(`^CC-[A-Z0-9]{3,8}$`, cost_center)

  msg := sprintf(
    "[MEDIUM][COMPLIANCE] INVALID COST CENTER: '%s' has CostCenter = '%s'. Required format: CC-XXXX (e.g., CC-PLAT, CC-SEC001).",
    [resource.address, cost_center]
  )
}

# ---------------------------------------------------------------------------
# RULE 6: Production databases and vaults must not be classified 'public'
# ---------------------------------------------------------------------------
deny[msg] {
  resource := input.resource_changes[_]
  resource.type in {"azurerm_mssql_server", "azurerm_mssql_database", "azurerm_key_vault"}
  resource.change.actions[_] in ["create", "update"]
  after := resource.change.after

  after.tags.Environment == "prod"
  lower(after.tags.DataClassification) == "public"

  msg := sprintf(
    "[HIGH][COMPLIANCE] CLASSIFICATION MISMATCH: '%s' is a prod %s classified as 'public'. Databases and Key Vaults in prod must be 'confidential' or 'restricted'.",
    [resource.address, resource.type]
  )
}
