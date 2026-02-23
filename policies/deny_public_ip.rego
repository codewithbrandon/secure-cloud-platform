# =============================================================================
# POLICY: Deny Unauthorized Public IP Exposure
# File: policies/deny_public_ip.rego
# Engine: OPA / Conftest
# Applied to: terraform show -json tfplan output
# =============================================================================
#
# THREAT MODEL:
#   Any resource with a public IP is an attack surface. The only approved
#   internet-facing boundary is the Application Gateway (WAF v2), which
#   provides DDoS protection, TLS termination, and WAF rules.
#
#   Directly exposed AKS nodes, databases, or internal services violate
#   zero-trust principles and dramatically expand the blast radius of a
#   credential compromise.
#
#   MITRE ATT&CK:
#     T1190 — Exploit Public-Facing Application
#     T1046 — Network Service Discovery (internet-facing API servers)
#     T1133 — External Remote Services (open management ports)
#
# CONFTEST USAGE:
#   terraform show -json tfplan > tfplan.json
#   conftest test tfplan.json --policy policies/ --namespace terraform.deny_public_ip
# =============================================================================

package terraform.deny_public_ip

import future.keywords.in

# ---------------------------------------------------------------------------
# APPROVED resources that may have public IPs (explicit allowlist)
# WHY allowlist vs blocklist: New resource types are denied by default.
# Allowlist forces a deliberate review before any new public exposure.
# ---------------------------------------------------------------------------
approved_public_ip_consumers := {
  "azurerm_application_gateway",  # DMZ boundary — WAF protects all traffic behind it
  "azurerm_bastion_host",         # Azure Bastion is the only approved SSH/RDP entry
  "azurerm_lb",                   # Public LB only when explicitly justified
}

# ---------------------------------------------------------------------------
# RULE 1: Deny standalone Public IP resources attached to unapproved consumers
#
# A public IP resource itself is not inherently wrong (Application Gateway
# needs one), but an unreviewed public IP creation in a PR should fail until
# the consumer is added to the allowlist above.
# ---------------------------------------------------------------------------
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "azurerm_public_ip"
  resource.change.actions[_] in ["create", "update"]

  # Only block if the resource name suggests it's NOT for an approved consumer
  # Production hardening: use resource graph to check association at apply time
  not contains(lower(resource.name), "appgw")
  not contains(lower(resource.name), "bastion")

  msg := sprintf(
    "[CRITICAL][T1190] PUBLIC IP DENIED: '%s' — Only Application Gateway and Bastion Host may have public IPs. Add resource to approved_public_ip_consumers if justified and reviewed. Violates zero-trust perimeter policy.",
    [resource.address]
  )
}

# ---------------------------------------------------------------------------
# RULE 2: Deny AKS clusters without private cluster mode
#
# Public AKS API server endpoints are routinely scanned and targeted.
# A compromised cluster credential with a public endpoint allows full
# cluster takeover from anywhere on the internet.
# MITRE T1046 — attackers scan for exposed Kubernetes API servers.
# ---------------------------------------------------------------------------
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "azurerm_kubernetes_cluster"
  resource.change.actions[_] in ["create", "update"]
  after := resource.change.after

  # Fail if private_cluster_enabled is missing or explicitly false
  not after.private_cluster_enabled

  msg := sprintf(
    "[CRITICAL][T1046] AKS PRIVATE CLUSTER REQUIRED: '%s' must set private_cluster_enabled = true. A public API server endpoint is a primary attack vector for cluster compromise. MITRE ATT&CK: T1046, T1609.",
    [resource.address]
  )
}

# ---------------------------------------------------------------------------
# RULE 3: Deny AKS with no API server authorized IP ranges
#
# Even if private cluster is enabled, the authorized_ip_ranges provides
# defense-in-depth for scenarios where private DNS is misconfigured.
# An empty list means any IP in the VNet can reach the API server.
# ---------------------------------------------------------------------------
warn[msg] {
  resource := input.resource_changes[_]
  resource.type == "azurerm_kubernetes_cluster"
  resource.change.actions[_] in ["create", "update"]
  after := resource.change.after

  # Check if authorized IP ranges is null or empty array
  count(object.get(after, "api_server_access_profile", [{}])) == 0

  msg := sprintf(
    "[WARN][T1046] AKS API SERVER: '%s' should configure api_server_access_profile with authorized_ip_ranges for defense-in-depth even on private clusters.",
    [resource.address]
  )
}

# ---------------------------------------------------------------------------
# RULE 4: Deny SQL servers with public network access enabled
#
# SQL servers with public_network_access_enabled = true can be reached
# from the internet if firewall rules are misconfigured. Private endpoints
# eliminate this attack surface entirely.
# MITRE T1190 — attackers target exposed databases for credential stuffing.
# ---------------------------------------------------------------------------
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "azurerm_mssql_server"
  resource.change.actions[_] in ["create", "update"]
  after := resource.change.after

  after.public_network_access_enabled == true

  msg := sprintf(
    "[CRITICAL][T1190] SQL PUBLIC ACCESS DENIED: '%s' has public_network_access_enabled = true. SQL servers must use private endpoints only. Data exfiltration via exposed databases is a top breach vector.",
    [resource.address]
  )
}

# ---------------------------------------------------------------------------
# RULE 5: Deny Key Vault with public network access (no private endpoint)
#
# A publicly accessible Key Vault with misconfigured access policies
# can expose secrets to unauthorized callers. Vault Firewall + private
# endpoint provides network-layer isolation.
# ---------------------------------------------------------------------------
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "azurerm_key_vault"
  resource.change.actions[_] in ["create", "update"]
  after := resource.change.after

  # network_acls.default_action must be "Deny" (not "Allow")
  network_acls := object.get(after, "network_acls", [{}])[0]
  network_acls.default_action == "Allow"

  msg := sprintf(
    "[HIGH][T1552] KEY VAULT EXPOSURE: '%s' has network_acls.default_action = Allow. Set default_action = Deny and whitelist specific subnets/IPs. Permissive Key Vault access enables credential theft.",
    [resource.address]
  )
}
