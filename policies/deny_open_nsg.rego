# =============================================================================
# POLICY: Deny Open Network Security Group Rules
# File: policies/deny_open_nsg.rego
# Engine: OPA / Conftest
# Applied to: terraform show -json tfplan output
# =============================================================================
#
# THREAT MODEL:
#   NSG rules that allow 0.0.0.0/0 on management ports (SSH:22, RDP:3389,
#   WinRM:5985/5986) create a permanent, internet-facing attack surface.
#   These ports are continuously scanned; credential stuffing and
#   vulnerability exploitation begin within minutes of exposure.
#
#   NSG rules that allow 0.0.0.0/0 on ANY port violate zero-trust networking
#   and contradict a default-deny perimeter model.
#
#   MITRE ATT&CK:
#     T1021.004 — Remote Services: SSH (open port 22 to internet)
#     T1021.001 — Remote Services: RDP (open port 3389 to internet)
#     T1133     — External Remote Services
#     T1190     — Exploit Public-Facing Application
#
# CONFTEST USAGE:
#   conftest test tfplan.json --policy policies/ --namespace terraform.deny_open_nsg
# =============================================================================

package terraform.deny_open_nsg

import future.keywords.in

# ---------------------------------------------------------------------------
# CONSTANTS — ports that must NEVER be open to the internet
# ---------------------------------------------------------------------------
critical_management_ports := {22, 3389, 5985, 5986, 23, 21}
# SSH, RDP, WinRM-HTTP, WinRM-HTTPS, Telnet, FTP

# ---------------------------------------------------------------------------
# HELPER: Determine if a source address prefix represents the internet
# ---------------------------------------------------------------------------
is_internet_source(prefix) {
  prefix == "*"
}
is_internet_source(prefix) {
  prefix == "0.0.0.0/0"
}
is_internet_source(prefix) {
  prefix == "Internet"
}
is_internet_source(prefix) {
  prefix == "Any"
}

# ---------------------------------------------------------------------------
# HELPER: Determine if a port range covers a specific port
# ---------------------------------------------------------------------------
port_in_range(port, range_str) {
  # Exact match
  to_number(range_str) == port
}
port_in_range(port, range_str) {
  # Range match: "22-1024"
  parts := split(range_str, "-")
  count(parts) == 2
  to_number(parts[0]) <= port
  to_number(parts[1]) >= port
}
port_in_range(_, range_str) {
  # Wildcard — covers all ports
  range_str == "*"
}

# ---------------------------------------------------------------------------
# RULE 1: Deny NSG rules allowing internet → management port (SSH/RDP)
#
# These ports must ONLY be reachable via Azure Bastion (which itself
# requires authenticated Azure AD session). No direct internet access.
# ---------------------------------------------------------------------------
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "azurerm_network_security_group"
  resource.change.actions[_] in ["create", "update"]
  after := resource.change.after

  rule := after.security_rule[_]
  rule.access == "Allow"
  rule.direction == "Inbound"
  is_internet_source(rule.source_address_prefix)

  # Check if any critical management port is covered
  critical_port := critical_management_ports[_]
  port_in_range(critical_port, rule.destination_port_range)

  msg := sprintf(
    "[CRITICAL][T1021] OPEN MANAGEMENT PORT: NSG '%s' rule '%s' allows internet (src: %s) to port %d. Management access must use Azure Bastion only. Direct internet access to SSH/RDP is the #1 initial access vector.",
    [resource.name, rule.name, rule.source_address_prefix, critical_port]
  )
}

# ---------------------------------------------------------------------------
# RULE 2: Deny standalone NSG rules (azurerm_network_security_rule) with
#         the same conditions — separate resource type check needed
# ---------------------------------------------------------------------------
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "azurerm_network_security_rule"
  resource.change.actions[_] in ["create", "update"]
  after := resource.change.after

  after.access == "Allow"
  after.direction == "Inbound"
  is_internet_source(after.source_address_prefix)

  critical_port := critical_management_ports[_]
  port_in_range(critical_port, after.destination_port_range)

  msg := sprintf(
    "[CRITICAL][T1021] OPEN MANAGEMENT PORT: NSG rule '%s' allows internet→port %d. MITRE T1021.004/T1021.001. Use Azure Bastion for all administrative access.",
    [resource.address, critical_port]
  )
}

# ---------------------------------------------------------------------------
# RULE 3: Deny ANY inbound NSG rule from 0.0.0.0/0 (catch-all)
#
# If you need internet-facing exposure, it must go through Application
# Gateway (WAF). Direct internet → VNet resource bypasses WAF controls.
# ---------------------------------------------------------------------------
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "azurerm_network_security_group"
  resource.change.actions[_] in ["create", "update"]
  after := resource.change.after

  rule := after.security_rule[_]
  rule.access == "Allow"
  rule.direction == "Inbound"
  is_internet_source(rule.source_address_prefix)
  rule.destination_port_range == "*"

  msg := sprintf(
    "[CRITICAL][T1190] OPEN INBOUND WILDCARD: NSG '%s' rule '%s' allows internet access to ALL ports. Zero-trust requires explicit port allowlisting. All internet traffic must route through WAF/AppGateway.",
    [resource.name, rule.name]
  )
}

# ---------------------------------------------------------------------------
# RULE 4: Warn on outbound Allow-All rules
#
# Unrestricted outbound allows data exfiltration and C2 beaconing.
# Outbound should be default-deny with explicit allows for required services.
# MITRE T1041 — Exfiltration Over C2 Channel
# ---------------------------------------------------------------------------
warn[msg] {
  resource := input.resource_changes[_]
  resource.type == "azurerm_network_security_group"
  resource.change.actions[_] in ["create", "update"]
  after := resource.change.after

  rule := after.security_rule[_]
  rule.access == "Allow"
  rule.direction == "Outbound"
  rule.destination_address_prefix == "*"
  rule.destination_port_range == "*"
  rule.priority >= 100
  rule.priority <= 200

  msg := sprintf(
    "[WARN][T1041] UNRESTRICTED OUTBOUND: NSG '%s' rule '%s' allows all outbound traffic. Consider default-deny outbound with explicit service tags (AzureMonitor, AzureActiveDirectory, etc.) to prevent data exfiltration.",
    [resource.name, rule.name]
  )
}

# ---------------------------------------------------------------------------
# RULE 5: Deny NSG on AKS subnet with inbound from non-VNet sources
#
# AKS subnet should only receive traffic from within the VNet
# (Application Gateway, Jenkins, etc.) — never directly from internet.
# ---------------------------------------------------------------------------
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "azurerm_network_security_group"
  resource.change.actions[_] in ["create", "update"]

  # Detect AKS-associated NSGs by name convention
  contains(lower(resource.name), "aks")

  after := resource.change.after
  rule := after.security_rule[_]
  rule.access == "Allow"
  rule.direction == "Inbound"
  is_internet_source(rule.source_address_prefix)

  msg := sprintf(
    "[CRITICAL][T1609] AKS SUBNET EXPOSED: NSG '%s' (AKS subnet) has inbound rule '%s' from internet. AKS nodes must only receive traffic from Application Gateway and VNet-internal sources.",
    [resource.name, rule.name]
  )
}
