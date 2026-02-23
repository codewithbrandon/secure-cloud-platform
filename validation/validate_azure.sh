#!/usr/bin/env bash
# POST-DEPLOYMENT AZURE INFRASTRUCTURE VALIDATION
# WHY: Verifies live Azure state matches security intent after terraform apply.
# 70% of cloud breaches involve misconfiguration. Catches it in minutes.
# MITRE ATT&CK: T1190 T1021 T1525 T1609 T1562
set -euo pipefail

RESOURCE_GROUP="${RESOURCE_GROUP:-}"
AKS_CLUSTER_NAME="${AKS_CLUSTER_NAME:-}"
ACR_NAME="${ACR_NAME:-}"
FAILURES=0; WARNINGS=0; CHECKS_PASSED=0

GREEN='[0;32m'; YELLOW='[1;33m'; RED='[0;31m'; BLUE='[0;34m'; NC='[0m'
log_check()   { echo -e "${BLUE}[CHECK]${NC}   $1"; }
log_pass()    { echo -e "${GREEN}[PASS]${NC}    $1"; ((CHECKS_PASSED++)) || true; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}    $1"; ((WARNINGS++)) || true; }
log_fail()    { echo -e "${RED}[CRITICAL]${NC} $1"; ((FAILURES++)) || true; }
log_section() { echo ""; echo "=== $1 ==="; }

check_prerequisites() {
  log_section "PREREQUISITES"
  [[ -z "$RESOURCE_GROUP" || -z "$AKS_CLUSTER_NAME" || -z "$ACR_NAME" ]] && {
    echo "ERROR: Set env vars: RESOURCE_GROUP, AKS_CLUSTER_NAME, ACR_NAME"; exit 1; }
  az account show &>/dev/null || { log_fail "Azure CLI not authenticated"; exit 1; }
  log_pass "Authenticated (sub: $(az account show --query id -o tsv))"
}

# CHECK 1: AKS Private Cluster
# WHY: Public API server = scanned within minutes. Private cluster = VNet-only.
# MITRE T1046 Network Service Discovery | T1609 Container Administration
check_aks_private_cluster() {
  log_section "AKS CLUSTER SECURITY"
  log_check "AKS private cluster enabled"
  PRIVATE=$(az aks show -g "$RESOURCE_GROUP" -n "$AKS_CLUSTER_NAME" \
    --query "apiServerAccessProfile.enablePrivateCluster" -o tsv 2>/dev/null || echo "false")
  [[ "$PRIVATE" == "true" ]] \
    && log_pass "Private cluster enabled -- API server not internet-accessible" \
    || log_fail "Private cluster DISABLED -- API server publicly accessible. MITRE T1046."
}

# CHECK 2: AKS RBAC
# WHY: Without RBAC any authenticated user = cluster-admin. MITRE T1078.
check_aks_rbac() {
  log_check "AKS RBAC enabled"
  RBAC=$(az aks show -g "$RESOURCE_GROUP" -n "$AKS_CLUSTER_NAME" \
    --query "enableRbac" -o tsv 2>/dev/null || echo "false")
  [[ "$RBAC" == "true" ]] \
    && log_pass "RBAC enabled -- least-privilege cluster access enforced" \
    || log_fail "RBAC DISABLED -- any authenticated user has cluster-admin. MITRE T1078."
}

# CHECK 3: No Public Node IPs
# WHY: Public node IPs = OS directly reachable from internet. MITRE T1190.
check_aks_node_public_ips() {
  log_check "AKS nodes have no public IP addresses"
  NODE_RG=$(az aks show -g "$RESOURCE_GROUP" -n "$AKS_CLUSTER_NAME" \
    --query "nodeResourceGroup" -o tsv 2>/dev/null)
  [[ -z "$NODE_RG" ]] && { log_warn "Cannot determine node RG -- skipping"; return; }
  COUNT=$(az network nic list --resource-group "$NODE_RG" \
    --query "length([?ipConfigurations[?publicIpAddress != null]])" \
    -o tsv 2>/dev/null || echo "0")
  [[ "$COUNT" -eq 0 ]] \
    && log_pass "No public IPs on AKS nodes -- all traffic VNet-internal" \
    || log_fail "$COUNT node(s) with public IPs. MITRE T1190."
}

# CHECK 4: NSG Management Port Exposure
# WHY: Open SSH/RDP to internet = automated attacks within minutes.
# All admin access must use Azure Bastion (requires AAD session).
# MITRE T1021.004 SSH | T1021.001 RDP | T1133 External Remote Services
check_nsg_management_ports() {
  log_section "NETWORK SECURITY GROUPS"
  log_check "No internet-accessible SSH/RDP in NSGs"
  DANGEROUS=$(az network nsg list -g "$RESOURCE_GROUP" \
    --query "[].securityRules[?access=='Allow'&&direction=='Inbound'&&(sourceAddressPrefix=='*'||sourceAddressPrefix=='0.0.0.0/0'||sourceAddressPrefix=='Internet')&&(destinationPortRange=='22'||destinationPortRange=='3389'||destinationPortRange=='*')].name" \
    -o tsv 2>/dev/null || echo "")
  [[ -z "$DANGEROUS" ]] \
    && log_pass "No NSG rules expose management ports to internet" \
    || log_fail "Dangerous NSG rules: $DANGEROUS. MITRE T1021."
}

# CHECK 5: ACR Admin Disabled
# WHY: Shared static password = supply chain risk if leaked. MITRE T1525.
check_acr_admin() {
  log_section "CONTAINER REGISTRY"
  log_check "ACR admin account disabled"
  ADMIN=$(az acr show --name "$ACR_NAME" -g "$RESOURCE_GROUP" \
    --query "adminUserEnabled" -o tsv 2>/dev/null || echo "true")
  [[ "$ADMIN" == "false" ]] \
    && log_pass "ACR admin disabled -- Managed Identity auth only" \
    || log_fail "ACR admin ENABLED -- static credentials = supply chain risk. MITRE T1525."
}

# CHECK 6: AKS Pulls from Trusted ACR
# WHY: Docker Hub pulls bypass Trivy scanning. ACR+MSI = all images scanned.
# MITRE T1525 Implant Internal Image | T1610 Deploy Container
check_aks_acr_pull() {
  log_section "SUPPLY CHAIN VALIDATION"
  log_check "AKS has AcrPull role on trusted internal registry"
  ACR_ID=$(az acr show --name "$ACR_NAME" -g "$RESOURCE_GROUP" \
    --query "id" -o tsv 2>/dev/null || echo "")
  [[ -z "$ACR_ID" ]] && { log_warn "Cannot get ACR ID -- skipping"; return; }
  ROLE_COUNT=$(az role assignment list --scope "$ACR_ID" \
    --query "length([?roleDefinitionName=='AcrPull'])" \
    -o tsv 2>/dev/null || echo "0")
  [[ "$ROLE_COUNT" -gt 0 ]] \
    && log_pass "AcrPull role exists -- MSI-authenticated pulls from trusted registry" \
    || log_warn "No AcrPull assignment. Verify Managed Identity image pulls."
}

# CHECK 7: AKS Diagnostic Logs
# WHY: No logs = no audit trail for exec events, RBAC changes, API calls.
# Required for Sentinel threat detection. MITRE T1562.008.
check_aks_diagnostics() {
  log_section "LOGGING AND OBSERVABILITY"
  log_check "AKS diagnostic logs enabled to Log Analytics"
  AKS_ID=$(az aks show -g "$RESOURCE_GROUP" -n "$AKS_CLUSTER_NAME" \
    --query "id" -o tsv 2>/dev/null || echo "")
  [[ -z "$AKS_ID" ]] && { log_warn "Cannot get AKS ID -- skipping"; return; }
  DIAG=$(az monitor diagnostic-settings list --resource "$AKS_ID" \
    --query "length(value)" -o tsv 2>/dev/null || echo "0")
  [[ "$DIAG" -gt 0 ]] \
    && log_pass "AKS has $DIAG diagnostic setting(s) -- audit logs captured" \
    || log_fail "AKS has NO diagnostic settings -- logs not captured. MITRE T1562.008."
}

print_summary() {
  echo ""
  echo "============================================================"
  echo "VALIDATION SUMMARY"
  echo "============================================================"
  echo -e "${GREEN}PASSED:${NC}   $CHECKS_PASSED"
  echo -e "${YELLOW}WARNINGS:${NC} $WARNINGS"
  echo -e "${RED}CRITICAL:${NC} $FAILURES"
  echo "============================================================"
  if [[ "$FAILURES" -gt 0 ]]; then
    echo -e "${RED}PIPELINE BLOCKED: $FAILURES critical finding(s).${NC}"
    echo "Fix before proceeding:"
    echo "  private_cluster_enabled = true   (terraform/modules/aks/main.tf)"
    echo "  enable_rbac             = true   (terraform/modules/aks/main.tf)"
    echo "  Remove 0.0.0.0/0 NSG rules, restrict to Bastion source only"
    echo "  admin_enabled           = false  (terraform/modules/acr/main.tf)"
    echo "  Add azurerm_monitor_diagnostic_setting for AKS"
    exit 1
  fi
  echo -e "${GREEN}ALL CRITICAL CHECKS PASSED. Infrastructure validated.${NC}"
  [[ "$WARNINGS" -gt 0 ]] && echo -e "${YELLOW}Review $WARNINGS warning(s) above.${NC}"
  exit 0
}

main() {
  echo "============================================================"
  echo "Secure Cloud Platform -- Post-Deployment Validation"
  echo "RG: $RESOURCE_GROUP | AKS: $AKS_CLUSTER_NAME | ACR: $ACR_NAME"
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "============================================================"
  check_prerequisites
  check_aks_private_cluster
  check_aks_rbac
  check_aks_node_public_ips
  check_nsg_management_ports
  check_acr_admin
  check_aks_acr_pull
  check_aks_diagnostics
  print_summary
}

main "$@"
