#------------------------------------------------------------------------------
# AKS MODULE - AZURE KUBERNETES SERVICE
#------------------------------------------------------------------------------
# Security Purpose:
# - Managed Kubernetes control plane (Microsoft patches, maintains)
# - Azure AD integration for RBAC authentication
# - Network policy enforcement for pod-to-pod traffic control
# - Managed identity eliminates need for service principal secrets
# - Integration with Azure security services (Defender, Policy)
#
# Enterprise Relevance:
# - Industry standard for container orchestration
# - Built-in HA with SLA (99.95% for paid tier)
# - Compliance certifications (SOC, ISO, PCI, HIPAA)
# - Integration with enterprise identity (Azure AD)
#
# Zero Trust Implementation:
# - Azure RBAC for cluster access control
# - Network policies for micro-segmentation
# - Pod identity for workload authentication
# - Private API server (production) or authorized IPs (portfolio)
#------------------------------------------------------------------------------

resource "azurerm_kubernetes_cluster" "main" {
  name                = var.cluster_name
  location            = var.location
  resource_group_name = var.resource_group_name
  dns_prefix          = var.dns_prefix

  # Kubernetes version - use supported version for security patches
  kubernetes_version = var.kubernetes_version

  #----------------------------------------------------------------------------
  # CONTROL PLANE SECURITY
  #----------------------------------------------------------------------------

  # SKU Tier: Free (no SLA) or Standard (99.95% SLA)
  # Portfolio: Free tier to minimize cost
  sku_tier = var.sku_tier

  # API Server Access: Restrict who can access the Kubernetes API
  # Portfolio: Public with authorized IP ranges
  # Production: Private cluster with private endpoint
  api_server_access_profile {
    authorized_ip_ranges = var.authorized_ip_ranges
  }

  # For private cluster (production), uncomment:
  # private_cluster_enabled = true
  # private_dns_zone_id     = "System"  # or custom private DNS zone

  #----------------------------------------------------------------------------
  # DEFAULT NODE POOL
  #----------------------------------------------------------------------------
  # The system node pool runs critical cluster components
  #----------------------------------------------------------------------------

  default_node_pool {
    name            = "system"
    node_count      = var.enable_auto_scaling ? null : var.node_count
    vm_size         = var.node_vm_size
    vnet_subnet_id  = var.subnet_id
    os_disk_size_gb = 128
    os_disk_type    = "Managed" # Ephemeral for better performance in production
    max_pods        = 110       # Azure CNI default

    # Autoscaling configuration
    auto_scaling_enabled = var.enable_auto_scaling
    min_count           = var.enable_auto_scaling ? var.min_node_count : null
    max_count           = var.enable_auto_scaling ? var.max_node_count : null

    # Availability zones for HA (production)
    # zones = ["1", "2", "3"]

    # Node labels for workload scheduling
    node_labels = {
      "nodepool" = "system"
    }

    # Temporary disk for emptyDir (faster than managed disk)
    temporary_name_for_rotation = "systemtemp"

    # Upgrade settings
    upgrade_settings {
      max_surge = "33%" # Roll 33% of nodes at a time during upgrades
    }
  }

  #----------------------------------------------------------------------------
  # IDENTITY
  #----------------------------------------------------------------------------
  # Use SystemAssigned managed identity instead of service principal
  # Eliminates need to manage credentials
  #----------------------------------------------------------------------------

  identity {
    type = "SystemAssigned"
  }

  #----------------------------------------------------------------------------
  # NETWORK CONFIGURATION
  #----------------------------------------------------------------------------
  # Azure CNI provides better network policy support and Azure integration
  #----------------------------------------------------------------------------

  network_profile {
    network_plugin    = "azure"        # Azure CNI for advanced networking
    network_policy    = "calico"       # Calico for Kubernetes Network Policies
    load_balancer_sku = "standard"     # Required for availability zones
    outbound_type     = "loadBalancer" # Default egress via LB
    service_cidr      = var.service_cidr
    dns_service_ip    = var.dns_service_ip

    # Load balancer configuration
    load_balancer_profile {
      managed_outbound_ip_count = 1 # Single outbound IP for cost optimization
    }
  }

  #----------------------------------------------------------------------------
  # AZURE AD INTEGRATION (RBAC)
  #----------------------------------------------------------------------------
  # Enables Azure AD authentication for kubectl access
  # Maps Azure AD groups to Kubernetes RBAC roles
  #----------------------------------------------------------------------------

  azure_active_directory_role_based_access_control {
    azure_rbac_enabled     = true # Use Azure RBAC for authorization
    admin_group_object_ids = var.admin_group_ids
  }

  # Local accounts: Disable for production (Azure AD only)
  # Enabling allows kubectl with certificate-based auth
  local_account_disabled = var.disable_local_accounts

  #----------------------------------------------------------------------------
  # SECURITY FEATURES
  #----------------------------------------------------------------------------

  # Azure Policy add-on: Enforce policies via Gatekeeper
  azure_policy_enabled = true

  # HTTP application routing: Disabled (insecure, use proper ingress)
  http_application_routing_enabled = false

  # Workload Identity: Enables pod-level Azure AD authentication
  workload_identity_enabled = true
  oidc_issuer_enabled       = true

  # Image cleaner: Automatically remove unused images
  image_cleaner_enabled        = true
  image_cleaner_interval_hours = 48

  #----------------------------------------------------------------------------
  # MONITORING
  #----------------------------------------------------------------------------

  oms_agent {
    log_analytics_workspace_id      = var.log_analytics_workspace_id
    msi_auth_for_monitoring_enabled = true # Use managed identity for monitoring
  }

  # Microsoft Defender for Containers
  microsoft_defender {
    log_analytics_workspace_id = var.log_analytics_workspace_id
  }

  #----------------------------------------------------------------------------
  # MAINTENANCE WINDOW
  #----------------------------------------------------------------------------
  # Control when automatic upgrades happen
  #----------------------------------------------------------------------------

  maintenance_window {
    allowed {
      day   = "Sunday"
      hours = [0, 1, 2, 3] # 12 AM - 4 AM
    }
  }

  #----------------------------------------------------------------------------
  # AUTO-UPGRADE
  #----------------------------------------------------------------------------
  # Automatically upgrade cluster to maintain security patches
  # Options: none, patch, stable, rapid, node-image
  #----------------------------------------------------------------------------

  automatic_upgrade_channel = "patch" # Auto-upgrade patch versions

  tags = var.tags

  lifecycle {
    ignore_changes = [
      # Ignore changes that happen outside Terraform
      default_node_pool[0].node_count,
      kubernetes_version, # Allow manual version control
    ]
  }
}

#------------------------------------------------------------------------------
# ROLE ASSIGNMENTS
#------------------------------------------------------------------------------
# Grant AKS identity required permissions for Azure resource access
#------------------------------------------------------------------------------

# Grant AKS identity Network Contributor on subnet for CNI
resource "azurerm_role_assignment" "aks_network_contributor" {
  scope                = var.subnet_id
  role_definition_name = "Network Contributor"
  principal_id         = azurerm_kubernetes_cluster.main.identity[0].principal_id
}

# Grant AKS identity AcrPull on container registry
# Note: ACR is always deployed in this architecture, so no count condition needed
resource "azurerm_role_assignment" "aks_acr_pull" {
  scope                = var.acr_id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_kubernetes_cluster.main.kubelet_identity[0].object_id
}

#------------------------------------------------------------------------------
# DIAGNOSTIC SETTINGS
#------------------------------------------------------------------------------
# Send AKS logs to Log Analytics for security monitoring
# Critical for detecting unauthorized access, misconfigurations
#------------------------------------------------------------------------------

resource "azurerm_monitor_diagnostic_setting" "aks" {
  name                       = "aks-diagnostics"
  target_resource_id         = azurerm_kubernetes_cluster.main.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  # Kubernetes API server audit logs - CRITICAL for security
  enabled_log {
    category = "kube-apiserver"
  }

  # Kubernetes audit logs
  enabled_log {
    category = "kube-audit"
  }

  # Kubernetes audit admin logs (admin operations only)
  enabled_log {
    category = "kube-audit-admin"
  }

  # Controller manager logs
  enabled_log {
    category = "kube-controller-manager"
  }

  # Scheduler logs
  enabled_log {
    category = "kube-scheduler"
  }

  # Cluster autoscaler logs
  enabled_log {
    category = "cluster-autoscaler"
  }

  # Guard logs (Azure AD authentication)
  enabled_log {
    category = "guard"
  }

  # Metrics
  metric {
    category = "AllMetrics"
    enabled  = true
  }
}
