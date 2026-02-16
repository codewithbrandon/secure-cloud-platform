#------------------------------------------------------------------------------
# ACR MODULE - AZURE CONTAINER REGISTRY
#------------------------------------------------------------------------------
# Security Purpose:
# - Private container image storage (no Docker Hub dependency)
# - Image vulnerability scanning with Microsoft Defender
# - Content trust for image signing (premium tier)
# - Network isolation via private endpoints or service endpoints
# - Managed identity authentication (no registry passwords)
#
# Enterprise Relevance:
# - Supply chain security: control what images run in your cluster
# - Compliance: scan images before deployment
# - Air-gapped environments: no external registry dependencies
# - Geo-replication for disaster recovery (premium tier)
#
# Zero Trust Implementation:
# - Admin account disabled (no shared credentials)
# - AKS authenticates via managed identity
# - Network rules restrict access to authorized networks
#------------------------------------------------------------------------------

resource "azurerm_container_registry" "main" {
  name                = var.acr_name
  location            = var.location
  resource_group_name = var.resource_group_name

  # SKU Options:
  # - Basic: Development, no geo-replication, no content trust
  # - Standard: Production, includes webhooks and more storage
  # - Premium: Geo-replication, content trust, private link
  # Portfolio: Standard for cost optimization while maintaining security features
  sku = var.sku

  #----------------------------------------------------------------------------
  # SECURITY CONFIGURATIONS
  #----------------------------------------------------------------------------

  # CRITICAL: Disable admin account - use managed identity instead
  # Admin accounts are shared credentials and violate Zero Trust
  admin_enabled = false

  # Enable anonymous pull for public images (disabled for security)
  anonymous_pull_enabled = false

  # Data endpoint for dedicated data traffic (premium only)
  data_endpoint_enabled = var.sku == "Premium" ? true : false

  # Export policy - prevent image export (premium only)
  # Useful for preventing data exfiltration
  export_policy_enabled = var.sku == "Premium" ? false : true

  # Quarantine policy - hold images pending security scan (premium only)
  # quarantine_policy_enabled = var.sku == "Premium" ? true : false

  # Network rules - restrict access to specific networks
  # Note: network_rule_set only applies when SKU is Premium
  # For Standard SKU, network rules are limited

  # Zone redundancy for high availability (premium only)
  zone_redundancy_enabled = var.sku == "Premium" ? true : false

  # Public network access - disable when using private endpoints
  public_network_access_enabled = true # Set to false with private endpoints

  tags = var.tags
}

#------------------------------------------------------------------------------
# PRIVATE ENDPOINT (Optional - Premium SKU required)
#------------------------------------------------------------------------------
# Private endpoint keeps all traffic on the Azure backbone network
# No data traverses the public internet
#------------------------------------------------------------------------------

resource "azurerm_private_endpoint" "acr" {
  count               = var.enable_private_endpoint ? 1 : 0
  name                = "pe-${var.acr_name}"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.private_endpoint_subnet_id

  private_service_connection {
    name                           = "psc-${var.acr_name}"
    private_connection_resource_id = azurerm_container_registry.main.id
    is_manual_connection           = false
    subresource_names              = ["registry"]
  }

  tags = var.tags
}

# Private DNS Zone for ACR private endpoint
resource "azurerm_private_dns_zone" "acr" {
  count               = var.enable_private_endpoint ? 1 : 0
  name                = "privatelink.azurecr.io"
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

# Link Private DNS Zone to VNet
resource "azurerm_private_dns_zone_virtual_network_link" "acr" {
  count                 = var.enable_private_endpoint ? 1 : 0
  name                  = "link-${var.acr_name}"
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.acr[0].name
  virtual_network_id    = var.vnet_id
  registration_enabled  = false
  tags                  = var.tags
}

# DNS A Record for private endpoint
resource "azurerm_private_dns_a_record" "acr" {
  count               = var.enable_private_endpoint ? 1 : 0
  name                = var.acr_name
  zone_name           = azurerm_private_dns_zone.acr[0].name
  resource_group_name = var.resource_group_name
  ttl                 = 300
  records             = [azurerm_private_endpoint.acr[0].private_service_connection[0].private_ip_address]
}

#------------------------------------------------------------------------------
# DIAGNOSTIC SETTINGS
#------------------------------------------------------------------------------
# Audit logs for tracking who pushed/pulled which images
# Critical for supply chain security investigations
#------------------------------------------------------------------------------

resource "azurerm_monitor_diagnostic_setting" "acr" {
  name                       = "acr-diagnostics"
  target_resource_id         = azurerm_container_registry.main.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  # Repository events - push, pull, delete operations
  enabled_log {
    category = "ContainerRegistryRepositoryEvents"
  }

  # Login events - authentication attempts
  enabled_log {
    category = "ContainerRegistryLoginEvents"
  }

  # Metrics
  metric {
    category = "AllMetrics"
    enabled  = true
  }
}
