#------------------------------------------------------------------------------
# SQL MODULE - AZURE SQL DATABASE
#------------------------------------------------------------------------------
# Security Purpose:
# - Managed database service with built-in security features
# - Transparent Data Encryption (TDE) for data at rest
# - Private endpoint for network isolation
# - Azure AD authentication for identity-based access
# - Auditing and threat detection for compliance
# - Automatic patching (no OS-level management)
#
# Enterprise Relevance:
# - PCI-DSS, HIPAA, SOC2 compliance requirements
# - Automatic backups with point-in-time restore
# - Built-in HA (99.99% SLA in production tiers)
# - Advanced Threat Protection detects SQL injection, anomalies
#
# Zero Trust Implementation:
# - Azure AD authentication preferred over SQL authentication
# - Private endpoint eliminates public internet exposure
# - Firewall rules restrict to known IP ranges only
# - All access logged for audit trail
#------------------------------------------------------------------------------

resource "azurerm_mssql_server" "main" {
  name                = var.server_name
  location            = var.location
  resource_group_name = var.resource_group_name
  version             = "12.0" # SQL Server 2019 compatibility

  #----------------------------------------------------------------------------
  # AUTHENTICATION
  #----------------------------------------------------------------------------
  # SQL authentication - used as fallback; prefer Azure AD
  administrator_login          = var.admin_username
  administrator_login_password = var.admin_password

  # Azure AD authentication - recommended for Zero Trust
  # Enables managed identity authentication from applications
  azuread_administrator {
    login_username              = var.aad_admin_username
    object_id                   = var.aad_admin_object_id
    azuread_authentication_only = false # Set to true to disable SQL auth entirely
  }

  #----------------------------------------------------------------------------
  # SECURITY CONFIGURATIONS
  #----------------------------------------------------------------------------

  # Minimum TLS version - enforce TLS 1.2 or higher
  minimum_tls_version = "1.2"

  # Public network access - disable when using private endpoints
  # For portfolio with service endpoints, we keep this enabled
  public_network_access_enabled = !var.enable_private_endpoint

  # Outbound network restriction - prevent data exfiltration
  outbound_network_restriction_enabled = false # Enable in production

  tags = var.tags
}

#------------------------------------------------------------------------------
# SQL DATABASE
#------------------------------------------------------------------------------

resource "azurerm_mssql_database" "main" {
  name      = var.database_name
  server_id = azurerm_mssql_server.main.id

  #----------------------------------------------------------------------------
  # PERFORMANCE TIER
  #----------------------------------------------------------------------------
  # Portfolio: Basic/S0 for cost optimization
  # Production: Premium or Business Critical for HA
  sku_name = var.sku_name

  # Collation for proper string comparison
  collation = "SQL_Latin1_General_CP1_CI_AS"

  # Max size in GB
  max_size_gb = var.max_size_gb

  #----------------------------------------------------------------------------
  # SECURITY CONFIGURATIONS
  #----------------------------------------------------------------------------

  # Zone redundancy for HA (Premium/Business Critical only)
  zone_redundant = var.zone_redundant

  # Geo-backup storage redundancy
  # Options: Local, Zone, Geo, GeoZone
  storage_account_type = var.backup_storage_redundancy

  # Transparent Data Encryption (enabled by default, cannot be disabled)
  # Encrypts data at rest using service-managed key or customer-managed key

  tags = var.tags
}

#------------------------------------------------------------------------------
# FIREWALL RULES
#------------------------------------------------------------------------------
# Restrict database access to specific networks
# Default: deny all, explicitly allow required sources
#------------------------------------------------------------------------------

# Allow Azure services (required for some Azure integrations)
# SECURITY NOTE: This allows ANY Azure service, not just yours
# Consider using private endpoints instead for strict isolation
resource "azurerm_mssql_firewall_rule" "allow_azure_services" {
  count            = var.allow_azure_services ? 1 : 0
  name             = "AllowAzureServices"
  server_id        = azurerm_mssql_server.main.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

# Allow admin IP addresses for direct access
# Strip CIDR notation if present (e.g., "10.0.0.1/32" -> "10.0.0.1")
resource "azurerm_mssql_firewall_rule" "allow_admin_ips" {
  for_each         = { for idx, ip in var.allowed_ip_addresses : idx => ip }
  name             = "AllowAdminIP-${each.key}"
  server_id        = azurerm_mssql_server.main.id
  start_ip_address = split("/", each.value)[0]
  end_ip_address   = split("/", each.value)[0]
}

#------------------------------------------------------------------------------
# VIRTUAL NETWORK RULES (Service Endpoints)
#------------------------------------------------------------------------------
# Allow access from specific subnets via service endpoints
# More secure than IP-based rules
#------------------------------------------------------------------------------

resource "azurerm_mssql_virtual_network_rule" "main" {
  for_each  = { for idx, subnet in var.allowed_subnet_ids : idx => subnet }
  name      = "AllowSubnet-${each.key}"
  server_id = azurerm_mssql_server.main.id
  subnet_id = each.value
}

#------------------------------------------------------------------------------
# PRIVATE ENDPOINT
#------------------------------------------------------------------------------
# Private endpoint provides dedicated private IP for SQL Server
# All traffic stays on Azure backbone - no public internet
#------------------------------------------------------------------------------

resource "azurerm_private_endpoint" "sql" {
  count               = var.enable_private_endpoint ? 1 : 0
  name                = "pe-${var.server_name}"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.private_endpoint_subnet_id

  private_service_connection {
    name                           = "psc-${var.server_name}"
    private_connection_resource_id = azurerm_mssql_server.main.id
    is_manual_connection           = false
    subresource_names              = ["sqlServer"]
  }

  tags = var.tags
}

# Private DNS Zone for SQL private endpoint
resource "azurerm_private_dns_zone" "sql" {
  count               = var.enable_private_endpoint ? 1 : 0
  name                = "privatelink.database.windows.net"
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

# Link Private DNS Zone to VNet
resource "azurerm_private_dns_zone_virtual_network_link" "sql" {
  count                 = var.enable_private_endpoint ? 1 : 0
  name                  = "link-${var.server_name}"
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.sql[0].name
  virtual_network_id    = var.vnet_id
  registration_enabled  = false
  tags                  = var.tags
}

# DNS A Record for private endpoint
resource "azurerm_private_dns_a_record" "sql" {
  count               = var.enable_private_endpoint ? 1 : 0
  name                = var.server_name
  zone_name           = azurerm_private_dns_zone.sql[0].name
  resource_group_name = var.resource_group_name
  ttl                 = 300
  records             = [azurerm_private_endpoint.sql[0].private_service_connection[0].private_ip_address]
}

#------------------------------------------------------------------------------
# AUDITING
#------------------------------------------------------------------------------
# SQL auditing records database events for security and compliance
# Required for PCI-DSS, HIPAA, and SOC2
#------------------------------------------------------------------------------

# Log Analytics-based auditing (always enabled when Log Analytics is available)
resource "azurerm_mssql_server_extended_auditing_policy" "main" {
  server_id              = azurerm_mssql_server.main.id
  log_monitoring_enabled = true
  retention_in_days      = var.audit_retention_days

  # Storage-based auditing only when storage account is provided
  # For portfolio, we use Log Analytics only (cost optimization)
}

#------------------------------------------------------------------------------
# THREAT DETECTION
#------------------------------------------------------------------------------
# Advanced Threat Protection detects:
# - SQL injection attempts
# - Anomalous database access patterns
# - Brute force attacks
# - Data exfiltration attempts
#------------------------------------------------------------------------------

resource "azurerm_mssql_server_security_alert_policy" "main" {
  resource_group_name = var.resource_group_name
  server_name         = azurerm_mssql_server.main.name
  state               = "Enabled"

  # Alert on all threat types
  disabled_alerts = []

  # Send alerts to security team
  email_addresses      = var.security_alert_emails
  email_account_admins = true
  retention_days       = var.audit_retention_days
}

#------------------------------------------------------------------------------
# DIAGNOSTIC SETTINGS
#------------------------------------------------------------------------------

resource "azurerm_monitor_diagnostic_setting" "sql_server" {
  name                       = "sql-server-diagnostics"
  target_resource_id         = azurerm_mssql_server.main.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}

resource "azurerm_monitor_diagnostic_setting" "sql_database" {
  name                       = "sql-database-diagnostics"
  target_resource_id         = azurerm_mssql_database.main.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log {
    category = "SQLSecurityAuditEvents"
  }

  enabled_log {
    category = "SQLInsights"
  }

  enabled_log {
    category = "Errors"
  }

  metric {
    category = "Basic"
    enabled  = true
  }
}
