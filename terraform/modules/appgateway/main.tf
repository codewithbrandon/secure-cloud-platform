#------------------------------------------------------------------------------
# APPLICATION GATEWAY MODULE - WAF-ENABLED INGRESS
#------------------------------------------------------------------------------
# Security Purpose:
# - Web Application Firewall (WAF) for OWASP protection
# - TLS termination with centralized certificate management
# - DDoS protection (basic) at Layer 7
# - URL-based routing and path-based rules
# - Health probes ensure only healthy backends receive traffic
#
# Enterprise Relevance:
# - Required for PCI-DSS (WAF protection for cardholder data)
# - Centralized SSL/TLS management
# - Integration with Azure Front Door for global distribution
# - Detailed access logs for compliance and security analytics
#
# Portfolio Note:
# - Using Standard_v2 (no WAF) for cost optimization
# - Production should use WAF_v2 with OWASP 3.2 ruleset
#------------------------------------------------------------------------------

# Public IP for Application Gateway
resource "azurerm_public_ip" "appgw" {
  name                = "pip-${var.appgw_name}"
  location            = var.location
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard" # Required for Application Gateway v2

  # Domain name label for FQDN
  domain_name_label = var.domain_name_label

  tags = var.tags
}

resource "azurerm_application_gateway" "main" {
  name                = var.appgw_name
  location            = var.location
  resource_group_name = var.resource_group_name

  #----------------------------------------------------------------------------
  # SKU CONFIGURATION
  #----------------------------------------------------------------------------
  # Standard_v2: Basic L7 load balancing
  # WAF_v2: Includes Web Application Firewall (recommended for production)
  #----------------------------------------------------------------------------

  sku {
    name = var.sku_name
    tier = var.sku_tier
  }

  # Autoscaling: Automatically scale capacity based on load
  autoscale_configuration {
    min_capacity = var.min_capacity
    max_capacity = var.max_capacity
  }

  #----------------------------------------------------------------------------
  # NETWORK CONFIGURATION
  #----------------------------------------------------------------------------

  gateway_ip_configuration {
    name      = "gateway-ip-config"
    subnet_id = var.subnet_id
  }

  #----------------------------------------------------------------------------
  # FRONTEND CONFIGURATION
  #----------------------------------------------------------------------------
  # Public frontend for internet-facing traffic
  #----------------------------------------------------------------------------

  frontend_ip_configuration {
    name                 = "frontend-ip-public"
    public_ip_address_id = azurerm_public_ip.appgw.id
  }

  # HTTP port (for redirect to HTTPS)
  frontend_port {
    name = "frontend-port-http"
    port = 80
  }

  # HTTPS port
  frontend_port {
    name = "frontend-port-https"
    port = 443
  }

  #----------------------------------------------------------------------------
  # BACKEND POOL
  #----------------------------------------------------------------------------
  # Points to AKS ingress controller internal IP
  #----------------------------------------------------------------------------

  backend_address_pool {
    name         = "backend-pool-aks"
    ip_addresses = var.backend_ip_addresses
  }

  #----------------------------------------------------------------------------
  # BACKEND HTTP SETTINGS
  #----------------------------------------------------------------------------
  # Configure how Application Gateway communicates with backends
  #----------------------------------------------------------------------------

  backend_http_settings {
    name                  = "backend-http-settings"
    cookie_based_affinity = "Disabled" # Stateless applications
    port                  = 80
    protocol              = "Http" # HTTP to backend (TLS terminated at AppGW)
    request_timeout       = 30

    # Health probe association
    probe_name = "health-probe"

    # Pick host from backend - useful for multi-tenant backends
    pick_host_name_from_backend_address = false
    host_name                           = var.backend_host_name
  }

  #----------------------------------------------------------------------------
  # HEALTH PROBE
  #----------------------------------------------------------------------------
  # Ensures traffic only goes to healthy backends
  #----------------------------------------------------------------------------

  probe {
    name                = "health-probe"
    protocol            = "Http"
    path                = var.health_probe_path
    host                = var.backend_host_name
    interval            = 30
    timeout             = 30
    unhealthy_threshold = 3

    match {
      status_code = ["200-399"]
    }
  }

  #----------------------------------------------------------------------------
  # HTTP LISTENER
  #----------------------------------------------------------------------------
  # Listens for incoming requests on specified ports
  #----------------------------------------------------------------------------

  # HTTP Listener (for redirect to HTTPS)
  http_listener {
    name                           = "listener-http"
    frontend_ip_configuration_name = "frontend-ip-public"
    frontend_port_name             = "frontend-port-http"
    protocol                       = "Http"
  }

  # HTTPS Listener (production - requires SSL certificate)
  # Uncomment when SSL certificate is available
  # http_listener {
  #   name                           = "listener-https"
  #   frontend_ip_configuration_name = "frontend-ip-public"
  #   frontend_port_name             = "frontend-port-https"
  #   protocol                       = "Https"
  #   ssl_certificate_name           = "ssl-cert"
  # }

  #----------------------------------------------------------------------------
  # ROUTING RULES
  #----------------------------------------------------------------------------
  # Determine how requests are routed to backends
  #----------------------------------------------------------------------------

  # HTTP to backend (temporary for portfolio without SSL)
  request_routing_rule {
    name                       = "routing-rule-http"
    priority                   = 100
    rule_type                  = "Basic"
    http_listener_name         = "listener-http"
    backend_address_pool_name  = "backend-pool-aks"
    backend_http_settings_name = "backend-http-settings"
  }

  # HTTP to HTTPS redirect (production)
  # request_routing_rule {
  #   name                       = "routing-rule-http-redirect"
  #   priority                   = 100
  #   rule_type                  = "Basic"
  #   http_listener_name         = "listener-http"
  #   redirect_configuration_name = "redirect-http-to-https"
  # }

  # redirect_configuration {
  #   name                 = "redirect-http-to-https"
  #   redirect_type        = "Permanent"
  #   target_listener_name = "listener-https"
  #   include_path         = true
  #   include_query_string = true
  # }

  #----------------------------------------------------------------------------
  # WAF CONFIGURATION (WAF_v2 SKU only)
  #----------------------------------------------------------------------------
  # Uncomment when using WAF_v2 SKU
  #----------------------------------------------------------------------------

  # waf_configuration {
  #   enabled                  = true
  #   firewall_mode            = "Prevention"  # Block malicious requests
  #   rule_set_type            = "OWASP"
  #   rule_set_version         = "3.2"
  #   file_upload_limit_mb     = 100
  #   request_body_check       = true
  #   max_request_body_size_kb = 128
  #
  #   # Disable specific rules if causing false positives
  #   disabled_rule_group {
  #     rule_group_name = "REQUEST-920-PROTOCOL-ENFORCEMENT"
  #     rules           = [920350]  # Example: disable specific rule
  #   }
  # }

  #----------------------------------------------------------------------------
  # SSL POLICY (when using HTTPS)
  #----------------------------------------------------------------------------

  ssl_policy {
    policy_type = "Predefined"
    policy_name = "AppGwSslPolicy20220101S" # TLS 1.2+ with strong ciphers
  }

  tags = var.tags
}

#------------------------------------------------------------------------------
# DIAGNOSTIC SETTINGS
#------------------------------------------------------------------------------
# Capture access logs and performance metrics
# Critical for security monitoring and troubleshooting
#------------------------------------------------------------------------------

resource "azurerm_monitor_diagnostic_setting" "appgw" {
  name                       = "appgw-diagnostics"
  target_resource_id         = azurerm_application_gateway.main.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  # Access logs - who accessed what
  enabled_log {
    category = "ApplicationGatewayAccessLog"
  }

  # Performance logs
  enabled_log {
    category = "ApplicationGatewayPerformanceLog"
  }

  # Firewall logs (WAF only)
  enabled_log {
    category = "ApplicationGatewayFirewallLog"
  }

  # Metrics
  metric {
    category = "AllMetrics"
    enabled  = true
  }
}
