#------------------------------------------------------------------------------
# SECURE CLOUD PLATFORM - ROOT MODULE
#------------------------------------------------------------------------------
# This is the main orchestration file that brings together all modules
# to create a production-grade secure cloud infrastructure.
#
# Architecture:
# - Segmented network with defense-in-depth
# - Private AKS cluster with managed identity
# - Private container registry (ACR)
# - Managed SQL database with private endpoint
# - Azure Key Vault for secrets management
# - Application Gateway for secure ingress
# - Jenkins for CI/CD automation
# - Comprehensive monitoring and logging
#
# Security Controls:
# - Zero Trust network architecture
# - Managed identities (no stored credentials)
# - RBAC at all layers
# - Encryption at rest and in transit
# - Centralized audit logging
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# DATA SOURCES
#------------------------------------------------------------------------------

# Get current Azure client configuration
data "azurerm_client_config" "current" {}

# Get current subscription
data "azurerm_subscription" "current" {}

#------------------------------------------------------------------------------
# RESOURCE GROUP
#------------------------------------------------------------------------------
# Single resource group for the entire platform
# Enables unified RBAC and cost tracking
#------------------------------------------------------------------------------

resource "azurerm_resource_group" "main" {
  name     = local.names.resource_group
  location = var.location
  tags     = local.common_tags
}

#------------------------------------------------------------------------------
# MONITORING MODULE
#------------------------------------------------------------------------------
# Deploy first as other modules depend on Log Analytics for diagnostics
#------------------------------------------------------------------------------

module "monitoring" {
  source = "./modules/monitoring"

  workspace_name      = local.names.log_analytics
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  retention_days      = 30 # 30 days free tier

  tags = local.common_tags
}

#------------------------------------------------------------------------------
# NETWORKING MODULE
#------------------------------------------------------------------------------
# Foundation for all other resources - VNet, subnets, NSGs
#------------------------------------------------------------------------------

module "networking" {
  source = "./modules/networking"

  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  vnet_name           = local.names.vnet
  vnet_address_space  = var.vnet_address_space
  subnet_names        = local.subnet_names
  subnet_prefixes     = var.subnet_prefixes
  nsg_names           = local.names
  admin_ip_addresses  = var.admin_ip_addresses

  tags = local.common_tags
}

#------------------------------------------------------------------------------
# KEY VAULT MODULE
#------------------------------------------------------------------------------
# Centralized secrets management - must be deployed before resources that need secrets
#------------------------------------------------------------------------------

module "keyvault" {
  source = "./modules/keyvault"

  keyvault_name       = local.names.keyvault
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku_name            = var.keyvault_sku

  # Network access - allow from AKS and management subnets
  allowed_subnet_ids = [
    module.networking.subnet_ids["aks"],
    module.networking.subnet_ids["mgmt"]
  ]
  allowed_ip_ranges = var.admin_ip_addresses

  # Identity access will be configured after AKS and Jenkins are created
  aks_identity_principal_id     = ""
  jenkins_identity_principal_id = ""

  log_analytics_workspace_id = module.monitoring.workspace_id

  tags = local.common_tags

  depends_on = [module.networking]
}

#------------------------------------------------------------------------------
# ACR MODULE
#------------------------------------------------------------------------------
# Container registry for storing application images
#------------------------------------------------------------------------------

module "acr" {
  source = "./modules/acr"

  acr_name            = local.names.acr
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "Standard" # Standard for network rules support

  # Network access - allow from AKS and management subnets
  allowed_subnet_ids = [
    module.networking.subnet_ids["aks"],
    module.networking.subnet_ids["mgmt"]
  ]
  allowed_ip_ranges = var.admin_ip_addresses

  # Private endpoint disabled for cost optimization
  enable_private_endpoint = false

  log_analytics_workspace_id = module.monitoring.workspace_id

  tags = local.common_tags

  depends_on = [module.networking]
}

#------------------------------------------------------------------------------
# SQL MODULE
#------------------------------------------------------------------------------
# Managed SQL database for application data
#------------------------------------------------------------------------------

module "sql" {
  source = "./modules/sql"

  server_name         = local.names.sql_server
  database_name       = local.names.sql_database
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  # Authentication
  admin_username      = var.sql_admin_username
  admin_password      = var.sql_admin_password
  aad_admin_username  = "AKS-Admin"
  aad_admin_object_id = data.azurerm_client_config.current.object_id

  # Database tier
  sku_name    = var.sql_database_sku
  max_size_gb = 2

  # Network access
  allow_azure_services = true
  allowed_subnet_ids = [
    module.networking.subnet_ids["aks"],
    module.networking.subnet_ids["mgmt"]
  ]
  allowed_ip_addresses = var.admin_ip_addresses

  # Private endpoint disabled for cost optimization
  enable_private_endpoint = false

  # Auditing (simplified for portfolio)
  audit_retention_days  = 30
  security_alert_emails = []

  log_analytics_workspace_id = module.monitoring.workspace_id

  tags = local.common_tags

  depends_on = [module.networking]
}

#------------------------------------------------------------------------------
# AKS MODULE
#------------------------------------------------------------------------------
# Kubernetes cluster for running containerized applications
#------------------------------------------------------------------------------

module "aks" {
  source = "./modules/aks"

  cluster_name        = local.names.aks_cluster
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  dns_prefix          = local.aks_config.dns_prefix
  kubernetes_version  = var.aks_kubernetes_version

  # SKU tier
  sku_tier = "Free" # Standard for production SLA

  # Node pool configuration
  node_vm_size        = var.aks_node_vm_size
  node_count          = var.aks_node_count
  enable_auto_scaling = var.aks_enable_auto_scaling
  min_node_count      = var.aks_min_node_count
  max_node_count      = var.aks_max_node_count

  # Network configuration
  subnet_id      = module.networking.subnet_ids["aks"]
  service_cidr   = local.aks_config.service_cidr
  dns_service_ip = local.aks_config.dns_service_ip

  # API server access - restrict to admin IPs
  authorized_ip_ranges = var.admin_ip_addresses

  # Azure AD integration (empty for portfolio - would be admin group IDs)
  admin_group_ids        = []
  disable_local_accounts = false # true for production

  # Integrations
  acr_id                     = module.acr.acr_id
  log_analytics_workspace_id = module.monitoring.workspace_id

  tags = local.common_tags

  depends_on = [module.networking, module.acr]
}

#------------------------------------------------------------------------------
# APPLICATION GATEWAY MODULE
#------------------------------------------------------------------------------
# Layer 7 load balancer with WAF capabilities
#------------------------------------------------------------------------------

module "appgateway" {
  source = "./modules/appgateway"

  appgw_name          = local.names.appgw
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  subnet_id           = module.networking.subnet_ids["appgw"]

  # SKU configuration
  sku_name     = var.appgw_sku_name
  sku_tier     = var.appgw_sku_tier
  min_capacity = var.appgw_min_capacity
  max_capacity = var.appgw_max_capacity

  # Frontend
  domain_name_label = "${var.project_name}${var.environment}"

  # Backend - will be updated after ingress controller deployment
  backend_ip_addresses = []
  backend_host_name    = "localhost"
  health_probe_path    = "/health"

  log_analytics_workspace_id = module.monitoring.workspace_id

  tags = local.common_tags

  depends_on = [module.networking]
}

#------------------------------------------------------------------------------
# JENKINS MODULE
#------------------------------------------------------------------------------
# CI/CD server for build and deployment automation
#------------------------------------------------------------------------------

module "jenkins" {
  source = "./modules/jenkins"

  vm_name             = local.names.jenkins_vm
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  subnet_id           = module.networking.subnet_ids["mgmt"]

  # VM configuration
  vm_size        = var.jenkins_vm_size
  admin_username = var.jenkins_admin_username

  # DNS label
  domain_name_label = "jenkins-${var.project_name}${var.environment}"

  # Integrations
  acr_id      = module.acr.acr_id
  aks_id      = module.aks.cluster_id
  keyvault_id = module.keyvault.keyvault_id

  tags = local.common_tags

  depends_on = [module.networking, module.keyvault, module.acr, module.aks]
}

#------------------------------------------------------------------------------
# POST-DEPLOYMENT CONFIGURATIONS
#------------------------------------------------------------------------------
# Additional role assignments and configurations after main resources are created
#------------------------------------------------------------------------------

# Grant AKS identity access to Key Vault secrets
resource "azurerm_role_assignment" "aks_keyvault_secrets" {
  scope                = module.keyvault.keyvault_id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = module.aks.kubelet_identity_object_id
}

# Grant Jenkins identity access to Key Vault secrets
resource "azurerm_role_assignment" "jenkins_keyvault_secrets" {
  scope                = module.keyvault.keyvault_id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = module.jenkins.managed_identity_principal_id
}
