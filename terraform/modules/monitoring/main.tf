#------------------------------------------------------------------------------
# MONITORING MODULE - LOG ANALYTICS WORKSPACE
#------------------------------------------------------------------------------
# Security Purpose:
# - Centralized log collection for all Azure resources
# - Enables threat detection, incident investigation, and compliance
# - Required for Microsoft Defender for Cloud integration
# - Supports SIEM integration for enterprise SOC workflows
#
# Enterprise Relevance:
# - SOC teams use Log Analytics for security monitoring
# - Compliance frameworks require centralized audit logging
# - Log retention policies support forensic investigations
# - Azure Monitor alerts enable automated incident response
#------------------------------------------------------------------------------

resource "azurerm_log_analytics_workspace" "main" {
  name                = var.workspace_name
  location            = var.location
  resource_group_name = var.resource_group_name

  # SKU: PerGB2018 is the current pricing model
  sku = "PerGB2018"

  # Retention period: 30 days free, extend for compliance requirements
  # PRODUCTION: Set to 90-365 days based on compliance needs (PCI-DSS, HIPAA, etc.)
  retention_in_days = var.retention_days

  # Enable internet ingestion for resources outside Azure
  internet_ingestion_enabled = true

  # Enable internet query for Azure Portal access
  internet_query_enabled = true

  tags = var.tags
}

#------------------------------------------------------------------------------
# LOG ANALYTICS SOLUTIONS
#------------------------------------------------------------------------------
# Solutions extend Log Analytics with specialized capabilities
#------------------------------------------------------------------------------

# Container Insights - Required for AKS monitoring
resource "azurerm_log_analytics_solution" "containers" {
  solution_name         = "ContainerInsights"
  location              = var.location
  resource_group_name   = var.resource_group_name
  workspace_resource_id = azurerm_log_analytics_workspace.main.id
  workspace_name        = azurerm_log_analytics_workspace.main.name

  plan {
    publisher = "Microsoft"
    product   = "OMSGallery/ContainerInsights"
  }
}

# Security Insights - Required for Microsoft Sentinel (optional)
# Uncomment if using Microsoft Sentinel for SIEM
# resource "azurerm_log_analytics_solution" "security" {
#   solution_name         = "SecurityInsights"
#   location              = var.location
#   resource_group_name   = var.resource_group_name
#   workspace_resource_id = azurerm_log_analytics_workspace.main.id
#   workspace_name        = azurerm_log_analytics_workspace.main.name
#
#   plan {
#     publisher = "Microsoft"
#     product   = "OMSGallery/SecurityInsights"
#   }
# }
