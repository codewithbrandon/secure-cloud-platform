#------------------------------------------------------------------------------
# LOCAL VALUES - NAMING CONVENTIONS AND COMMON CONFIGURATIONS
#------------------------------------------------------------------------------
# Security Note: Consistent naming conventions help with:
# - Resource identification during incident response
# - Cost allocation and security auditing
# - Automated policy enforcement (Azure Policy)
# - Access control patterns (RBAC wildcards)
#------------------------------------------------------------------------------

locals {
  # Naming prefix following Azure naming conventions
  # Format: {resource-type}-{project}-{environment}-{region}
  name_prefix = "${var.project_name}-${var.environment}"

  # Resource-specific names with Azure naming conventions
  # Reference: https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/resource-naming
  names = {
    resource_group   = "rg-${local.name_prefix}"
    vnet             = "vnet-${local.name_prefix}"
    aks_cluster      = "aks-${local.name_prefix}"
    acr              = "acr${var.project_name}${var.environment}" # ACR names must be alphanumeric
    sql_server       = "sql-${local.name_prefix}"
    sql_database     = "sqldb-${local.name_prefix}"
    keyvault         = "kv-${local.name_prefix}-v2"
    appgw            = "appgw-${local.name_prefix}"
    jenkins_vm       = "vm-jenkins-${local.name_prefix}"
    log_analytics    = "log-${local.name_prefix}"
    managed_identity = "id-${local.name_prefix}"
    nsg_aks          = "nsg-aks-${local.name_prefix}"
    nsg_appgw        = "nsg-appgw-${local.name_prefix}"
    nsg_data         = "nsg-data-${local.name_prefix}"
    nsg_mgmt         = "nsg-mgmt-${local.name_prefix}"
    nsg_acr          = "nsg-acr-${local.name_prefix}"
  }

  # Subnet names
  subnet_names = {
    aks   = "snet-aks-${local.name_prefix}"
    appgw = "snet-appgw-${local.name_prefix}"
    data  = "snet-data-${local.name_prefix}"
    mgmt  = "snet-mgmt-${local.name_prefix}"
    acr   = "snet-acr-${local.name_prefix}"
  }

  # Common tags applied to all resources
  # Security relevance: Tags enable cost tracking, ownership identification,
  # and automated security policy application
  common_tags = merge(
    {
      Project                = var.project_name
      Environment            = var.environment
      ManagedBy              = "Terraform"
      SecurityClassification = "Internal"
      DataClassification     = "Confidential"
      CostCenter             = "Security-Portfolio"
      Owner                  = "Platform-Team"
      CreatedDate            = timestamp()
    },
    var.tags
  )

  # AKS-specific configurations
  aks_config = {
    dns_prefix        = "${var.project_name}${var.environment}"
    network_plugin    = "azure"    # Azure CNI for better network policy support
    network_policy    = "calico"   # Calico for Kubernetes Network Policies
    load_balancer_sku = "standard" # Required for availability zones
    outbound_type     = "loadBalancer"
    service_cidr      = "10.1.0.0/16"
    dns_service_ip    = "10.1.0.10"
  }

  # NSG rule priorities (lower = higher priority)
  # Organized by category for maintainability
  nsg_priorities = {
    allow_critical    = 100  # Critical infrastructure (health probes, etc.)
    allow_application = 200  # Application traffic
    allow_management  = 300  # Management access
    deny_all          = 4096 # Explicit deny all (defense in depth)
  }
}
