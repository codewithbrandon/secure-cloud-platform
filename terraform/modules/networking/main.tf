#------------------------------------------------------------------------------
# NETWORKING MODULE - VIRTUAL NETWORK AND SECURITY GROUPS
#------------------------------------------------------------------------------
# Security Architecture:
# - Network segmentation isolates workloads and limits blast radius
# - NSGs implement default-deny posture with explicit allow rules
# - Each subnet has dedicated NSG for granular control
# - Private endpoints keep traffic off public internet
#
# Enterprise Relevance:
# - Network segmentation is foundational to Zero Trust
# - NSG flow logs enable threat detection and forensics
# - Micro-segmentation prevents lateral movement
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# VIRTUAL NETWORK
#------------------------------------------------------------------------------
# The VNet is the network boundary for our Azure resources.
# All subnets share this address space but are isolated by NSGs.
#------------------------------------------------------------------------------

resource "azurerm_virtual_network" "main" {
  name                = var.vnet_name
  location            = var.location
  resource_group_name = var.resource_group_name
  address_space       = var.vnet_address_space

  # Enable DDoS protection in production (adds ~$3000/month)
  # ddos_protection_plan {
  #   id     = azurerm_network_ddos_protection_plan.main.id
  #   enable = true
  # }

  tags = var.tags
}

#------------------------------------------------------------------------------
# SUBNETS
#------------------------------------------------------------------------------
# Each subnet serves a specific purpose with appropriate security controls.
# Service endpoints are enabled only where needed (least privilege).
#------------------------------------------------------------------------------

# AKS Subnet - Hosts Kubernetes worker nodes
resource "azurerm_subnet" "aks" {
  name                 = var.subnet_names["aks"]
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [var.subnet_prefixes.aks]

  # Service endpoints for secure access to Azure services
  service_endpoints = [
    "Microsoft.ContainerRegistry", # Pull images without public internet
    "Microsoft.KeyVault",          # Access secrets securely
    "Microsoft.Sql"                # Database access
  ]
}

# Application Gateway Subnet - Dedicated subnet for ingress
# Note: Application Gateway requires dedicated subnet
resource "azurerm_subnet" "appgw" {
  name                 = var.subnet_names["appgw"]
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [var.subnet_prefixes.appgw]
}

# Data Subnet - Hosts private endpoints for PaaS services
resource "azurerm_subnet" "data" {
  name                 = var.subnet_names["data"]
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [var.subnet_prefixes.data]

  # Required for private endpoints
  private_endpoint_network_policies = "Disabled"
}

# Management Subnet - Jenkins and administrative resources
resource "azurerm_subnet" "mgmt" {
  name                 = var.subnet_names["mgmt"]
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [var.subnet_prefixes.mgmt]

  service_endpoints = [
    "Microsoft.ContainerRegistry",
    "Microsoft.KeyVault",
    "Microsoft.Sql"
  ]
}

# ACR Subnet - Private endpoint for container registry
resource "azurerm_subnet" "acr" {
  name                 = var.subnet_names["acr"]
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [var.subnet_prefixes.acr]

  private_endpoint_network_policies = "Disabled"
}

#------------------------------------------------------------------------------
# NETWORK SECURITY GROUPS
#------------------------------------------------------------------------------
# NSGs implement defense-in-depth at the network layer.
# Rules follow the principle: explicit deny all, then allow only required traffic.
# Each rule includes justification for security audits.
#------------------------------------------------------------------------------

# AKS Subnet NSG
resource "azurerm_network_security_group" "aks" {
  name                = var.nsg_names["nsg_aks"]
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

# AKS NSG Rules
resource "azurerm_network_security_rule" "aks_allow_appgw_https" {
  name                        = "AllowAppGatewayHTTPS"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = var.subnet_prefixes.appgw
  destination_address_prefix  = var.subnet_prefixes.aks
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.aks.name

  # Security Justification: Required for Application Gateway to forward HTTPS traffic to AKS ingress
}

resource "azurerm_network_security_rule" "aks_allow_appgw_http" {
  name                        = "AllowAppGatewayHTTP"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "80"
  source_address_prefix       = var.subnet_prefixes.appgw
  destination_address_prefix  = var.subnet_prefixes.aks
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.aks.name

  # Security Justification: Required for HTTP to HTTPS redirect at ingress level
}

resource "azurerm_network_security_rule" "aks_allow_internal" {
  name                        = "AllowVNetInternal"
  priority                    = 200
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "VirtualNetwork"
  destination_address_prefix  = "VirtualNetwork"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.aks.name

  # Security Justification: Required for AKS internal communication (kubelet, pod-to-pod)
}

resource "azurerm_network_security_rule" "aks_allow_lb" {
  name                        = "AllowAzureLoadBalancer"
  priority                    = 300
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "AzureLoadBalancer"
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.aks.name

  # Security Justification: Required for Azure Load Balancer health probes
}

resource "azurerm_network_security_rule" "aks_deny_all_inbound" {
  name                        = "DenyAllInbound"
  priority                    = 4096
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.aks.name

  # Security Justification: Default deny - only explicitly allowed traffic passes
}

# Application Gateway Subnet NSG
resource "azurerm_network_security_group" "appgw" {
  name                = var.nsg_names["nsg_appgw"]
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

# AppGW NSG Rules
resource "azurerm_network_security_rule" "appgw_allow_internet_https" {
  name                        = "AllowInternetHTTPS"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "Internet"
  destination_address_prefix  = var.subnet_prefixes.appgw
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.appgw.name

  # Security Justification: Public HTTPS endpoint - protected by WAF rules
}

resource "azurerm_network_security_rule" "appgw_allow_internet_http" {
  name                        = "AllowInternetHTTP"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "80"
  source_address_prefix       = "Internet"
  destination_address_prefix  = var.subnet_prefixes.appgw
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.appgw.name

  # Security Justification: HTTP allowed for redirect to HTTPS only
}

resource "azurerm_network_security_rule" "appgw_allow_gateway_manager" {
  name                        = "AllowGatewayManager"
  priority                    = 120
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "65200-65535"
  source_address_prefix       = "GatewayManager"
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.appgw.name

  # Security Justification: Required by Azure for Application Gateway health monitoring
}

resource "azurerm_network_security_rule" "appgw_allow_lb" {
  name                        = "AllowAzureLoadBalancer"
  priority                    = 130
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "AzureLoadBalancer"
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.appgw.name

  # Security Justification: Required for Azure Load Balancer health probes
}

resource "azurerm_network_security_rule" "appgw_deny_all_inbound" {
  name                        = "DenyAllInbound"
  priority                    = 4096
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.appgw.name

  # Security Justification: Default deny - only explicitly allowed traffic passes
}

# Data Subnet NSG (SQL, Key Vault private endpoints)
resource "azurerm_network_security_group" "data" {
  name                = var.nsg_names["nsg_data"]
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_network_security_rule" "data_allow_aks_sql" {
  name                        = "AllowAKStoSQL"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "1433"
  source_address_prefix       = var.subnet_prefixes.aks
  destination_address_prefix  = var.subnet_prefixes.data
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.data.name

  # Security Justification: Application pods need SQL access; restricted to AKS subnet only
}

resource "azurerm_network_security_rule" "data_allow_mgmt_sql" {
  name                        = "AllowMgmttoSQL"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "1433"
  source_address_prefix       = var.subnet_prefixes.mgmt
  destination_address_prefix  = var.subnet_prefixes.data
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.data.name

  # Security Justification: Jenkins needs SQL access for migrations/deployments
}

resource "azurerm_network_security_rule" "data_deny_all_inbound" {
  name                        = "DenyAllInbound"
  priority                    = 4096
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.data.name

  # Security Justification: Data tier has NO internet access - private endpoints only
}

# Management Subnet NSG (Jenkins)
resource "azurerm_network_security_group" "mgmt" {
  name                = var.nsg_names["nsg_mgmt"]
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_network_security_rule" "mgmt_allow_ssh" {
  name                        = "AllowSSHFromAdmin"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefixes     = var.admin_ip_addresses
  destination_address_prefix  = var.subnet_prefixes.mgmt
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.mgmt.name

  # Security Justification: SSH access restricted to admin IPs only
}

resource "azurerm_network_security_rule" "mgmt_allow_jenkins" {
  name                        = "AllowJenkinsFromAdmin"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "8080"
  source_address_prefixes     = var.admin_ip_addresses
  destination_address_prefix  = var.subnet_prefixes.mgmt
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.mgmt.name

  # Security Justification: Jenkins UI access restricted to admin IPs only
}

resource "azurerm_network_security_rule" "mgmt_deny_all_inbound" {
  name                        = "DenyAllInbound"
  priority                    = 4096
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.mgmt.name

  # Security Justification: Management resources have NO public access except admin IPs
}

# ACR Subnet NSG
resource "azurerm_network_security_group" "acr" {
  name                = var.nsg_names["nsg_acr"]
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_network_security_rule" "acr_allow_aks" {
  name                        = "AllowAKStoACR"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = var.subnet_prefixes.aks
  destination_address_prefix  = var.subnet_prefixes.acr
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.acr.name

  # Security Justification: AKS pulls images from ACR via private endpoint
}

resource "azurerm_network_security_rule" "acr_allow_mgmt" {
  name                        = "AllowMgmttoACR"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = var.subnet_prefixes.mgmt
  destination_address_prefix  = var.subnet_prefixes.acr
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.acr.name

  # Security Justification: Jenkins pushes images to ACR
}

resource "azurerm_network_security_rule" "acr_deny_all_inbound" {
  name                        = "DenyAllInbound"
  priority                    = 4096
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = azurerm_network_security_group.acr.name

  # Security Justification: ACR has NO public access - private endpoint only
}

#------------------------------------------------------------------------------
# NSG ASSOCIATIONS
#------------------------------------------------------------------------------
# Associate each NSG with its subnet to enforce rules
#------------------------------------------------------------------------------

resource "azurerm_subnet_network_security_group_association" "aks" {
  subnet_id                 = azurerm_subnet.aks.id
  network_security_group_id = azurerm_network_security_group.aks.id
}

resource "azurerm_subnet_network_security_group_association" "appgw" {
  subnet_id                 = azurerm_subnet.appgw.id
  network_security_group_id = azurerm_network_security_group.appgw.id
}

resource "azurerm_subnet_network_security_group_association" "data" {
  subnet_id                 = azurerm_subnet.data.id
  network_security_group_id = azurerm_network_security_group.data.id
}

resource "azurerm_subnet_network_security_group_association" "mgmt" {
  subnet_id                 = azurerm_subnet.mgmt.id
  network_security_group_id = azurerm_network_security_group.mgmt.id
}

resource "azurerm_subnet_network_security_group_association" "acr" {
  subnet_id                 = azurerm_subnet.acr.id
  network_security_group_id = azurerm_network_security_group.acr.id
}
