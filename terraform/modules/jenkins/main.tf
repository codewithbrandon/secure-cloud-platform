#------------------------------------------------------------------------------
# JENKINS MODULE - SECURE CI/CD SERVER
#------------------------------------------------------------------------------
# Security Purpose:
# - Dedicated VM for CI/CD to isolate build environment
# - Managed identity for Azure resource access (no stored credentials)
# - SSH key authentication (no passwords)
# - Network isolation in management subnet
# - Minimal attack surface with controlled access
#
# Enterprise Relevance:
# - CI/CD is a high-value target for supply chain attacks
# - Separation of duties: developers don't access Jenkins directly
# - Audit trail for all pipeline executions
# - Controlled deployment flow to production
#
# Zero Trust Implementation:
# - SSH access restricted to admin IPs only
# - Jenkins UI access restricted to admin IPs only
# - Managed identity for Azure operations (no secrets)
# - Network policies prevent lateral movement
#------------------------------------------------------------------------------

# Generate SSH key pair for Jenkins VM
resource "tls_private_key" "jenkins" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# User-assigned managed identity for Jenkins
resource "azurerm_user_assigned_identity" "jenkins" {
  name                = "id-${var.vm_name}"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

# Network interface for Jenkins VM
resource "azurerm_network_interface" "jenkins" {
  name                = "nic-${var.vm_name}"
  location            = var.location
  resource_group_name = var.resource_group_name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.jenkins.id
  }

  tags = var.tags
}

# Public IP for Jenkins (restricted by NSG)
resource "azurerm_public_ip" "jenkins" {
  name                = "pip-${var.vm_name}"
  location            = var.location
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard"

  # Domain name label for easier access
  domain_name_label = var.domain_name_label

  tags = var.tags
}

# Jenkins Virtual Machine
resource "azurerm_linux_virtual_machine" "jenkins" {
  name                = var.vm_name
  location            = var.location
  resource_group_name = var.resource_group_name
  size                = var.vm_size

  #----------------------------------------------------------------------------
  # AUTHENTICATION
  #----------------------------------------------------------------------------
  # SSH key authentication only - password auth disabled
  #----------------------------------------------------------------------------

  admin_username                  = var.admin_username
  disable_password_authentication = true

  admin_ssh_key {
    username   = var.admin_username
    public_key = tls_private_key.jenkins.public_key_openssh
  }

  #----------------------------------------------------------------------------
  # NETWORK
  #----------------------------------------------------------------------------

  network_interface_ids = [azurerm_network_interface.jenkins.id]

  #----------------------------------------------------------------------------
  # IDENTITY
  #----------------------------------------------------------------------------
  # User-assigned identity for Azure resource access
  # Grants permissions via RBAC without storing credentials
  #----------------------------------------------------------------------------

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.jenkins.id]
  }

  #----------------------------------------------------------------------------
  # OS CONFIGURATION
  #----------------------------------------------------------------------------

  os_disk {
    name                 = "osdisk-${var.vm_name}"
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS" # Premium_LRS for production
    disk_size_gb         = 128
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  #----------------------------------------------------------------------------
  # SECURITY CONFIGURATIONS
  #----------------------------------------------------------------------------

  # Enable boot diagnostics for troubleshooting
  boot_diagnostics {
    storage_account_uri = null # Use managed storage account
  }

  # Patch mode - automatic security patches
  patch_mode = "AutomaticByPlatform"

  # Provision VM agent for extensions
  provision_vm_agent = true

  #----------------------------------------------------------------------------
  # CLOUD-INIT CONFIGURATION
  #----------------------------------------------------------------------------
  # Basic setup script - Ansible will complete configuration
  #----------------------------------------------------------------------------

  custom_data = base64encode(<<-EOF
    #cloud-config
    package_update: true
    package_upgrade: true
    packages:
      - apt-transport-https
      - ca-certificates
      - curl
      - gnupg
      - lsb-release
      - openjdk-17-jdk
      - docker.io
      - unzip

    runcmd:
      # Add user to docker group
      - usermod -aG docker ${var.admin_username}

      # Install Azure CLI
      - curl -sL https://aka.ms/InstallAzureCLIDeb | bash

      # Install kubectl
      - curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
      - install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

      # Install Helm
      - curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

      # Create Jenkins directories
      - mkdir -p /var/jenkins_home
      - chown ${var.admin_username}:${var.admin_username} /var/jenkins_home

      # Security: Restrict file permissions
      - chmod 700 /var/jenkins_home

      # Note: Jenkins installation completed via Ansible for idempotency
    EOF
  )

  tags = var.tags

  lifecycle {
    ignore_changes = [
      custom_data, # Don't redeploy on cloud-init changes
    ]
  }
}

#------------------------------------------------------------------------------
# ROLE ASSIGNMENTS
#------------------------------------------------------------------------------
# Grant Jenkins identity permissions to Azure resources
# Follow least privilege principle
#------------------------------------------------------------------------------

# Grant Jenkins AcrPush permission to container registry
# Note: ACR is always deployed in this architecture
resource "azurerm_role_assignment" "jenkins_acr_push" {
  scope                = var.acr_id
  role_definition_name = "AcrPush"
  principal_id         = azurerm_user_assigned_identity.jenkins.principal_id
}

# Grant Jenkins permissions to get AKS credentials
# Note: AKS is always deployed in this architecture
resource "azurerm_role_assignment" "jenkins_aks_user" {
  scope                = var.aks_id
  role_definition_name = "Azure Kubernetes Service Cluster User Role"
  principal_id         = azurerm_user_assigned_identity.jenkins.principal_id
}

# Grant Jenkins Contributor on AKS for deployments
# Note: More restrictive role recommended for production
resource "azurerm_role_assignment" "jenkins_aks_contributor" {
  scope                = var.aks_id
  role_definition_name = "Azure Kubernetes Service Contributor Role"
  principal_id         = azurerm_user_assigned_identity.jenkins.principal_id
}

#------------------------------------------------------------------------------
# DIAGNOSTIC SETTINGS
#------------------------------------------------------------------------------

# Store SSH private key in Key Vault for secure access
# Note: Key Vault is always deployed in this architecture
resource "azurerm_key_vault_secret" "jenkins_ssh_private_key" {
  name         = "jenkins-ssh-private-key"
  value        = tls_private_key.jenkins.private_key_pem
  key_vault_id = var.keyvault_id

  content_type = "application/x-pem-file"

  tags = var.tags
}
