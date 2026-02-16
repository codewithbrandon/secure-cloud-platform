#------------------------------------------------------------------------------
# SECURE CLOUD PLATFORM - ROOT MODULE OUTPUTS
#------------------------------------------------------------------------------
# These outputs provide essential information for:
# - Accessing deployed resources
# - Configuring downstream systems (CI/CD, monitoring)
# - Documentation and operational runbooks
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# RESOURCE GROUP
#------------------------------------------------------------------------------

output "resource_group_name" {
  description = "Name of the resource group"
  value       = azurerm_resource_group.main.name
}

output "resource_group_id" {
  description = "Resource group ID"
  value       = azurerm_resource_group.main.id
}

#------------------------------------------------------------------------------
# NETWORKING
#------------------------------------------------------------------------------

output "vnet_id" {
  description = "Virtual network ID"
  value       = module.networking.vnet_id
}

output "vnet_name" {
  description = "Virtual network name"
  value       = module.networking.vnet_name
}

output "subnet_ids" {
  description = "Map of subnet IDs"
  value       = module.networking.subnet_ids
}

#------------------------------------------------------------------------------
# AKS CLUSTER
#------------------------------------------------------------------------------

output "aks_cluster_name" {
  description = "AKS cluster name"
  value       = module.aks.cluster_name
}

output "aks_cluster_id" {
  description = "AKS cluster resource ID"
  value       = module.aks.cluster_id
}

output "aks_cluster_fqdn" {
  description = "AKS cluster FQDN"
  value       = module.aks.cluster_fqdn
}

output "aks_kube_config" {
  description = "Kubeconfig for AKS cluster access"
  value       = module.aks.kube_config_raw
  sensitive   = true
}

output "aks_get_credentials_command" {
  description = "Azure CLI command to get AKS credentials"
  value       = "az aks get-credentials --resource-group ${azurerm_resource_group.main.name} --name ${module.aks.cluster_name}"
}

output "aks_oidc_issuer_url" {
  description = "OIDC issuer URL for workload identity"
  value       = module.aks.oidc_issuer_url
}

#------------------------------------------------------------------------------
# CONTAINER REGISTRY
#------------------------------------------------------------------------------

output "acr_name" {
  description = "Azure Container Registry name"
  value       = module.acr.acr_name
}

output "acr_login_server" {
  description = "ACR login server URL"
  value       = module.acr.acr_login_server
}

output "acr_login_command" {
  description = "Azure CLI command to login to ACR"
  value       = "az acr login --name ${module.acr.acr_name}"
}

#------------------------------------------------------------------------------
# SQL DATABASE
#------------------------------------------------------------------------------

output "sql_server_fqdn" {
  description = "SQL Server fully qualified domain name"
  value       = module.sql.server_fqdn
}

output "sql_database_name" {
  description = "SQL Database name"
  value       = module.sql.database_name
}

output "sql_connection_string" {
  description = "SQL connection string (without credentials)"
  value       = module.sql.connection_string
  sensitive   = true
}

#------------------------------------------------------------------------------
# KEY VAULT
#------------------------------------------------------------------------------

output "keyvault_name" {
  description = "Key Vault name"
  value       = module.keyvault.keyvault_name
}

output "keyvault_uri" {
  description = "Key Vault URI"
  value       = module.keyvault.keyvault_uri
}

#------------------------------------------------------------------------------
# APPLICATION GATEWAY
#------------------------------------------------------------------------------

output "appgw_public_ip" {
  description = "Application Gateway public IP address"
  value       = module.appgateway.public_ip_address
}

output "appgw_fqdn" {
  description = "Application Gateway FQDN"
  value       = module.appgateway.public_ip_fqdn
}

#------------------------------------------------------------------------------
# JENKINS
#------------------------------------------------------------------------------

output "jenkins_public_ip" {
  description = "Jenkins VM public IP address"
  value       = module.jenkins.public_ip_address
}

output "jenkins_fqdn" {
  description = "Jenkins VM FQDN"
  value       = module.jenkins.public_fqdn
}

output "jenkins_url" {
  description = "Jenkins web UI URL"
  value       = "http://${module.jenkins.public_fqdn}:8080"
}

output "jenkins_ssh_command" {
  description = "SSH command to connect to Jenkins VM"
  value       = "ssh -i jenkins_key.pem ${module.jenkins.admin_username}@${module.jenkins.public_fqdn}"
}

output "jenkins_ssh_private_key" {
  description = "Jenkins SSH private key (save to file for SSH access)"
  value       = module.jenkins.ssh_private_key
  sensitive   = true
}

#------------------------------------------------------------------------------
# MONITORING
#------------------------------------------------------------------------------

output "log_analytics_workspace_id" {
  description = "Log Analytics workspace ID"
  value       = module.monitoring.workspace_id
}

output "log_analytics_workspace_name" {
  description = "Log Analytics workspace name"
  value       = module.monitoring.workspace_name
}

#------------------------------------------------------------------------------
# QUICK START COMMANDS
#------------------------------------------------------------------------------

output "quick_start" {
  description = "Quick start commands after deployment"
  value       = <<-EOT

    ============================================================
    SECURE CLOUD PLATFORM - DEPLOYMENT COMPLETE
    ============================================================

    1. GET AKS CREDENTIALS:
       ${module.aks.cluster_name != "" ? "az aks get-credentials --resource-group ${azurerm_resource_group.main.name} --name ${module.aks.cluster_name}" : ""}

    2. LOGIN TO ACR:
       az acr login --name ${module.acr.acr_name}

    3. ACCESS JENKINS:
       URL: http://${module.jenkins.public_fqdn}:8080
       SSH: ssh -i jenkins_key.pem ${module.jenkins.admin_username}@${module.jenkins.public_fqdn}

    4. SAVE JENKINS SSH KEY:
       terraform output -raw jenkins_ssh_private_key > jenkins_key.pem
       chmod 600 jenkins_key.pem

    5. VIEW APPLICATION:
       http://${module.appgateway.public_ip_fqdn}

    ============================================================
  EOT
}
