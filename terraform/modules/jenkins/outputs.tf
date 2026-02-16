#------------------------------------------------------------------------------
# JENKINS MODULE - OUTPUTS
#------------------------------------------------------------------------------

output "vm_id" {
  description = "Jenkins VM resource ID"
  value       = azurerm_linux_virtual_machine.jenkins.id
}

output "vm_name" {
  description = "Jenkins VM name"
  value       = azurerm_linux_virtual_machine.jenkins.name
}

output "private_ip_address" {
  description = "Jenkins VM private IP address"
  value       = azurerm_network_interface.jenkins.private_ip_address
}

output "public_ip_address" {
  description = "Jenkins VM public IP address"
  value       = azurerm_public_ip.jenkins.ip_address
}

output "public_fqdn" {
  description = "Jenkins VM public FQDN"
  value       = azurerm_public_ip.jenkins.fqdn
}

output "admin_username" {
  description = "Jenkins VM admin username"
  value       = azurerm_linux_virtual_machine.jenkins.admin_username
}

output "ssh_private_key" {
  description = "SSH private key for Jenkins VM access"
  value       = tls_private_key.jenkins.private_key_pem
  sensitive   = true
}

output "ssh_public_key" {
  description = "SSH public key"
  value       = tls_private_key.jenkins.public_key_openssh
}

output "managed_identity_principal_id" {
  description = "Jenkins managed identity principal ID"
  value       = azurerm_user_assigned_identity.jenkins.principal_id
}

output "managed_identity_client_id" {
  description = "Jenkins managed identity client ID"
  value       = azurerm_user_assigned_identity.jenkins.client_id
}
