$env:PATH = "C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin;C:\Users\qkdat\AppData\Local\Microsoft\WinGet\Links;" + $env:PATH
Set-Location "C:\Users\qkdat\secure-cloud-platform\terraform"
$terraformPath = "C:\Users\qkdat\AppData\Local\Microsoft\WinGet\Packages\Hashicorp.Terraform_Microsoft.Winget.Source_8wekyb3d8bbwe\terraform.exe"

Write-Host "Importing NSG data..."
& $terraformPath import "module.networking.azurerm_network_security_group.data" "/subscriptions/1802a8b6-7c48-4e43-b8d7-0ea4369ac707/resourceGroups/rg-seccloud-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-data-seccloud-prod"

Write-Host "`nImporting NSG mgmt..."
& $terraformPath import "module.networking.azurerm_network_security_group.mgmt" "/subscriptions/1802a8b6-7c48-4e43-b8d7-0ea4369ac707/resourceGroups/rg-seccloud-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-mgmt-seccloud-prod"

Write-Host "`nImporting AKS deny all inbound rule..."
& $terraformPath import "module.networking.azurerm_network_security_rule.aks_deny_all_inbound" "/subscriptions/1802a8b6-7c48-4e43-b8d7-0ea4369ac707/resourceGroups/rg-seccloud-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-aks-seccloud-prod/securityRules/DenyAllInbound"

Write-Host "`nRunning terraform apply..."
& $terraformPath apply -auto-approve
