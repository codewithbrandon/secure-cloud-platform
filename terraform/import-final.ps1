$env:PATH = "C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin;C:\Users\qkdat\AppData\Local\Microsoft\WinGet\Links;" + $env:PATH
Set-Location "C:\Users\qkdat\secure-cloud-platform\terraform"
$terraformPath = "C:\Users\qkdat\AppData\Local\Microsoft\WinGet\Packages\Hashicorp.Terraform_Microsoft.Winget.Source_8wekyb3d8bbwe\terraform.exe"

Write-Host "Importing mgmt subnet..."
& $terraformPath import "module.networking.azurerm_subnet.mgmt" "/subscriptions/1802a8b6-7c48-4e43-b8d7-0ea4369ac707/resourceGroups/rg-seccloud-prod/providers/Microsoft.Network/virtualNetworks/vnet-seccloud-prod/subnets/snet-mgmt-seccloud-prod"

Write-Host "`nImporting data subnet NSG association..."
& $terraformPath import "module.networking.azurerm_subnet_network_security_group_association.data" "/subscriptions/1802a8b6-7c48-4e43-b8d7-0ea4369ac707/resourceGroups/rg-seccloud-prod/providers/Microsoft.Network/virtualNetworks/vnet-seccloud-prod/subnets/snet-data-seccloud-prod"

Write-Host "`nRunning terraform apply..."
& $terraformPath apply -auto-approve
