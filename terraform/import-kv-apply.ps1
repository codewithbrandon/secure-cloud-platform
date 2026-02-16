$env:PATH = "C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin;C:\Users\qkdat\AppData\Local\Microsoft\WinGet\Links;" + $env:PATH
Set-Location "C:\Users\qkdat\secure-cloud-platform\terraform"
$terraformPath = "C:\Users\qkdat\AppData\Local\Microsoft\WinGet\Packages\Hashicorp.Terraform_Microsoft.Winget.Source_8wekyb3d8bbwe\terraform.exe"

Write-Host "Importing Key Vault into Terraform state..."
& $terraformPath import "module.keyvault.azurerm_key_vault.main" "/subscriptions/1802a8b6-7c48-4e43-b8d7-0ea4369ac707/resourceGroups/rg-seccloud-prod/providers/Microsoft.KeyVault/vaults/kv-seccloud-prod"

Write-Host "`nRunning terraform apply..."
& $terraformPath apply -auto-approve
