$env:PATH = "C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin;C:\Users\qkdat\AppData\Local\Microsoft\WinGet\Links;" + $env:PATH
Set-Location "C:\Users\qkdat\secure-cloud-platform\terraform"
$terraformPath = "C:\Users\qkdat\AppData\Local\Microsoft\WinGet\Packages\Hashicorp.Terraform_Microsoft.Winget.Source_8wekyb3d8bbwe\terraform.exe"

Write-Host "Attempting to recover soft-deleted Key Vault..."
az keyvault recover --name "kv-seccloud-prod" --location "westus2" 2>&1

Write-Host "`nUpgrading providers..."
& $terraformPath init -upgrade

Write-Host "`nRunning terraform apply..."
& $terraformPath apply -auto-approve
