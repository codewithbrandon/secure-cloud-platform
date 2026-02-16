$env:PATH = "C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin;C:\Users\qkdat\AppData\Local\Microsoft\WinGet\Links;" + $env:PATH
Set-Location "C:\Users\qkdat\secure-cloud-platform\terraform"

Write-Host "Getting supported AKS versions in westus2..."
az aks get-versions --location westus2 --query "values[?isDefault].version" -o tsv

Write-Host "`nChecking for soft-deleted Key Vaults..."
az keyvault list-deleted --query "[?name=='kv-seccloud-prod']" -o table

Write-Host "`nPurging soft-deleted Key Vault (if exists)..."
az keyvault purge --name "kv-seccloud-prod" --location "eastus" 2>&1
az keyvault purge --name "kv-seccloud-prod" --location "westus2" 2>&1
