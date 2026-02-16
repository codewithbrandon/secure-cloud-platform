$env:PATH = "C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin;C:\Users\qkdat\AppData\Local\Microsoft\WinGet\Links;" + $env:PATH
Set-Location "C:\Users\qkdat\secure-cloud-platform\terraform"
$terraformPath = "C:\Users\qkdat\AppData\Local\Microsoft\WinGet\Packages\Hashicorp.Terraform_Microsoft.Winget.Source_8wekyb3d8bbwe\terraform.exe"

Write-Host "Listing deleted vaults to find location..."
$deletedVaults = az keyvault list-deleted --query "[?name=='kv-seccloud-prod']" -o json | ConvertFrom-Json
if ($deletedVaults) {
    $location = $deletedVaults[0].properties.location
    Write-Host "Found soft-deleted vault in location: $location"

    Write-Host "`nRecovering soft-deleted Key Vault..."
    az keyvault recover --name "kv-seccloud-prod" --location $location
}

Write-Host "`nRunning terraform apply..."
& $terraformPath apply -auto-approve
