$env:PATH = "C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin;C:\Users\qkdat\AppData\Local\Microsoft\WinGet\Links;" + $env:PATH
Set-Location "C:\Users\qkdat\secure-cloud-platform\terraform"
$terraformPath = "C:\Users\qkdat\AppData\Local\Microsoft\WinGet\Packages\Hashicorp.Terraform_Microsoft.Winget.Source_8wekyb3d8bbwe\terraform.exe"

Write-Host "Upgrading providers..."
& $terraformPath init -upgrade

Write-Host "Planning changes..."
& $terraformPath plan -out=tfplan

if ($LASTEXITCODE -eq 0) {
    Write-Host "Applying changes..."
    & $terraformPath apply tfplan
}
