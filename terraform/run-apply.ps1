$env:PATH = "C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin;C:\Users\qkdat\AppData\Local\Microsoft\WinGet\Links;" + $env:PATH
Set-Location "C:\Users\qkdat\secure-cloud-platform\terraform"
$terraformPath = "C:\Users\qkdat\AppData\Local\Microsoft\WinGet\Packages\Hashicorp.Terraform_Microsoft.Winget.Source_8wekyb3d8bbwe\terraform.exe"

# Generate fresh plan and apply
& $terraformPath plan -out=tfplan
if ($LASTEXITCODE -eq 0) {
    & $terraformPath apply tfplan
}
