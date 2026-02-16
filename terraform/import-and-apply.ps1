$env:PATH = "C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin;C:\Users\qkdat\AppData\Local\Microsoft\WinGet\Links;" + $env:PATH
Set-Location "C:\Users\qkdat\secure-cloud-platform\terraform"
$terraformPath = "C:\Users\qkdat\AppData\Local\Microsoft\WinGet\Packages\Hashicorp.Terraform_Microsoft.Winget.Source_8wekyb3d8bbwe\terraform.exe"

Write-Host "Importing existing ContainerInsights solution..."
& $terraformPath import "module.monitoring.azurerm_log_analytics_solution.containers" "/subscriptions/1802a8b6-7c48-4e43-b8d7-0ea4369ac707/resourceGroups/rg-seccloud-prod/providers/Microsoft.OperationsManagement/solutions/ContainerInsights(log-seccloud-prod)"

Write-Host "`nRunning terraform apply..."
& $terraformPath apply -auto-approve
