# Safe teardown script for the sandbox AWS infrastructure (stops EC2/RDS charges).
param(
    [Parameter(Mandatory = $true)]
    [string]$StateBucket,
    [switch]$IncludeBootstrap
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$InfraDir = Join-Path $Root "msp-sandbox-infra\infra"
$BootstrapDir = Join-Path $Root "msp-sandbox-infra\bootstrap"

Write-Host "Destroying sandbox infra in $InfraDir..." -ForegroundColor Yellow
Push-Location $InfraDir
try {
    terraform init -input=false -backend-config="bucket=$StateBucket"
    terraform destroy -auto-approve
} finally {
    Pop-Location
}

if ($IncludeBootstrap) {
    Write-Host "Destroying bootstrap resources in $BootstrapDir..." -ForegroundColor Red
    Push-Location $BootstrapDir
    try {
        terraform destroy
    } finally {
        Pop-Location
    }
}
