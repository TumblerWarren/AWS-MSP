# One-time AWS OIDC + State Bucket Bootstrap (uses local Terraform or Docker hashicorp/terraform:1.10.5).
# After this runs once, ALL infrastructure deployments happen through GitHub Actions:
#   - msp-sandbox-infra/.github/workflows/deploy-infra.yml
#   - msp-platform/.github/workflows/deploy-platform-infra.yml
# And the application runs locally in Docker via:
#   docker compose -f msp-platform/docker-compose.yml up --build

param(
    [Parameter(Mandatory = $true)]
    [string]$SandboxGitHubRepo,   # e.g. "your-user/msp-sandbox-infra"
    [string]$PlatformGitHubRepo = "", # e.g. "your-user/msp-platform"
    [string]$Region = "us-east-1"
)

$ErrorActionPreference = "Stop"
$WorkspaceRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$BootstrapDir = Join-Path $WorkspaceRoot "msp-sandbox-infra\bootstrap"

function Invoke-Terraform {
    param([string]$WorkDir, [string[]]$TfArgs)
    if (Get-Command terraform -ErrorAction SilentlyContinue) {
        Push-Location $WorkDir
        try {
            & terraform @TfArgs
            if ($LASTEXITCODE -ne 0) { throw "terraform exited with code $LASTEXITCODE" }
        } finally {
            Pop-Location
        }
    } else {
        docker run --rm `
            -v "${WorkDir}:/workspace" `
            -w /workspace `
            -e AWS_ACCESS_KEY_ID `
            -e AWS_SECRET_ACCESS_KEY `
            -e AWS_SESSION_TOKEN `
            -e AWS_REGION=$Region `
            hashicorp/terraform:1.10.5 @TfArgs
        if ($LASTEXITCODE -ne 0) { throw "docker terraform exited with code $LASTEXITCODE" }
    }
}

Write-Host "1. Verifying temporary AWS credentials..." -ForegroundColor Cyan
$Caller = aws sts get-caller-identity --output json | ConvertFrom-Json
if (-not $Caller.Account) {
    throw "No valid AWS credentials found. Set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_SESSION_TOKEN."
}
Write-Host "   Authenticated as $($Caller.Arn) in account $($Caller.Account)" -ForegroundColor Green

Write-Host "2. Bootstrapping S3 state bucket + GitHub Actions OIDC role..." -ForegroundColor Cyan
Invoke-Terraform -WorkDir $BootstrapDir -TfArgs @("init", "-input=false")
Invoke-Terraform -WorkDir $BootstrapDir -TfArgs @(
    "apply", "-auto-approve",
    "-var=aws_region=$Region",
    "-var=github_repo=$SandboxGitHubRepo",
    "-var=platform_github_repo=$PlatformGitHubRepo"
)

$StateBucket = (Invoke-Terraform -WorkDir $BootstrapDir -TfArgs @("output", "-raw", "state_bucket_name") | Select-Object -Last 1).Trim()
$CiRoleArn = (Invoke-Terraform -WorkDir $BootstrapDir -TfArgs @("output", "-raw", "ci_role_arn") | Select-Object -Last 1).Trim()

Write-Host ""
Write-Host "Bootstrap complete! Configure these on both GitHub repos ($SandboxGitHubRepo and $PlatformGitHubRepo):" -ForegroundColor Green
Write-Host "  Repository Secret   AWS_CI_ROLE_ARN = $CiRoleArn"
Write-Host "  Repository Variable TF_STATE_BUCKET = $StateBucket"
Write-Host "  Repository Variable AWS_REGION      = $Region"
Write-Host ""
Write-Host "Then trigger the GitHub Actions workflows:" -ForegroundColor Cyan
Write-Host "  1. msp-platform      -> 'Deploy Platform AWS Infrastructure' (creates msp-investigator-readonly role; leave host_on_aws_fargate=false)"
Write-Host "  2. msp-sandbox-infra -> 'Deploy Sandbox Infrastructure' (deploys VPC, Subnets, SGs, EC2, RDS)"
Write-Host ""
Write-Host "Finally, run the application locally in Docker:" -ForegroundColor Cyan
Write-Host "  cd msp-platform"
Write-Host "  docker compose up --build"
