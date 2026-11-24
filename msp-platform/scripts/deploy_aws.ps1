# End-to-end AWS deployment script for MSP MVP 1.
# Run once you have configured temporary AWS credentials in your shell.
#
# What it deploys:
#   1. msp-sandbox-infra/bootstrap -> S3 state bucket + GitHub OIDC CI role
#   2. msp-platform/infra          -> msp-investigator-readonly IAM role, ECS task roles,
#                                     ECR repo, and ECS cluster
#   3. Writes MSP_INVESTIGATOR_ROLE_ARN into msp-platform/backend/.env
#   4. (Optional -DeployContainer) -> Builds & pushes the Docker image (UI + API + Strands
#                                     Investigator + Claude Agent SDK Patcher + AWS MCP servers)
#                                     to ECR and starts the ECS Fargate service
#   5. (Optional -DeploySandboxInfra) -> Deploys VPC, Subnets, SGs, EC2, RDS in msp-sandbox-infra/infra

param(
    [string]$Region = "us-east-1",
    [string]$GitHubRepo = "owner/msp-sandbox-infra",
    [string]$GitHubToken = "",
    [switch]$DeployContainer,
    [switch]$DeploySandboxInfra
)

$ErrorActionPreference = "Stop"
$WorkspaceRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$BootstrapDir = Join-Path $WorkspaceRoot "msp-sandbox-infra\bootstrap"
$SandboxInfraDir = Join-Path $WorkspaceRoot "msp-sandbox-infra\infra"
$PlatformDir = Join-Path $WorkspaceRoot "msp-platform"
$PlatformInfraDir = Join-Path $PlatformDir "infra"
$BackendEnvFile = Join-Path $PlatformDir "backend\.env"

Write-Host "1. Verifying AWS credentials..." -ForegroundColor Cyan
$Caller = aws sts get-caller-identity --output json | ConvertFrom-Json
if (-not $Caller.Account) {
    throw "No valid AWS credentials found. Set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY (and AWS_SESSION_TOKEN)."
}
Write-Host "   Authenticated as $($Caller.Arn) in account $($Caller.Account)" -ForegroundColor Green

Write-Host "2. Deploying bootstrap (S3 state bucket + GitHub OIDC role)..." -ForegroundColor Cyan
Push-Location $BootstrapDir
try {
    terraform init -input=false
    terraform apply -auto-approve -var="aws_region=$Region" -var="github_repo=$GitHubRepo"
    $StateBucket = terraform output -raw state_bucket_name
    $StateBucketArn = terraform output -raw state_bucket_arn
    $CiRoleArn = terraform output -raw ci_role_arn
} finally {
    Pop-Location
}

Write-Host "3. Deploying MSP Platform & Agent IAM roles + ECR + ECS cluster..." -ForegroundColor Cyan
Push-Location $PlatformInfraDir
try {
    terraform init -input=false
    terraform apply -auto-approve `
        -var="aws_region=$Region" `
        -var="state_bucket_arn=$StateBucketArn" `
        -var="github_repo=$GitHubRepo" `
        -var="github_token=$GitHubToken" `
        -var="deploy_ecs_service=false"
    $InvestigatorRoleArn = terraform output -raw investigator_role_arn
    $EcrUrl = terraform output -raw ecr_repository_url
} finally {
    Pop-Location
}

Write-Host "4. Writing msp-platform/backend/.env..." -ForegroundColor Cyan
@"
MSP_DATABASE_URL=sqlite:///./msp.db
MSP_AWS_REGION=$Region
MSP_INVESTIGATOR_ROLE_ARN=$InvestigatorRoleArn
MSP_GITHUB_REPO=$(if ($GitHubRepo -ne "owner/msp-sandbox-infra") { $GitHubRepo } else { "" })
MSP_GITHUB_TOKEN=$GitHubToken
MSP_STRANDS_MODEL_ID=us.anthropic.claude-sonnet-4-20250514-v1:0
MSP_CLAUDE_USE_BEDROCK=true
MSP_CLAUDE_MODEL=us.anthropic.claude-sonnet-4-20250514-v1:0
MSP_AWS_MCP_ENABLED=true
"@ | Set-Content -Path $BackendEnvFile -Encoding UTF8

if ($DeployContainer) {
    Write-Host "5. Building & pushing Agent + Platform container to ECR ($EcrUrl)..." -ForegroundColor Cyan
    $EcrRegistry = $EcrUrl.Split("/")[0]
    aws ecr get-login-password --region $Region | docker login --username AWS --password-stdin $EcrRegistry
    Push-Location $PlatformDir
    try {
        docker build -t "${EcrUrl}:latest" .
        docker push "${EcrUrl}:latest"
    } finally {
        Pop-Location
    }

    Write-Host "   Enabling ECS Fargate service..." -ForegroundColor Cyan
    Push-Location $PlatformInfraDir
    try {
        terraform apply -auto-approve `
            -var="aws_region=$Region" `
            -var="state_bucket_arn=$StateBucketArn" `
            -var="github_repo=$GitHubRepo" `
            -var="github_token=$GitHubToken" `
            -var="deploy_ecs_service=true"
    } finally {
        Pop-Location
    }
}

if ($DeploySandboxInfra) {
    Write-Host "6. Deploying sandbox AWS infrastructure (VPC, Subnets, SGs, EC2, RDS)..." -ForegroundColor Cyan
    Push-Location $SandboxInfraDir
    try {
        terraform init -input=false -backend-config="bucket=$StateBucket"
        terraform apply -auto-approve -var="aws_region=$Region"
    } finally {
        Pop-Location
    }
}

Write-Host ""
Write-Host "Deployment Summary:" -ForegroundColor Green
Write-Host "  State Bucket         : $StateBucket"
Write-Host "  GitHub OIDC CI Role  : $CiRoleArn"
Write-Host "  Investigator Role ARN: $InvestigatorRoleArn"
Write-Host "  ECR Repository       : $EcrUrl"
