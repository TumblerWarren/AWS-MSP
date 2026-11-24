# Copy the stdlib-only msp_policy package into msp-sandbox-infra/scripts/msp_policy
# so GitHub Actions workflows always run the exact same deterministic policy gate.
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Src = Join-Path $Root "msp-platform\packages\msp_policy\msp_policy"
$Dst = Join-Path $Root "msp-sandbox-infra\scripts\msp_policy"

if (Test-Path $Dst) {
    Remove-Item -Recurse -Force $Dst
}
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Dst) | Out-Null
Copy-Item -Recurse -Force $Src $Dst
Get-ChildItem -Recurse -Directory -Filter "__pycache__" $Dst | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Synced msp_policy -> $Dst"
