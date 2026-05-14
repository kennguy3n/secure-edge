# Build a Secure Edge MSI installer using WiX Toolset.
#
# This script targets WiX v4+ (currently v7 on hosted runners) and
# uses the native <Files Include="..."> element in secure-edge.wxs to
# pick up the rules folder, so no separate `heat` harvest step is
# required (heat was removed in WiX v4).
#
# Inputs (environment or parameters):
#   -AgentExePath  Path to the freshly-built secure-edge-agent.exe.
#   -Version       Product version (semver-style, e.g. 1.2.3).
#   -OutputPath    Where to write the .msi. Defaults to dist/windows/.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $AgentExePath,
    [Parameter(Mandatory = $true)] [string] $Version,
    [string] $OutputPath = (Join-Path $PSScriptRoot '..\..\dist\windows')
)

$ErrorActionPreference = 'Stop'
# Native commands (wix.exe etc.) propagate non-zero exit codes as
# terminating errors when this is set, matching $ErrorActionPreference.
$PSNativeCommandUseErrorActionPreference = $true

if (-not (Test-Path $AgentExePath)) {
    throw "secure-edge-agent.exe not found at: $AgentExePath"
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$wxsPath  = Join-Path $PSScriptRoot 'secure-edge.wxs'
$rulesDir = Join-Path $repoRoot 'rules'

New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null

if (-not (Test-Path $rulesDir)) {
    throw "rules directory not found at: $rulesDir"
}

$msiPath = Join-Path $OutputPath "secure-edge-$Version.msi"

# No -ext is required: secure-edge.wxs only uses the core WiX schema
# (Package, ComponentGroup, Files, StandardDirectory, ServiceInstall,
# ServiceControl) — no util: / fw: / etc. namespace elements.
wix build $wxsPath `
    -d "ProductVersion=$Version" `
    -d "AgentExePath=$AgentExePath" `
    -d "RulesSourceDir=$rulesDir" `
    -out $msiPath

Write-Host "Wrote $msiPath"
