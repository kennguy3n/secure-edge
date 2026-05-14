<#
.SYNOPSIS
    Register the Secure Edge Go agent as a Windows Service.

.DESCRIPTION
    Creates a Windows Service named "SecureEdge" that runs the agent
    binary with the bundled config. The service name, display name,
    and install paths must match scripts/windows/secure-edge.wxs so an
    MSI install and a hand-run of this script produce the same service
    registration. Equivalent shell-level command:

        sc.exe create SecureEdge ^
            binPath= "\"C:\Program Files\SecureEdge\bin\secure-edge-agent.exe\" --config \"C:\ProgramData\SecureEdge\config.yaml\"" ^
            start= auto ^
            DisplayName= "Secure Edge"

.PARAMETER Mode
    'install'   — create and start the service (default)
    'uninstall' — stop and remove the service

.EXAMPLE
    PS> .\register-service.ps1 install
    PS> .\register-service.ps1 uninstall

.NOTES
    Run from an elevated PowerShell session.
#>

[CmdletBinding()]
param(
    [ValidateSet('install','uninstall')]
    [string]$Mode = 'install',
    [string]$BinaryPath = 'C:\Program Files\SecureEdge\bin\secure-edge-agent.exe',
    [string]$ConfigPath = 'C:\ProgramData\SecureEdge\config.yaml',
    [string]$ServiceName = 'SecureEdge',
    [string]$DisplayName = 'Secure Edge'
)

function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Error 'register-service.ps1 must be run from an elevated PowerShell session.'
        exit 1
    }
}

function Install-Service {
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Write-Host "secure-edge: service '$ServiceName' already exists; leaving it in place."
        return
    }
    $binPath = "`"$BinaryPath`" --config `"$ConfigPath`""
    Write-Host "secure-edge: creating service '$ServiceName' -> $binPath"
    New-Service -Name $ServiceName -BinaryPathName $binPath -DisplayName $DisplayName `
        -StartupType Automatic -Description 'Secure Edge DNS + DLP agent.'
    Start-Service -Name $ServiceName
}

function Uninstall-Service {
    if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
        Write-Host "secure-edge: service '$ServiceName' not installed."
        return
    }
    Write-Host "secure-edge: stopping and removing service '$ServiceName'"
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
}

Assert-Admin
switch ($Mode) {
    'install'   { Install-Service }
    'uninstall' { Uninstall-Service }
}
