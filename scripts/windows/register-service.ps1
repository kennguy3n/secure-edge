<#
.SYNOPSIS
    Register the Secure Edge Go agent as a Windows Service.

.DESCRIPTION
    Creates a Windows Service named "SecureEdgeAgent" that runs the agent
    binary with the bundled config. Equivalent shell-level command:

        sc.exe create SecureEdgeAgent ^
            binPath= "\"C:\Program Files\Secure Edge\secure-edge-agent.exe\" --config \"C:\ProgramData\Secure Edge\config.yaml\"" ^
            start= auto ^
            DisplayName= "Secure Edge Agent"

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
    [string]$BinaryPath = 'C:\Program Files\Secure Edge\secure-edge-agent.exe',
    [string]$ConfigPath = 'C:\ProgramData\Secure Edge\config.yaml',
    [string]$ServiceName = 'SecureEdgeAgent',
    [string]$DisplayName = 'Secure Edge Agent'
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
