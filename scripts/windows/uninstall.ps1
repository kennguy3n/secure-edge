# Secure Edge Windows uninstall hook.
#
# Invoked by the MSI custom action during a "remove" transaction. Runs
# in the system context. Tasks:
#   1. Restore the original DNS settings via configure-dns.ps1 restore.
#   2. Stop and delete the Windows service.
#   3. Remove ProgramData\SecureEdge\ (config, rules, sqlite db).
#
# This script intentionally does NOT remove the installed program
# files — the MSI engine handles that.

$ErrorActionPreference = 'Continue'
$dataDir = Join-Path $env:ProgramData 'SecureEdge'

try {
    & (Join-Path $PSScriptRoot 'configure-dns.ps1') -Action restore
} catch {
    # Restoring DNS is best-effort: continue to remove the service.
}

if (Get-Service -Name 'SecureEdge' -ErrorAction SilentlyContinue) {
    Stop-Service -Name 'SecureEdge' -Force -ErrorAction SilentlyContinue
    & sc.exe delete 'SecureEdge' | Out-Null
}

if (Test-Path $dataDir) {
    Remove-Item -Recurse -Force -Path $dataDir -ErrorAction SilentlyContinue
}

exit 0
