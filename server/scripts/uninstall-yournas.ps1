# Undoes the system changes of install-yournas.ps1. Never deletes the storage root or any file in
# it, the code folder, the venv or the backups. Each step asks first. Run from an ELEVATED
# PowerShell:
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File C:\YourNAS\server\scripts\uninstall-yournas.ps1
#
# Permissions go back to "inherit from the parent folder" (Windows' default for a new folder).
# The exact earlier permissions are in install-backup\*.acl; restore one by hand with
#   icacls <parent folder of it> /restore <file.acl>

$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'host-common.ps1')

function Ask([string]$question) {
    Write-Host ''
    Write-Host "== $question" -ForegroundColor Cyan
    return (Read-Host '   Do this now? (y/n)') -match '^\s*(y|yes)\s*$'
}

if (-not (Test-Admin)) {
    [Console]::Error.WriteLine('uninstall-yournas: run this from an elevated PowerShell (Run as administrator).')
    exit 1
}

if (Ask "1. Stop YourNAS and delete the scheduled task $TaskName") {
    if (-not (Stop-YourNAS)) { Write-Host '   some processes are still running; see stop-yournas.ps1' -ForegroundColor Red }
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    Write-Host '   done'
}

# The oldest backup holds the values from before the first install.
$firstPower = Get-ChildItem -LiteralPath $BackupDir -Filter 'power-*.json' -ErrorAction SilentlyContinue |
    Sort-Object Name | Select-Object -First 1
if ($firstPower -and (Ask "2. Power: plugged-in lid and sleep values back to $($firstPower.Name)")) {
    $old = Get-Content -LiteralPath $firstPower.FullName -Raw | ConvertFrom-Json
    powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION $old.lid.AC
    powercfg /setacvalueindex SCHEME_CURRENT SUB_SLEEP STANDBYIDLE $old.standby.AC
    powercfg /setacvalueindex SCHEME_CURRENT SUB_SLEEP HIBERNATEIDLE $old.hibernate.AC
    powercfg /setactive SCHEME_CURRENT
    Write-Host '   done'
}

$cfg = $null
if (Test-Path -LiteralPath $ConfigPath -PathType Leaf) { $cfg = Read-YourNASConfig $ConfigPath }
if (Ask "3. Permissions back to inherited: storage root, $RepoDir, log/data folders, Python folder") {
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ($cfg -and $cfg.StorageRoot -and (Test-Path -LiteralPath $cfg.StorageRoot)) {
        icacls $cfg.StorageRoot /reset /T /C /Q
        icacls $cfg.StorageRoot /setowner "*$me" /T /C /Q
    }
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        # Inherited permissions let every local user change the code; the task would then run it.
        Write-Host "   $RepoDir kept locked: the task $TaskName still exists (answer y at step 1 first)" -ForegroundColor Yellow
    } else {
        icacls $RepoDir /reset /T /C /Q
        Write-Host "   note: every local user can now change files in $RepoDir; do not run its scripts elevated" -ForegroundColor Yellow
    }
    if ($cfg) {
        foreach ($dir in @($cfg.LogDir, $cfg.DataDir)) {
            if ($dir -and (Test-Path -LiteralPath $dir)) { icacls $dir /remove:g $ServiceUser /T /C /Q }
        }
    }
    $found = & py -3.12 -c 'import sys; print(sys.base_prefix)' 2>$null
    if ($LASTEXITCODE -eq 0 -and $found) { icacls "$found".Trim() /remove:g $ServiceUser /T /C /Q }
    Write-Host '   done'
}

if ((Get-LocalUser -Name $ServiceUser -ErrorAction SilentlyContinue) -and
    (Ask "4. Remove the batch logon right, the local account $ServiceUser and its profile folder (no YourNAS data)")) {
    $sid = (Get-LocalUser -Name $ServiceUser).SID.Value
    Edit-BatchLogonRight $sid -Remove
    Remove-LocalUser -Name $ServiceUser
    Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sid } | Remove-CimInstance
    Remove-ItemProperty -Path $HiddenUsersKey -Name $ServiceUser -ErrorAction SilentlyContinue
    Write-Host '   done'
}

Write-Host ''
Write-Host "Finished. Data in the storage root and the backups in $BackupDir were not touched."
