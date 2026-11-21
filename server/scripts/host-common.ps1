# Shared by install-yournas.ps1, stop-yournas.ps1 and uninstall-yournas.ps1 (dot-sourced).
# Defines names and helpers only; running this file changes nothing.

$TaskName = 'YourNAS'
$ServiceUser = 'yournas-svc'
$ServerDir = Split-Path -Parent $PSScriptRoot
$RepoDir = Split-Path -Parent $ServerDir
$VenvPython = Join-Path $ServerDir '.venv\Scripts\python.exe'
$ConfigPath = Join-Path $ServerDir 'config.local.json'
$StartScript = Join-Path $PSScriptRoot 'start-yournas.ps1'
$BackupDir = Join-Path $RepoDir 'install-backup'
$HiddenUsersKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'

# Well-known SIDs, so the scripts work on any Windows display language.
$SidSystem = '*S-1-5-18'
$SidAdministrators = '*S-1-5-32-544'

function Test-Admin {
    $principal = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-Native([string]$exe, [string[]]$arguments) {
    & $exe @arguments
    if ($LASTEXITCODE -ne 0) { throw "$(Split-Path -Leaf $exe) exited with code $LASTEXITCODE" }
}

function Read-YourNASConfig([string]$path) {
    # The keys the host scripts need, with the server's defaults. The server validates the rest.
    $raw = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $names = @($raw.PSObject.Properties | ForEach-Object { $_.Name })
    $get = {
        param($name, $default)
        if ($names -contains $name -and $null -ne $raw.$name -and "$($raw.$name)" -ne '') { $raw.$name } else { $default }
    }
    [pscustomobject]@{
        StorageRoot = & $get 'storage_root' $null
        Host        = & $get 'host' '127.0.0.1'
        Port        = [int](& $get 'port' 8000)
        LogDir      = & $get 'log_dir' $null
        DataDir     = & $get 'data_dir' $null
    }
}

function Test-PathInside([string]$child, [string]$parent) {
    $c = [IO.Path]::GetFullPath($child).TrimEnd('\') + '\'
    $p = [IO.Path]::GetFullPath($parent).TrimEnd('\') + '\'
    return $c.StartsWith($p, [StringComparison]::OrdinalIgnoreCase)
}

function Get-YourNASProcesses {
    # The supervisor (powershell running start-yournas.ps1) and the server: the venv launcher and
    # its child, the real interpreter, both started as "python -m yournas" with no subcommand.
    @(Get-CimInstance Win32_Process | Where-Object {
        $_.CommandLine -and (
            $_.CommandLine -like '*start-yournas.ps1*' -or
            $_.CommandLine -match '\s-m\s+yournas\s*$')
    })
}

function Stop-YourNAS {
    # Stops the task and then every process of it. Ending the task alone can leave the server
    # running, because the server is a grandchild of the task's PowerShell process.
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    }
    # Supervisor first, so it cannot start the server again.
    Get-YourNASProcesses | Where-Object { $_.CommandLine -like '*start-yournas.ps1*' } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Get-YourNASProcesses |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    $deadline = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $deadline) {
        if ((Get-YourNASProcesses).Count -eq 0) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return (Get-YourNASProcesses).Count -eq 0
}

function Edit-BatchLogonRight([string]$sid, [switch]$Remove) {
    # "Log on as a batch job" (SeBatchLogonRight): a task that runs as yournas-svc with a stored
    # password needs it, and Task Scheduler does NOT grant it when the task is registered (seen on
    # the Surface 2026-11-01: the task never ran, result 0x41303). Re-applies the exported user
    # rights with this one SID added or removed; every other right is written back unchanged.
    $inf = Join-Path $env:TEMP "yournas-rights-$PID.inf"
    $db = Join-Path $env:TEMP "yournas-rights-$PID.sdb"
    try {
        Invoke-Native 'secedit' @('/export', '/areas', 'USER_RIGHTS', '/cfg', $inf, '/quiet')
        $entry = "*$sid"
        $seen = $false
        $lines = foreach ($line in Get-Content -LiteralPath $inf) {
            if ($line -match '^SeBatchLogonRight\s*=\s*(.*)$') {
                $seen = $true
                $sids = @($Matches[1] -split ',' | ForEach-Object { $_.Trim() } |
                    Where-Object { $_ -and $_ -ne $entry })
                if (-not $Remove) { $sids += $entry }
                'SeBatchLogonRight = ' + ($sids -join ',')
            } else {
                $line
                if (-not $Remove -and $line -eq '[Privilege Rights]') { '#BATCH#' }
            }
        }
        $lines = @($lines | ForEach-Object {
            if ($_ -eq '#BATCH#') { if (-not $seen) { "SeBatchLogonRight = $entry" } } else { $_ }
        })
        Set-Content -LiteralPath $inf -Value $lines -Encoding Unicode
        Invoke-Native 'secedit' @('/configure', '/db', $db, '/cfg', $inf, '/areas', 'USER_RIGHTS', '/quiet')
    } finally {
        Remove-Item -LiteralPath $inf, $db -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath ([IO.Path]::ChangeExtension($db, '.jfm')) -ErrorAction SilentlyContinue
    }
}

function Get-PowerIndex([string]$subgroup, [string]$setting) {
    # Current AC and DC values of one power setting of the active plan. powercfg labels are
    # translated, so read the last two hex numbers: they are always the AC and the DC index.
    # /qh, not /q: /q leaves out hidden settings, and some power plans hide the lid action
    # (found on the Surface, 2026-11-01).
    $text = (powercfg /qh SCHEME_CURRENT $subgroup $setting) -join "`n"
    $hex = @([regex]::Matches($text, '0x[0-9a-fA-F]{8}') | ForEach-Object { $_.Value })
    if ($hex.Count -lt 2) { throw "powercfg did not report $subgroup $setting" }
    [pscustomobject]@{ AC = [Convert]::ToInt64($hex[-2], 16); DC = [Convert]::ToInt64($hex[-1], 16) }
}
