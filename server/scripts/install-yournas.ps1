# Installs YourNAS on this Windows machine so it runs at boot without anyone logged in.
# Read it before running it. Run from an ELEVATED Windows PowerShell:
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File C:\YourNAS\server\scripts\install-yournas.ps1
#
# -DryRun prints every step and changes nothing (no elevation needed).
# -SkipTests skips the test suite (only for a re-run after it passed once).
#
# Steps 1-3 only touch the code folder: its permissions are locked first (inheritance off, so other
# local users cannot change code this elevated script runs), then venv, tests, config.local.json.
# Steps 4-8 change the system, and each asks first and can be answered "n":
#   4 local account yournas-svc (random password nobody sees; hidden from the sign-in screen)
#   5 NTFS permissions: only yournas-svc (plus SYSTEM and elevated Administrators) can write the
#     storage root, its .yournas-data and .yournas-tmp; the code folder is read-only for it
#   6 owner account of the app (python -m yournas create-owner)
#   7 scheduled task "YourNAS": at boot, as yournas-svc, start-yournas.ps1 -KeepRunning
#   8 power: closing the lid does nothing and the machine never sleeps while plugged in
# Never touched: the firewall, Tailscale, SMB, network settings, the files inside the storage root.
# The storage root is never created or deleted. Old permissions and power values are saved in
# install-backup\ first; uninstall-yournas.ps1 undoes steps 4, 5, 7 and 8.
param(
    [switch]$DryRun,
    [switch]$SkipTests,
    [string]$PythonVersion = '3.12'
)

$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'host-common.ps1')

$script:Problems = 0

function Say([string]$text, [string]$color = 'Gray') { Write-Host $text -ForegroundColor $color }

function Stop-Install([string]$why) {
    if ($DryRun) {
        Say "   [dry run] a real run would stop here: $why" Yellow
        $script:Problems++
        return
    }
    Say "STOPPED: $why" Red
    exit 1
}

function Invoke-Step([string]$title, [string[]]$plan, [scriptblock]$action, [switch]$Ask) {
    Say ''
    Say "== $title" Cyan
    foreach ($line in $plan) { Say "   $line" }
    if ($DryRun) { Say '   [dry run] nothing changed'; return $false }
    if ($Ask) {
        $answer = Read-Host '   Do this now? (y/n)'
        if ($answer -notmatch '^\s*(y|yes)\s*$') { Say '   skipped' Yellow; return $false }
    }
    try {
        & $action | Out-Host
    } catch {
        Say "   FAILED: $($_.Exception.Message)" Red
        Say '   Later steps were not run. Fix the cause and run the script again.' Red
        exit 1
    }
    return $true
}

function New-ServicePassword {
    # 24 random bytes as base64, with a prefix that meets the Windows complexity rule.
    $bytes = New-Object byte[] 24
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    return 'Yn!' + [Convert]::ToBase64String($bytes)
}

function Get-ServiceAccount { Get-LocalUser -Name $ServiceUser -ErrorAction SilentlyContinue }

function Set-CodeFolderAcl {
    # A folder made under C:\ inherits "Authenticated Users: Modify", so any local user could
    # plant code that this elevated script would then run. Inheritance off: SYSTEM,
    # Administrators and the installing user full; yournas-svc read (and modify on the log and
    # data folders) once it exists, so a re-run never takes the running server's access away.
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $grants = @("${SidSystem}:(OI)(CI)F", "${SidAdministrators}:(OI)(CI)F", "*${me}:(OI)(CI)F")
    $svc = Get-ServiceAccount
    if ($svc) { $grants += "${ServiceUser}:(OI)(CI)RX" }
    Invoke-Native 'icacls' @($RepoDir, '/reset', '/T', '/C', '/Q')
    Invoke-Native 'icacls' (@($RepoDir, '/inheritance:r', '/grant:r') + $grants + @('/Q'))
    if ($svc) {
        foreach ($dir in $writable) {
            New-Item -ItemType Directory -Force -Path $dir | Out-Null
            Invoke-Native 'icacls' @($dir, '/grant', "${ServiceUser}:(OI)(CI)M", '/Q')
        }
    }
}

function Clear-YourNASEnv {
    Get-ChildItem Env: | Where-Object { $_.Name -like 'YOURNAS_*' } |
        ForEach-Object { Remove-Item -LiteralPath ("Env:" + $_.Name) }
}

# ---- 0. checks ---------------------------------------------------------------------------------

Say "YourNAS install  (code: $RepoDir)" White
if ($DryRun) { Say 'DRY RUN: nothing will be changed.' Yellow }

if (-not $DryRun -and -not (Test-Admin)) {
    Say 'STOPPED: run this from an elevated PowerShell (Run as administrator).' Red
    exit 1
}

$usersRoot = Split-Path -Parent $env:PUBLIC
if (Test-PathInside $RepoDir $usersRoot) {
    Stop-Install "the code is under $usersRoot; $ServiceUser cannot read user folders. Move it to C:\YourNAS."
}

$pythonHome = $null
$found = & py "-$PythonVersion" -c 'import sys; print(sys.base_prefix)' 2>$null
if ($LASTEXITCODE -eq 0 -and $found) {
    $pythonHome = "$found".Trim()
    Say "Python $PythonVersion found: $pythonHome"
} else {
    Stop-Install "py -$PythonVersion does not work. Install Python $PythonVersion first."
}
$pythonForOneUser = [bool]($pythonHome -and (Test-PathInside $pythonHome $usersRoot))

$configSource = $ConfigPath
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    $configSource = Join-Path $ServerDir 'config.example.json'
}
$cfg = Read-YourNASConfig $configSource
Say "Config ($configSource): storage root $($cfg.StorageRoot), $($cfg.Host):$($cfg.Port), logs $($cfg.LogDir)"

if (-not $cfg.StorageRoot) {
    Stop-Install 'storage_root is not set in the config.'
} elseif (-not (Test-Path -LiteralPath $cfg.StorageRoot -PathType Container)) {
    Stop-Install "the storage root $($cfg.StorageRoot) does not exist. Create it yourself; this script never creates it."
} elseif ((Test-PathInside $RepoDir $cfg.StorageRoot) -or (Test-PathInside $cfg.StorageRoot $RepoDir)) {
    Stop-Install 'the code folder and the storage root must not contain each other.'
}
if ($cfg.Host -notin '127.0.0.1', 'localhost', '::1') {
    Stop-Install "host is $($cfg.Host); it must be loopback (127.0.0.1). Tailscale Serve is the only way in."
}

# Folders yournas-svc must write besides the storage root (which holds .yournas-data and
# .yournas-tmp unless data_dir says otherwise).
$writable = @()
if ($cfg.LogDir) { $writable += [string]$cfg.LogDir }
if ($cfg.DataDir -and -not (Test-PathInside $cfg.DataDir $cfg.StorageRoot)) { $writable += [string]$cfg.DataDir }

# ---- 1-3. code folder only ---------------------------------------------------------------------

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

$null = Invoke-Step '1. Lock the code folder, then Python venv and packages' @(
    "save the permissions of $RepoDir to $BackupDir\code-$stamp.acl",
    "${RepoDir}: inheritance off; SYSTEM, Administrators and $env:USERNAME full ($ServiceUser read once it exists)",
    '    (before any code from it runs elevated: by default every local user may change a folder under C:\)',
    "py -$PythonVersion -m venv $ServerDir\.venv   (only if it does not exist)",
    'pip install -c constraints.txt -e .[dev]   (the exact versions the tests passed with)'
) {
    New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
    Invoke-Native 'icacls' @($RepoDir, '/save', "$BackupDir\code-$stamp.acl", '/T', '/C', '/Q')
    Set-CodeFolderAcl
    if (-not (Test-Path -LiteralPath $VenvPython -PathType Leaf)) {
        Invoke-Native 'py' @("-$PythonVersion", '-m', 'venv', (Join-Path $ServerDir '.venv'))
    }
    Push-Location -LiteralPath $ServerDir
    try {
        Invoke-Native $VenvPython @('-m', 'pip', 'install', '--disable-pip-version-check', '-q',
            '-c', 'constraints.txt', '-e', '.[dev]')
    } finally { Pop-Location }
}

if (-not $SkipTests) {
    $null = Invoke-Step '2. Test suite (several minutes on this machine)' @(
        'python -m pytest -q -p no:cacheprovider   (stops the install if anything fails)'
    ) {
        Push-Location -LiteralPath $ServerDir
        try {
            # Tests set their own settings; inherited YOURNAS_* variables must not leak in.
            Clear-YourNASEnv
            & $VenvPython -m pytest -q -p no:cacheprovider
            if ($LASTEXITCODE -ne 0) {
                Stop-Install "the test suite failed (exit $LASTEXITCODE). Only the code folder's permissions were changed."
            }
        } finally { Pop-Location }
    }
}

$null = Invoke-Step '3. config.local.json' @(
    "copy config.example.json to $ConfigPath   (only if it does not exist; never overwritten)"
) {
    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
        Copy-Item -LiteralPath (Join-Path $ServerDir 'config.example.json') -Destination $ConfigPath
        Say '   created from the template'
    } else {
        Say '   exists, kept as it is'
    }
}

if (-not $DryRun) {
    foreach ($dir in $writable) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
}

# ---- 4-8. system changes, each asked -----------------------------------------------------------

$null = Invoke-Step "4. Local account $ServiceUser" @(
    "create a standard (non-admin) local user $ServiceUser with a random password nobody sees",
    'password never expires; hidden from the sign-in screen',
    'if it already exists: left as it is'
) -Ask {
    if (Get-ServiceAccount) {
        Say "   $ServiceUser exists, kept"
    } else {
        $secure = ConvertTo-SecureString (New-ServicePassword) -AsPlainText -Force
        New-LocalUser -Name $ServiceUser -Password $secure -PasswordNeverExpires `
            -UserMayNotChangePassword -AccountNeverExpires `
            -Description 'YourNAS server (scheduled task YourNAS)' -ErrorAction Stop | Out-Null
        Say "   $ServiceUser created"
    }
    if (-not (Test-Path $HiddenUsersKey)) { New-Item -Path $HiddenUsersKey -Force | Out-Null }
    New-ItemProperty -Path $HiddenUsersKey -Name $ServiceUser -Value 0 -PropertyType DWord -Force | Out-Null
}

$aclPlan = @(
    "save current permissions to $BackupDir\storage-root-$stamp.acl",
    "$($cfg.StorageRoot): inheritance off, owner Administrators; SYSTEM and Administrators full,",
    "    $ServiceUser modify, nobody else; everything inside inherits it (elevated admin still reads)",
    "${RepoDir}: as in step 1, now with $ServiceUser read"
)
foreach ($dir in $writable) { $aclPlan += "${dir}: add $ServiceUser modify" }
if ($pythonForOneUser) { $aclPlan += "${pythonHome}: add $ServiceUser read (Python is installed for one user only)" }
$aclDone = Invoke-Step '5. NTFS permissions' $aclPlan -Ask {
    if (-not (Get-ServiceAccount)) { throw "$ServiceUser does not exist; answer y at step 4 first" }
    $root = [IO.Path]::GetFullPath($cfg.StorageRoot).TrimEnd('\')
    Invoke-Native 'icacls' @($root, '/save', "$BackupDir\storage-root-$stamp.acl", '/T', '/C', '/Q')
    # Children back to inherit-only first, then the folder's own list is replaced.
    Invoke-Native 'icacls' @($root, '/reset', '/T', '/C', '/Q')
    Invoke-Native 'icacls' @($root, '/inheritance:r', '/grant:r',
        "${SidSystem}:(OI)(CI)F", "${SidAdministrators}:(OI)(CI)F", "${ServiceUser}:(OI)(CI)M", '/Q')
    Invoke-Native 'icacls' @($root, '/setowner', $SidAdministrators, '/T', '/C', '/Q')
    Set-CodeFolderAcl
    if ($pythonForOneUser) {
        Invoke-Native 'icacls' @($pythonHome, '/grant', "${ServiceUser}:(OI)(CI)RX", '/Q')
    }
    Say '   storage root now:'
    icacls $root
}

$null = Invoke-Step '6. Owner account of the app' @(
    'python -m yournas create-owner   (asks for a username and a password here, hidden)',
    'answer n if you created the owner before'
) -Ask {
    Clear-YourNASEnv
    $env:YOURNAS_CONFIG = $ConfigPath
    Push-Location -LiteralPath $ServerDir
    try { & $VenvPython -m yournas create-owner } finally {
        Pop-Location
        Remove-Item Env:YOURNAS_CONFIG -ErrorAction SilentlyContinue
    }
}

$taskArgs = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$StartScript`" -Config `"$ConfigPath`" -KeepRunning"
$null = Invoke-Step "7. Scheduled task $TaskName (start at boot)" @(
    "stop and replace an existing $TaskName task",
    "give $ServiceUser the right 'Log on as a batch job' (a task with a stored password needs it)",
    "give $ServiceUser a new random password (kept only inside Task Scheduler)",
    "task: at startup, as $ServiceUser, no time limit, normal priority, also on battery",
    "runs: powershell $taskArgs",
    "then start it and check http://127.0.0.1:$($cfg.Port)/health"
) -Ask {
    if (-not (Get-ServiceAccount)) { throw "$ServiceUser does not exist; answer y at step 4 first" }
    if (-not $aclDone) { Say '   note: step 5 was skipped in this run; the server needs those permissions' Yellow }
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        if (-not (Stop-YourNAS)) { throw 'the running server did not stop' }
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    Edit-BatchLogonRight (Get-ServiceAccount).SID.Value
    $password = New-ServicePassword
    Set-LocalUser -Name $ServiceUser -Password (ConvertTo-SecureString $password -AsPlainText -Force)
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Argument $taskArgs -WorkingDirectory $ServerDir
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -Priority 4
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
        -User "$env:COMPUTERNAME\$ServiceUser" -Password $password -RunLevel Limited `
        -Description 'YourNAS file server (loopback only; reached through Tailscale Serve)' -ErrorAction Stop | Out-Null
    $password = $null
    Start-ScheduledTask -TaskName $TaskName
    $url = "http://127.0.0.1:$($cfg.Port)/health"
    $deadline = (Get-Date).AddSeconds(60)
    $ok = $false
    while (-not $ok -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 2
        try {
            $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 3
            $ok = $r.StatusCode -eq 200
            if ($ok) { Say "   $url -> $($r.StatusCode) $($r.Content)" Green }
        } catch { }
    }
    if (-not $ok) {
        $info = Get-ScheduledTaskInfo -TaskName $TaskName
        Say ("   server did not answer within 60 s; task last result 0x{0:X8}" -f $info.LastTaskResult) Red
        if ($cfg.LogDir) {
            foreach ($name in 'supervisor.log', 'yournas.log') {
                $file = Join-Path $cfg.LogDir $name
                if (Test-Path -LiteralPath $file) { Say "   last lines of ${file}:"; Get-Content -LiteralPath $file -Tail 15 }
            }
        }
        $script:Problems++
    }
}

$null = Invoke-Step '8. Power: lid and sleep (plugged in only)' @(
    "save current values to $BackupDir\power-$stamp.json",
    'plugged in: closing the lid does nothing, never sleep, never hibernate (active power plan)',
    'on battery: unchanged'
) -Ask {
    $before = [pscustomobject]@{
        lid       = Get-PowerIndex 'SUB_BUTTONS' 'LIDACTION'
        standby   = Get-PowerIndex 'SUB_SLEEP' 'STANDBYIDLE'
        hibernate = Get-PowerIndex 'SUB_SLEEP' 'HIBERNATEIDLE'
    }
    $before | ConvertTo-Json | Set-Content -LiteralPath "$BackupDir\power-$stamp.json" -Encoding UTF8
    Invoke-Native 'powercfg' @('/setacvalueindex', 'SCHEME_CURRENT', 'SUB_BUTTONS', 'LIDACTION', '0')
    Invoke-Native 'powercfg' @('/setacvalueindex', 'SCHEME_CURRENT', 'SUB_SLEEP', 'STANDBYIDLE', '0')
    Invoke-Native 'powercfg' @('/setacvalueindex', 'SCHEME_CURRENT', 'SUB_SLEEP', 'HIBERNATEIDLE', '0')
    Invoke-Native 'powercfg' @('/setactive', 'SCHEME_CURRENT')
    $lid = Get-PowerIndex 'SUB_BUTTONS' 'LIDACTION'
    $standby = Get-PowerIndex 'SUB_SLEEP' 'STANDBYIDLE'
    Say "   plugged in now: lid action $($lid.AC) (0 = do nothing), sleep after $($standby.AC) s (0 = never)"
}

Say ''
if ($DryRun) {
    Say "Dry run finished: $script:Problems problem(s) a real run would stop on." White
} elseif ($script:Problems -gt 0) {
    Say "Finished with $script:Problems problem(s); see the red lines above." Red
    exit 1
} else {
    Say 'Finished. Stop the server: scripts\stop-yournas.ps1. Undo steps 4, 5, 7, 8: scripts\uninstall-yournas.ps1.' Green
}
