# Starts the YourNAS server with one explicit config file. Run by hand or by Task Scheduler.
# Changes nothing on the system: no firewall, service, task, ACL or Tailscale change.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File start-yournas.ps1 [-Config <path>] [-KeepRunning]
#
# Default config: ..\config.local.json (copy config.example.json and edit it; git-ignored).
# Exit code is the server's: 0 stopped, 1 failure, 2 configuration/storage/database problem,
# 3 another server already runs on the same data directory. The script itself exits 2 when the
# venv or the config file is missing.
#
# -KeepRunning (used by the scheduled task): start the server again after an unexpected exit
# (any code except 0, 2 and 3), after -RestartDelaySeconds. Task Scheduler does not restart a task
# whose program merely exits with an error, so the loop lives here. Each restart is appended to
# supervisor.log in the configured log_dir. -MaxRestarts 0 means no limit.
param(
    [string]$Config = (Join-Path (Split-Path -Parent $PSScriptRoot) 'config.local.json'),
    [switch]$KeepRunning,
    [int]$RestartDelaySeconds = 30,
    [int]$MaxRestarts = 0
)

$server = Split-Path -Parent $PSScriptRoot
$python = Join-Path $server '.venv\Scripts\python.exe'

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    [Console]::Error.WriteLine("start-yournas: venv not found: $python")
    [Console]::Error.WriteLine("  create it: py -3.12 -m venv .venv; .venv\Scripts\python -m pip install -e .")
    exit 2
}
if (-not (Test-Path -LiteralPath $Config -PathType Leaf)) {
    [Console]::Error.WriteLine("start-yournas: config file not found: $Config")
    exit 2
}

# The config file is the only source of settings: drop YOURNAS_* inherited from the caller.
Get-ChildItem Env: | Where-Object { $_.Name -like 'YOURNAS_*' } |
    ForEach-Object { Remove-Item -LiteralPath ("Env:" + $_.Name) }
$env:YOURNAS_CONFIG = (Resolve-Path -LiteralPath $Config).Path

$supervisorLog = $null
if ($KeepRunning) {
    try {
        $logDir = (Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json).log_dir
        if ($logDir) { $supervisorLog = Join-Path $logDir 'supervisor.log' }
    } catch {
        # An unreadable config is reported by the server itself on the first start.
    }
}

function Write-Supervisor([string]$message) {
    $line = "{0} {1}" -f (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK'), $message
    [Console]::Error.WriteLine("start-yournas: $message")
    if ($supervisorLog) {
        try { Add-Content -LiteralPath $supervisorLog -Value $line -Encoding UTF8 } catch { }
    }
}

Set-Location -LiteralPath $server
$restarts = 0
while ($true) {
    & $python -m yournas
    $code = $LASTEXITCODE
    if (-not $KeepRunning -or $code -in 0, 2, 3) { exit $code }
    if ($MaxRestarts -gt 0 -and $restarts -ge $MaxRestarts) {
        Write-Supervisor "server exited with code $code; restart limit $MaxRestarts reached, giving up"
        exit $code
    }
    $restarts++
    Write-Supervisor "server exited with code $code; restart $restarts in $RestartDelaySeconds s"
    Start-Sleep -Seconds $RestartDelaySeconds
}
