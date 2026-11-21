# Stops the YourNAS server started by the scheduled task (for example before updating the code).
# Run from an ELEVATED PowerShell:
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File C:\YourNAS\server\scripts\stop-yournas.ps1
#
# Start it again with: Start-ScheduledTask -TaskName YourNAS   (or reboot)
# Ends the task and every process of it (supervisor, venv launcher, server). Changes nothing else.

. (Join-Path $PSScriptRoot 'host-common.ps1')

if (-not (Test-Admin)) {
    [Console]::Error.WriteLine('stop-yournas: run this from an elevated PowerShell (Run as administrator).')
    exit 1
}
if (Stop-YourNAS) {
    Write-Host 'YourNAS stopped.'
    exit 0
}
[Console]::Error.WriteLine('stop-yournas: some YourNAS processes are still running:')
Get-YourNASProcesses | ForEach-Object { [Console]::Error.WriteLine("  $($_.ProcessId) $($_.CommandLine)") }
exit 1
