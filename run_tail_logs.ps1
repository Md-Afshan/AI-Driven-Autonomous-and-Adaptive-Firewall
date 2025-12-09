# run_tail_logs.ps1 - Tail logs created by run_all scripts
param(
  [string]$File = "logs\\dashboard.log"
)
# Use script folder as base so the script can be launched from anywhere
if ($PSScriptRoot) { $Root = $PSScriptRoot } else { $Root = Get-Location }
$path = Join-Path $Root $File
if (-not (Test-Path $path)) {
  Write-Output "Log file not found: $path"
  Write-Output "Available files under $Root\logs:";
  Get-ChildItem -Path (Join-Path $Root 'logs') -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | ForEach-Object { Write-Output " - $_" }
  exit 1
}
Write-Output "Tailing $path (Ctrl-C to stop)"
try {
  Get-Content -Path $path -Wait -Tail 50
} catch {
  Write-Output "Failed to tail log: $($_.Exception.Message)"
  exit 1
}
