# run_all.ps1 - Start ML engine, dashboard and optional agent (Windows-friendly)
param(
  [switch]$NoAgent
)
# Use the script directory as project root for robust behavior when launched from elsewhere
if ($PSScriptRoot) { $Root = $PSScriptRoot } else { $Root = Get-Location }
$VenvPy = Join-Path $Root '.venv\Scripts\python.exe'
$VenvPy = (Test-Path $VenvPy) ? $VenvPy : 'python'
$LogDir = Join-Path $Root 'logs'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }

Write-Output "Starting ML engine on port 5001..."
try {
  Start-Process -NoNewWindow -FilePath $VenvPy -ArgumentList '-m','uvicorn','app.main:app','--host','0.0.0.0','--port','5001' -WorkingDirectory (Join-Path $Root 'ml-engine') -ErrorAction Stop
  Start-Sleep -Milliseconds 500
  Write-Output "Starting Dashboard on port 8000..."
  Start-Process -NoNewWindow -FilePath $VenvPy -ArgumentList '-m','uvicorn','app.main:app','--host','0.0.0.0','--port','8000' -WorkingDirectory (Join-Path $Root 'dashboard-api') -ErrorAction Stop
  Start-Sleep -Milliseconds 500
} catch {
  Write-Output "Failed to start services with python path '$VenvPy': $($_.Exception.Message)"
  Write-Output 'Try creating a virtualenv at .venv or run the services manually.'
  exit 1
}
if (-not $NoAgent) {
  $agentScript = Join-Path $Root 'agent\run_agent_simulator.py'
  if (Test-Path $agentScript) {
    Write-Output 'Starting agent simulator...'
    Start-Process -NoNewWindow -FilePath $VenvPy -ArgumentList $agentScript -WorkingDirectory (Join-Path $Root 'agent')
  } else {
    Write-Output 'No agent simulator found; skipping.'
  }
} else { Write-Output 'Agent startup skipped by flag' }

Write-Output "All services started. Open http://localhost:8000/"
