$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$statePath = Join-Path $root '.counterflow-state\processes.json'
if (-not (Test-Path -LiteralPath $statePath)) {
  Write-Output 'No CounterFlow process record was found.'
  exit 0
}

$records = @(Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json)
foreach ($record in $records) {
  $process = Get-CimInstance Win32_Process -Filter "ProcessId = $($record.pid)" -ErrorAction SilentlyContinue
  if (-not $process) { continue }
  $expectedPath = [string]$record.executable
  $pathMatches = [string]::Equals([string]$process.ExecutablePath, $expectedPath, [StringComparison]::OrdinalIgnoreCase)
  $commandMatches = [string]$process.CommandLine -and [string]$process.CommandLine.Contains([string]$record.marker, [StringComparison]::OrdinalIgnoreCase)
  if ($pathMatches -or $commandMatches) {
    Stop-Process -Id ([int]$record.pid) -Force -ErrorAction SilentlyContinue
    Write-Output "Stopped $($record.service)."
  } else {
    Write-Warning "Skipped process $($record.pid); it no longer matches CounterFlow's recorded executable."
  }
}
Remove-Item -LiteralPath $statePath -Force
