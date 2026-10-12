param(
  [Parameter(Mandatory = $true)][Guid]$RepairId,
  [switch]$Apply
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$envPath = Join-Path $root '.env'
if (-not (Test-Path -LiteralPath $envPath)) { throw 'Missing .env. Run scripts/init-env.ps1 first.' }

$token = $null
foreach ($line in Get-Content -LiteralPath $envPath) {
  if ($line -match '^CONTROL_API_TOKEN=(.+)$') { $token = $Matches[1]; break }
}
if (-not $token) { throw 'CONTROL_API_TOKEN is missing from .env.' }

$headers = @{ Authorization = "Bearer $token" }
$baseUrl = 'http://127.0.0.1:8002'
$null = Invoke-RestMethod -Uri "$baseUrl/health/ready" -TimeoutSec 5
$repair = Invoke-RestMethod -Uri "$baseUrl/api/v1/repairs/$RepairId" -Headers $headers -TimeoutSec 10
if ($repair.status -ne 'approved_for_manual_lab_promotion') { throw "Repair must be approved in the dashboard first; current status: $($repair.status)." }
if ($repair.model_provider -ne 'deterministic-baseline') { throw 'This local script accepts only the reviewed deterministic lab-origin candidate.' }
if (-not $repair.checks -or @($repair.checks).Count -ne 3 -or @($repair.checks | Where-Object { $_.exit_code -ne 0 -or $_.outcome -ne 'passed' }).Count -gt 0) {
  throw 'The repair does not have a complete set of passing recorded checks.'
}
$requiredChecks = @('git diff whitespace check', 'SQL injection and benign regression', 'origin regression suite')
$checkNames = @($repair.checks | ForEach-Object { [string]$_.test_name })
if (@($requiredChecks | Where-Object { $_ -notin $checkNames }).Count -gt 0) {
  throw 'The repair is missing one or more required validation records.'
}
if (-not $repair.diff) { throw 'The approved repair has no saved diff.' }

$diffPaths = @([regex]::Matches([string]$repair.diff, '(?m)^diff --git a/(.*?) b/(.*?)\r?$'))
if ($diffPaths.Count -ne 1 -or $diffPaths[0].Groups[1].Value -ne 'services/lab-origin/app/main.py' -or $diffPaths[0].Groups[2].Value -ne 'services/lab-origin/app/main.py') {
  throw 'The repair diff must change only services/lab-origin/app/main.py.'
}
if ([regex]::IsMatch([string]$repair.diff, '(?m)^(rename from|rename to|copy from|copy to|new file mode|deleted file mode|GIT binary patch)')) {
  throw 'The repair diff contains an unsupported file operation.'
}

$diffFile = Join-Path ([System.IO.Path]::GetTempPath()) "counterflow-$RepairId.diff"
$utf8 = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText($diffFile, [string]$repair.diff, $utf8)
try {
  git -C $root apply --check --ignore-space-change --ignore-whitespace -- $diffFile
  if ($LASTEXITCODE -ne 0) { throw 'The approved diff does not cleanly apply to the current lab source.' }
  if (-not $Apply) {
    Write-Output "Approved repair $RepairId is ready and applies cleanly to services/lab-origin/app/main.py."
    Write-Output 'Preview the diff in the dashboard. Pass -Apply to apply it and run the origin regression checks.'
    exit 0
  }

  git -C $root apply --ignore-space-change --ignore-whitespace -- $diffFile
  if ($LASTEXITCODE -ne 0) { throw 'Git could not apply the approved diff.' }
  $python = Join-Path $root '.venv\Scripts\python.exe'
  if (-not (Test-Path -LiteralPath $python)) {
    git -C $root apply -R --ignore-space-change --ignore-whitespace -- $diffFile
    throw 'Workspace Python environment is missing; the patch was reverted. Create .venv and install requirements.txt.'
  }
  Push-Location $root
  $savedPythonPath = $env:PYTHONPATH
  Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
  try {
    & $python -m pytest -q -m safe_after_patch services/lab-origin/tests
    $safeExit = $LASTEXITCODE
    & $python -m pytest -q -m 'not baseline_only and not safe_after_patch' services/lab-origin/tests
    $suiteExit = $LASTEXITCODE
    if ($safeExit -ne 0 -or $suiteExit -ne 0) {
      git -C $root apply -R --ignore-space-change --ignore-whitespace -- $diffFile
      if ($LASTEXITCODE -ne 0) { throw 'Regression checks failed and automatic rollback also failed; inspect the lab-origin source immediately.' }
      throw 'Regression checks failed; the patch was reverted.'
    }
  }
  finally {
    Pop-Location
    if ($null -ne $savedPythonPath) { $env:PYTHONPATH = $savedPythonPath }
  }
  Write-Output 'Approved lab-origin patch applied and both regression suites passed. No image or container was changed.'
}
finally {
  Remove-Item -LiteralPath $diffFile -Force -ErrorAction SilentlyContinue
}
