param(
  [string]$LocalModelNameOverride,
  [string]$OriginSitePath
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$envPath = Join-Path $root '.env'
$stateDir = Join-Path $root '.counterflow-state'
$statePath = Join-Path $stateDir 'processes.json'
$python = Join-Path $root '.venv\Scripts\python.exe'
$started = [System.Collections.Generic.List[object]]::new()

if (-not (Test-Path -LiteralPath $envPath)) {
  & (Join-Path $PSScriptRoot 'init-env.ps1')
}
if (Test-Path -LiteralPath $statePath) {
  $existing = @(Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json)
  $alive = @($existing | Where-Object { Get-Process -Id $_.pid -ErrorAction SilentlyContinue })
  if ($alive.Count -gt 0) { throw 'CounterFlow already has recorded processes. Run scripts/stop-local.ps1 before starting it again.' }
  Remove-Item -LiteralPath $statePath -Force
}
if (-not (Test-Path -LiteralPath $python)) { throw 'Missing .venv. Create it and install requirements.txt before starting.' }

foreach ($line in Get-Content -LiteralPath $envPath) {
  $trimmed = $line.Trim()
  if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }
  $separator = $line.IndexOf('=')
  if ($separator -lt 1) { throw 'Invalid .env line. Expected NAME=value.' }
  $name = $line.Substring(0, $separator).Trim()
  $value = $line.Substring($separator + 1)
  if ($name -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') { throw 'Invalid environment variable name in .env.' }
  [Environment]::SetEnvironmentVariable($name, $value, 'Process')
}
if ($PSBoundParameters.ContainsKey('LocalModelNameOverride')) { $env:LOCAL_MODEL_NAME = $LocalModelNameOverride }

foreach ($required in @('CONTROL_API_TOKEN', 'GATEWAY_API_TOKEN', 'POLICY_SIGNING_KEY', 'SOURCE_HASH_SALT')) {
  if (-not [Environment]::GetEnvironmentVariable($required, 'Process')) { throw "$required must be set in .env." }
}

$env:CONTROL_API_URL = if ($env:CONTROL_API_URL) { $env:CONTROL_API_URL } else { 'http://127.0.0.1:8002' }
$env:ORIGIN_URL = if ($env:ORIGIN_URL) { $env:ORIGIN_URL } else { 'http://127.0.0.1:8000' }
$env:HONEYPOT_URL = if ($env:HONEYPOT_URL) { $env:HONEYPOT_URL } else { 'http://127.0.0.1:8001' }
$env:LISTEN_ADDR = if ($env:LISTEN_ADDR) { $env:LISTEN_ADDR } else { '127.0.0.1:8080' }
$env:LAB_MODE = if ($env:LAB_MODE) { $env:LAB_MODE } else { 'lab-auto' }
$env:COUNTERFLOW_SITE_ID = if ($env:COUNTERFLOW_SITE_ID) { $env:COUNTERFLOW_SITE_ID } else { 'counterflow-site' }
$env:DATABASE_URL = if ($env:DATABASE_URL) { $env:DATABASE_URL } else { 'sqlite:///./counterflow.db' }
$env:REPAIR_ARTIFACT_DIR = if ($env:REPAIR_ARTIFACT_DIR) { $env:REPAIR_ARTIFACT_DIR } else { './repair-artifacts' }
$env:EVALUATION_DATASET = if ($env:EVALUATION_DATASET) { $env:EVALUATION_DATASET } else { 'data/evaluation/events.jsonl' }
$env:TYPESAFE_API_CONFIGURED = if ($env:TYPESAFE_API_KEY) { 'true' } else { 'false' }
$env:PYTHONPATH = @(
  (Join-Path $root 'services\common'),
  (Join-Path $root 'services\control-api'),
  (Join-Path $root 'services\detector')
) -join ';'

New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
$logDir = Join-Path $stateDir 'logs'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
Push-Location $root

function Add-ServiceProcess([string]$name, [string]$file, [string[]]$arguments, [string]$workdir, [string]$marker) {
  $stdout = Join-Path $logDir "$name.out.log"
  $stderr = Join-Path $logDir "$name.err.log"
  $process = Start-Process -FilePath $file -ArgumentList $arguments -WorkingDirectory $workdir -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
  $started.Add([pscustomobject]@{ service = $name; pid = $process.Id; executable = $file; marker = $marker })
  return $process
}

function Wait-HttpReady([string]$uri, [string]$name, [int]$timeoutSeconds = 30) {
  $deadline = [DateTime]::UtcNow.AddSeconds($timeoutSeconds)
  while ([DateTime]::UtcNow -lt $deadline) {
    try {
      $null = Invoke-RestMethod -Uri $uri -TimeoutSec 2
      return
    } catch {
      Start-Sleep -Milliseconds 350
    }
  }
  throw "$name did not become ready. See $logDir\$name.err.log."
}

function Wait-StaticOrigin([string]$uri, [string]$name, [int]$timeoutSeconds = 30) {
  $deadline = [DateTime]::UtcNow.AddSeconds($timeoutSeconds)
  while ([DateTime]::UtcNow -lt $deadline) {
    try {
      $response = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 2
      if ($response.StatusCode -eq 200) { return }
    } catch {
      Start-Sleep -Milliseconds 350
    }
  }
  throw "$name did not become ready. See $logDir\origin-site.err.log."
}

try {
  if (-not $env:CONTROL_API_BIND_ADDRESS) { $env:CONTROL_API_BIND_ADDRESS = '127.0.0.1' }
  $controlUri = [Uri]$env:CONTROL_API_URL
  $controlPort = if ($controlUri.IsDefaultPort) { 80 } else { $controlUri.Port }
  $controlHost = $env:CONTROL_API_BIND_ADDRESS

  $env:APP_PROFILE = if ($env:APP_PROFILE) { $env:APP_PROFILE } else { 'lab' }
  $env:LAB_VULNERABLE = if ($env:LAB_VULNERABLE) { $env:LAB_VULNERABLE } else { '0' }
  & $python -m alembic upgrade head
  if ($LASTEXITCODE -ne 0) { throw 'Database migration failed. No service has been marked ready.' }

  $savedControlToken = $env:CONTROL_API_TOKEN
  $savedGatewayToken = $env:GATEWAY_API_TOKEN
  $savedSigningKey = $env:POLICY_SIGNING_KEY
  $savedSourceSalt = $env:SOURCE_HASH_SALT
  Add-ServiceProcess 'control-api' $python @('-m', 'uvicorn', 'counterflow_api.main:app', '--app-dir', 'services/control-api', '--host', $controlHost, '--port', [string]$controlPort) $root 'counterflow_api.main' | Out-Null
  Wait-HttpReady ($env:CONTROL_API_URL.TrimEnd('/') + '/health/ready') 'control-api'

  Remove-Item Env:CONTROL_API_TOKEN, Env:GATEWAY_API_TOKEN, Env:POLICY_SIGNING_KEY, Env:SOURCE_HASH_SALT, Env:TYPESAFE_API_KEY, Env:LOCAL_MODEL_API_KEY -ErrorAction SilentlyContinue
  $originUri = [Uri]$env:ORIGIN_URL
  if ($OriginSitePath) {
    if ($originUri.Scheme -ne 'http' -or $originUri.Host -ne '127.0.0.1' -or $originUri.IsDefaultPort) {
      throw 'A supplied static origin must use an explicit port on 127.0.0.1 in ORIGIN_URL.'
    }
    $originSiteRoot = (Resolve-Path -LiteralPath $OriginSitePath).Path
    $originEntry = Join-Path $originSiteRoot 'server.js'
    if (-not (Test-Path -LiteralPath $originEntry -PathType Leaf)) { throw 'The supplied origin folder must contain server.js.' }
    $node = Get-Command node.exe -ErrorAction Stop
    $nodeVersionText = & $node.Source --version
    if ($LASTEXITCODE -ne 0 -or $nodeVersionText -notmatch '^v(\d+)\.' -or [int]$Matches[1] -lt 18) {
      throw 'Node.js 18 or newer is required for a supplied static origin.'
    }
    $occupiedOrigin = Get-NetTCPConnection -State Listen -LocalPort $originUri.Port -ErrorAction SilentlyContinue
    if ($occupiedOrigin) { throw "Origin port $($originUri.Port) is already in use. Stop that listener or choose another port in ORIGIN_URL." }
    $savedPort = [Environment]::GetEnvironmentVariable('PORT', 'Process')
    $env:PORT = [string]$originUri.Port
    try {
      Add-ServiceProcess 'origin-site' $node.Source @('server.js') $originSiteRoot 'server.js' | Out-Null
    } finally {
      if ($null -eq $savedPort) { Remove-Item Env:PORT -ErrorAction SilentlyContinue }
      else { $env:PORT = $savedPort }
    }
  } elseif ($originUri.IsLoopback -and $originUri.Port -eq 8000) {
    Add-ServiceProcess 'origin' $python @('-m', 'uvicorn', 'app.main:app', '--app-dir', 'services/lab-origin', '--host', '127.0.0.1', '--port', '8000') $root 'services/lab-origin' | Out-Null
  }
  Add-ServiceProcess 'honeypot' $python @('-m', 'uvicorn', 'app.main:app', '--app-dir', 'services/honeypot', '--host', '127.0.0.1', '--port', '8001') $root 'services/honeypot' | Out-Null
  if ($OriginSitePath) { Wait-StaticOrigin ($env:ORIGIN_URL.TrimEnd('/') + '/') 'origin-site' }
  elseif ($originUri.IsLoopback -and $originUri.Port -eq 8000) { Wait-HttpReady 'http://127.0.0.1:8000/health/ready' 'origin' }
  Wait-HttpReady 'http://127.0.0.1:8001/health/live' 'honeypot'

  $env:GATEWAY_API_TOKEN = $savedGatewayToken
  $env:POLICY_SIGNING_KEY = $savedSigningKey
  $env:SOURCE_HASH_SALT = $savedSourceSalt

  $goCommand = Get-Command go.exe -ErrorAction SilentlyContinue
  $goCandidates = [System.Collections.Generic.List[string]]::new()
  if ($goCommand) { $goCandidates.Add($goCommand.Source) }
  $goCandidates.Add((Join-Path $env:TEMP 'counterflow-go1.27.2\go\bin\go.exe'))
  $goCandidates.Add((Join-Path $env:LOCALAPPDATA 'Programs\Go\bin\go.exe'))
  $goCandidates.Add('C:\Program Files\Go\bin\go.exe')
  $goCandidate = $goCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
  if (-not $goCandidate) { throw 'Go is required to build the gateway. Install Go 1.27 or point PATH at go.exe.' }
  $gatewayExe = Join-Path $stateDir 'counterflow-gateway.exe'
  Push-Location (Join-Path $root 'services\gateway')
  try {
    & $goCandidate build -o $gatewayExe .
    if ($LASTEXITCODE -ne 0) { throw 'Gateway build failed.' }
  } finally { Pop-Location }
  Add-ServiceProcess 'gateway' $gatewayExe @() $root 'counterflow-gateway.exe' | Out-Null
  if ($env:LISTEN_ADDR -match '^\[(.*)\]:(\d+)$') {
    $gatewayHost = $Matches[1]
    $gatewayPort = $Matches[2]
    if ($gatewayHost -eq '::') { $gatewayHost = '::1' }
  } elseif ($env:LISTEN_ADDR -match '^(.*):(\d+)$') {
    $gatewayHost = $Matches[1]
    $gatewayPort = $Matches[2]
    if (-not $gatewayHost -or $gatewayHost -eq '0.0.0.0') { $gatewayHost = '127.0.0.1' }
  } else {
    throw 'LISTEN_ADDR must use host:port or [IPv6]:port format.'
  }
  if ($gatewayHost.Contains(':')) { $gatewayHost = "[$gatewayHost]" }
  Wait-HttpReady "http://${gatewayHost}:$gatewayPort/health/ready" 'gateway'

  Remove-Item Env:CONTROL_API_TOKEN, Env:GATEWAY_API_TOKEN, Env:POLICY_SIGNING_KEY, Env:SOURCE_HASH_SALT -ErrorAction SilentlyContinue
  Push-Location (Join-Path $root 'apps\dashboard')
  try {
    & npm run build
    if ($LASTEXITCODE -ne 0) { throw 'Dashboard production build failed.' }
  } finally { Pop-Location }

  $node = (Get-Command node.exe -ErrorAction Stop).Source
  $env:CONTROL_API_TOKEN = $savedControlToken
  Push-Location (Join-Path $root 'apps\dashboard')
  try {
    Add-ServiceProcess 'dashboard' $node @('node_modules/next/dist/bin/next', 'start', '-H', '127.0.0.1', '-p', '3000') (Join-Path $root 'apps\dashboard') 'node_modules/next/dist/bin/next' | Out-Null
  } finally { Pop-Location }
  Wait-HttpReady 'http://127.0.0.1:3000' 'dashboard'

  $started | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8
  Write-Output 'CounterFlow native services are ready.'
  Write-Output 'Dashboard:  http://127.0.0.1:3000'
  Write-Output 'Protected site: http://127.0.0.1:8080'
  Write-Output "Logs: $logDir"
  Write-Output 'To stop: scripts/stop-local.ps1'
} catch {
  foreach ($item in $started) {
    Stop-Process -Id $item.pid -Force -ErrorAction SilentlyContinue
  }
  if (Test-Path -LiteralPath $statePath) { Remove-Item -LiteralPath $statePath -Force }
  throw
} finally {
  Pop-Location
}
