$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$envPath = Join-Path $root '.env'
if (Test-Path -LiteralPath $envPath) {
  throw '.env already exists. Keep its secrets; edit it directly if needed.'
}
function New-Secret {
  $bytes = [byte[]]::new(32)
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
  [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}
$text = @"
DATABASE_URL=sqlite:///./counterflow.db
CONTROL_API_TOKEN=$(New-Secret)
GATEWAY_API_TOKEN=$(New-Secret)
POLICY_SIGNING_KEY=$(New-Secret)
SOURCE_HASH_SALT=$(New-Secret)
COUNTERFLOW_SITE_ID=counterflow-site
CONTROL_API_URL=http://127.0.0.1:8002
CONTROL_API_BIND_ADDRESS=127.0.0.1
ORIGIN_URL=http://127.0.0.1:8000
HONEYPOT_URL=http://127.0.0.1:8001
LISTEN_ADDR=127.0.0.1:8080
LAB_MODE=lab-auto
APP_PROFILE=lab
LAB_VULNERABLE=0
TYPESAFE_API_KEY=
LOCAL_MODEL_API_BASE=
LOCAL_MODEL_NAME=
LOCAL_MODEL_API_KEY=
LOCAL_MODEL_TIMEOUT_SECONDS=120
REPAIR_ARTIFACT_DIR=./repair-artifacts
EVALUATION_DATASET=data/evaluation/events.jsonl
"@
[System.IO.File]::WriteAllText($envPath, $text, [System.Text.UTF8Encoding]::new($false))
Write-Output 'Created local .env with fresh secrets. They were not printed.'
