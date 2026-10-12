# Operations runbook

## Start and stop

From PowerShell at the repository root:

```powershell
.\scripts\start-local.ps1
.\scripts\stop-local.ps1
```

The start script applies Alembic migrations, builds the Go gateway, makes a production dashboard build, and starts native services. It generates `.env` on first run and never prints its secrets. Logs and process records are written to `.counterflow-state`.

## Health checks

- `GET /health/live` on the control API reports that the process is responding.
- `GET /health/ready` on the control API checks the database.
- `GET /health/live` on the local origin and honeypot checks those processes.
- `GET /health/ready` on the gateway checks the API and both configured upstreams. It also reports `telemetry_dropped`.
- An empty dashboard before the first proxied request is expected. Events only appear after real requests reach the gateway.

## Common issues

- **Gateway fails to start:** check `.counterflow-state\logs\gateway.err.log` and verify the signing key, session salt, gateway token, listener port, and Coraza ruleset initialization.
- **Control API is unavailable:** check the API log, SQLite file location, and Alembic migration output. The API requires a configured operator token.
- **Origin is unavailable:** verify `ORIGIN_URL` from the CounterFlow computer. The application does not change the upstream or repair its network path.
- **Events stop appearing:** the gateway health response shows API connectivity and event-drop count. The WAF continues to enforce locally while the API is down; its bounded in-memory telemetry queue can lose pending events if the gateway exits.
- **Policies are not applied:** verify the event's session identity, the site's lab mode, policy TTL, and signing key. The gateway polls active policies every 750 ms, validates each signature and exact route/session scope, and removes revoked or expired policies on refresh.
- **Jev is `not_configured`:** set `TYPESAFE_API_KEY` in `.env`, restart CounterFlow, then send a new suspicious request. If configured but a call fails, incident state reports the model failure while deterministic detection continues.
- **Local model is not configured or unavailable:** set the exact API base and model ID in `.env`; the endpoint must implement OpenAI-compatible `/chat/completions`. Model results are advisory only.
- **Repair job waits for a model:** this build has no coding-model repair adapter. The deterministic baseline action is labeled separately and can create a real test-backed diff.

## Local secrets and data

`scripts/init-env.ps1` creates fresh local secrets and will not overwrite an existing `.env`. TypeSafe and local-model API keys are read by the control/detection API process; the dashboard receives only the operator bearer token it needs for its same-origin server proxy. The origin and honeypot receive no API keys. Do not commit `.env`, logs, repair artifacts, or the SQLite database.

Back up `counterflow.db` only while services are stopped or with a SQLite-consistent backup mechanism. The local single-operator setup does not provide production-grade retention, encryption, disaster recovery, or multi-tenant isolation.
