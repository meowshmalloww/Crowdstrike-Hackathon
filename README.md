# CounterFlow

CounterFlow is a single-site website protection lab. A Go reverse proxy with Coraza and the OWASP Core Rule Set sits in front of a configurable website origin. It blocks known malicious requests, records privacy-reduced traffic, correlates suspicious events into explainable incidents, and can apply a scoped, expiring deception policy for an authorized lab session. A local control center shows the live state.

The gateway makes enforcement decisions without waiting on AI. Jev provides optional asynchronous structured triage when a TypeSafe API key is configured. A separately configured OpenAI-compatible local model can add an advisory to incidents; it cannot change gateway policy. The demo origin and honeypot run as native Python processes. SQLite stores events, incidents, policy state, repairs, and audit history.

## Native Windows run

No Docker, Redis, or PostgreSQL service is used or required. Install Python 3.11, Go 1.27, Node.js 24, and Git. Then, from PowerShell in this folder:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
cd apps\dashboard
npm ci
cd ..\..
.\scripts\init-env.ps1
.\scripts\start-local.ps1
```

`start-local.ps1` applies SQLite migrations, builds the Go gateway and dashboard, then starts the origin, honeypot, control API, gateway, and UI. It writes logs and process IDs under `.counterflow-state`. The dashboard and management API bind to loopback; the demo origin and honeypot also bind to loopback. Stop the services with:

```powershell
.\scripts\stop-local.ps1
```

Open the dashboard at [http://127.0.0.1:3000](http://127.0.0.1:3000). The protected demo site is at [http://127.0.0.1:8080](http://127.0.0.1:8080). The local test uses only this disposable loopback site:

```powershell
.\.venv\Scripts\python.exe scripts\verify-local.py
```

It verifies a benign request, three real WAF denials, the exact-session deception rule, a real honeypot response, persisted events and incident evidence, and the dashboard HTTP response. It refuses to send attack requests unless `ORIGIN_URL` points at the local disposable storefront on port 8000.

### Protect a local Node.js website

For a local static site with a `server.js` entry point, set `ORIGIN_URL=http://127.0.0.1:3001` in `.env`, then run:

```powershell
.\scripts\start-local.ps1 -OriginSitePath 'C:\path\to\your\site'
```

CounterFlow starts that Node origin on loopback port 3001 and routes the protected site through `http://127.0.0.1:8080`. Open the dashboard at `http://127.0.0.1:3000`. The origin process is tracked and stopped by `scripts\stop-local.ps1`. This local-site option does not configure public hosting or TLS.

Run `node scripts\verify-protected-site.mjs` to check the gallery, origin isolation, response headers, and local gateway blocking. The check refuses non-loopback origin or gateway settings and sends only read-only requests.

## Protect your own website

Edit the private `.env` file before starting CounterFlow:

```text
ORIGIN_URL=http://<your-website-origin-ip>:<origin-port>
LISTEN_ADDR=0.0.0.0:8080
LAB_MODE=production-review
LAB_VULNERABLE=0
```

Use the origin’s real HTTPS URL when it has a valid certificate. Point the website’s public entry point or DNS/reverse proxy at the CounterFlow gateway, and restrict direct access to the origin so visitors cannot bypass the gateway. Allow inbound traffic to port 8080 only from the intended network until TLS termination, firewall rules, and access controls are in place. Keep ports 8000, 8001, 8002, and 3000 private. Restart CounterFlow after changing `.env`.

The included `verify-local.py` only tests the disposable loopback storefront. Do not run it after pointing `ORIGIN_URL` at a remote site; it will refuse that configuration. Test a real site only with an explicitly authorized, separately scoped plan.

## Jev and model integrations

For real Jev triage, set `TYPESAFE_API_KEY` in `.env` and restart. The key stays in the API process. Without it, incidents still use deterministic detection and show Jev as `not_configured`; no fabricated Jev answer is produced.

The optional model adapter uses an OpenAI-compatible Chat Completions endpoint. Configure these values only for a provider that permits application traffic:

```text
LOCAL_MODEL_API_BASE=https://<approved-provider>/v1
LOCAL_MODEL_NAME=<exact model ID exposed by your server>
LOCAL_MODEL_API_KEY=<provider key, if required>
```

The supplied moLab notebook runs Qwen inside its sandbox. [moLab's current usage restrictions](https://molab.marimo.io/pages/molab/restrictions) prohibit exposing sandbox compute to outside traffic and proxying or re-exposing its AI endpoints, so CounterFlow does not connect to that notebook server. Keep Qwen in the notebook's interactive workflow, or choose an inference provider that permits application requests. CounterFlow does not download or start a model. `LOCAL_MODEL_TIMEOUT_SECONDS` defaults to 120 and is bounded to 5–300 seconds at runtime. Jev and permitted inference models are advisory; only Coraza and explicit signed gateway policies enforce traffic decisions.

## Current scope and limits

- One configured website, one local operator, and one SQLite database.
- OWASP CRS blocks known WAF matches synchronously; rules-only detection remains available when Jev or the local model is down.
- Automatic deception is limited to lab-auto mode, an exact hashed session, `/api/search`, and a short TTL. It is not enabled for production-review mode.
- The repair panel offers a clearly labeled deterministic baseline remediation and records its real diff and test results. No coding-model repair is claimed without a configured provider.
- The native telemetry queue is bounded and held in process memory while the gateway publishes events to the local API. Gateway readiness reports API loss and the dropped-event count; protection itself continues at the gateway.
- This is a working lab, not a production security certification. It still needs production authentication/RBAC, a durable queue, TLS deployment design, multi-tenant isolation, load/recovery exercises, and independent security review.

See [docs/local-lab.md](docs/local-lab.md), [docs/architecture.md](docs/architecture.md), [docs/operations.md](docs/operations.md), and [docs/production-readiness.md](docs/production-readiness.md) for setup and boundaries.
