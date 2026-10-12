# Architecture and trust boundaries

## Request and event flow

```text
Browser / authorized tester
             |
             v
Go reverse proxy + Coraza + OWASP CRS  -----> configured website origin
             |                                      (HTTP or HTTPS)
             | authenticated, redacted event POST
             v
FastAPI control and detection API -----> SQLite
             |                                |
             |                                +--> events, incidents, policies, audit
             +--> async Jev typed triage (optional)
             +--> async OpenAI-compatible local model advisory (optional)
             |
             +--> signed expiring policy list (polled by gateway)
             |
             +--> same-origin Next.js control center and SSE

Scoped deception policy --> separate loopback honeypot with fictional records
```

The default single-machine profile needs only Python, Go, Node.js, and SQLite. Gateway telemetry uses a bounded in-process queue and authenticated HTTP delivery to the API. The API stores normalized events and detection results in SQLite. The gateway polls signed active policies and validates their HMAC, site, route, session hash, and expiry before applying them.

## Enforcement and AI roles

Coraza and the OWASP CRS run synchronously in the gateway. They keep enforcing if the API or any model is unavailable. Deterministic code derives request signals, risk contributions, incident grouping, and policy scope. It stores the query fingerprint, not raw search text.

Jev receives a redacted incident summary asynchronously and returns a typed Choice plus confidence. The optional local model receives the same kind of structured evidence through an OpenAI-compatible chat endpoint and returns a short advisory. Neither output can authorize or directly change a policy. The local model never receives the raw request body, query string, cookies, authorization header, or source IP.

## Site configuration

`ORIGIN_URL` is deployment configuration and is not editable through the web dashboard. This prevents an unauthenticated proxy target change and keeps the application from becoming an open proxy or an SSRF control. The native demo origin is started only when this URL points to loopback port 8000. A configured website can use an IP or a hostname and either HTTP or HTTPS.

The native demo origin and honeypot bind to loopback. The control API and dashboard also bind to loopback. Only the gateway should be reachable from a tester or public ingress. Public use needs TLS termination, firewall policy, authentication and operator access review before it is suitable for real customer traffic.

## Data and failure behavior

The SQLite database is persistent across local process restarts. An event is committed before incident triage starts. Duplicate `event_id` values are ignored. Management mutations use a database-backed 24-hour idempotency key and append an audit record.

The gateway keeps up to 4,096 queued event payloads in memory and retries each API delivery three times. Requests continue to receive WAF enforcement if the API is unavailable. Events still queued at gateway process exit may be lost; the readiness response reports API connectivity and the dropped-event count. The gateway retains its last verified, unexpired policy set during a temporary API outage. Policy expiry still applies locally.

## Repair boundary

The deterministic baseline repair creates a local, isolated Git checkout, edits only the disposable origin source, runs the real regression and SQL injection tests, and saves the real diff and logs. The dashboard labels this path as deterministic. It does not claim to be a coding-model patch. Promotion is a separate, reviewed operation and is limited to the local demo source.
