# Threat model

## Assets

- Availability and integrity of the configured website origin.
- Local operator credentials, gateway-to-API token, policy-signing key, and source-hash salt.
- Persisted request metadata, incidents, policy records, repair artifacts, and audit entries.
- Separation between the configured website and fictional honeypot.

## Trust boundaries

- The gateway is the only service intended for tester or public ingress. The control API, dashboard, local origin, and honeypot bind to loopback in the default profile.
- All request input is attacker-controlled. The gateway does not store raw query strings, bodies, cookies, or authorization headers in telemetry. It stores a keyed query fingerprint, route template, status, WAF IDs, latency, and derived booleans.
- Gateway telemetry and policy fetches use a shared random bearer token on the local API connection. Active policies are signed with HMAC and checked for site, action, exact session hash, fixed route, and expiry before enforcement.
- Jev and local-model inputs contain compact derived incident features. Model output is untrusted and advisory; model output is never a gateway policy.
- The honeypot uses fictional in-memory records and has no origin database or credentials.

## Main risks and mitigations

| Risk | Mitigation | Remaining limit |
| --- | --- | --- |
| Direct origin access bypasses WAF | Keep demo origin on loopback; restrict a configured remote origin with its own ingress firewall | Remote origin firewall configuration is owned by the site operator |
| Malicious request data manipulates an AI analysis | Redact raw values, label evidence as untrusted, narrow the task, and prevent AI output from changing controls | Model advice can still be wrong and requires human interpretation |
| False positive blocks a benign user | WAF operates at gateway with known rules; quoted/punctuation tests are included; lab deception matches one exact test session | OWASP CRS needs site-specific tuning before production use |
| Forged or stale policy | Random token for policy fetch; HMAC signature; exact session and route check; local expiry; cache retains only unexpired entries | Revocation is reflected on the next successful 750 ms poll; expired policies are removed locally during outage |
| API or AI outage affects website availability | WAF request processing is local and independent; website traffic continues while telemetry is queued | In-memory telemetry can be lost if the gateway exits while the API is unavailable |
| Dashboard or API exposed to the network | Both bind to loopback by default; only the gateway is intended for ingress | No multi-user login or production RBAC is implemented |
| Repair candidate changes unrelated code | Baseline repair is limited to one known lab file, tested in a temporary Git checkout, and requires separate human promotion | No isolated VM/container runner is included; do not execute untrusted customer repositories |

## Out of scope

This lab is not a general-purpose reverse-proxy management service, a production WAF certification, a multi-tenant security product, an autonomous code deployment system, or an offensive testing tool. It does not contact external attacker infrastructure or perform active tests against remote sites.
