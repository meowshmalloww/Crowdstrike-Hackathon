# Native local and private-LAN lab

CounterFlow runs as native Windows processes. No container runtime is involved.

## Start on Computer B

Install Python 3.11, Node.js 24/npm, Go 1.27, and Git. From the repository folder:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Push-Location apps\dashboard
npm ci
Pop-Location
.\scripts\init-env.ps1
.\scripts\start-local.ps1
```

The startup script creates/migrates `counterflow.db`, builds the gateway and UI, then starts the processes with logs under `.counterflow-state\logs`. The default addresses are:

| Service | Address | Reachability |
| --- | --- | --- |
| Demo origin | `127.0.0.1:8000` | Loopback only |
| Fictional honeypot | `127.0.0.1:8001` | Loopback only |
| Control API | `127.0.0.1:8002` | Loopback only |
| Dashboard | `127.0.0.1:3000` | Loopback only |
| Gateway | `127.0.0.1:8080` | Loopback by default |

Open the dashboard at `http://127.0.0.1:3000`, then verify the actual request path:

```powershell
.\.venv\Scripts\python.exe scripts\verify-local.py
```

The test is hard-limited to the local demo origin on port 8000. It verifies normal search, actual WAF denials, a short-lived exact-session deception rule, a real decoy response, database persistence, and the dashboard response. See its JSON output for measured results.

## Point the gateway at your website

In `.env`, change `ORIGIN_URL` to your website's origin address and restart:

```text
ORIGIN_URL=https://<your-origin-host-or-ip>
LISTEN_ADDR=0.0.0.0:8080
LAB_VULNERABLE=0
LAB_MODE=production-review
```

Use an origin that is reachable from Computer B and has valid TLS when using HTTPS. The gateway is a reverse proxy, so direct public requests must be routed to it. Restrict the origin's direct ingress so users cannot bypass the gateway. Keep the management API, dashboard, origin, and honeypot private. Terminate client TLS at a maintained HTTPS ingress in front of the gateway and limit port 8080 to that ingress or a known private tester.

If the configured origin is not loopback port 8000, `start-local.ps1` does not start the disposable demo origin. It always keeps the honeypot on loopback.

### Let other computers on the same Wi-Fi open the protected site

For the included Cat Break website, keep the origin at `http://127.0.0.1:3001` and set `LISTEN_ADDR=0.0.0.0:8080` in the private `.env`. Restart with `scripts\start-local.ps1 -OriginSitePath 'C:\path\to\AttackTheCatWebsite-main'`. Open `http://<this-computer's-Wi-Fi-IPv4>:8080` from another device on the same network. The gateway listens on every local interface, while the dashboard, management API, and website origin stay on loopback. Allow only TCP 8080 from the Wi-Fi subnet in the host firewall; do not open ports 3000, 3001, or 8002. A Wi-Fi network may block device-to-device connections, and a private IP is not reachable from the public internet.

## Optional two-computer lab

Use this only on an authorized private network with the disposable local storefront. Computer B runs CounterFlow; Computer A sends the test traffic. On Computer B, set `LISTEN_ADDR` to its private address, for example `192.168.50.10:8080`. Keep `CONTROL_API_BIND_ADDRESS=127.0.0.1`. Add a Windows Firewall rule allowing only Computer A's private address to reach TCP 8080. Do not expose the origin or management ports to the LAN.

From Computer A, first verify benign traffic:

```powershell
curl.exe -G --data-urlencode "q=O'Reilly mug" http://192.168.50.10:8080/api/search
```

Then send the bounded lab SQL injection requests with one test-session marker. The first three should be blocked by the active WAF. The lab defense may then route that same session to the fictional honeypot for the policy TTL:

```powershell
curl.exe -G --data-urlencode "q=%' OR 1=1 --" -H "X-CounterFlow-Session: authorized-demo-session-01" http://192.168.50.10:8080/api/search
```

Run these only after confirming `ORIGIN_URL` is the local disposable storefront. A `production-review` deployment does not auto-enable deception. Do not run SQLmap, Nmap, Nikto, credential tools, or other scanners against a public site as part of this local verification.

## Jev and model integrations

Set `TYPESAFE_API_KEY` in `.env` to enable Jev. The service reports `not_configured` when it is empty. For an optional OpenAI-compatible inference endpoint whose provider permits application traffic, set `LOCAL_MODEL_API_BASE`, `LOCAL_MODEL_NAME`, and optionally `LOCAL_MODEL_API_KEY`. `LOCAL_MODEL_TIMEOUT_SECONDS` defaults to 120. CounterFlow does not download or start a model.

The supplied moLab notebook runs Qwen inside its sandbox. [moLab's current usage restrictions](https://molab.marimo.io/pages/molab/restrictions) prohibit exposing sandbox compute to outside traffic and proxying or re-exposing its AI endpoints. Keep Qwen in the notebook's interactive workflow; do not point CounterFlow at its sandbox port. Jev and any permitted inference endpoint provide advisory triage only; Coraza and explicit signed policies make enforcement decisions.

## Stop and inspect

Stop the processes with `scripts\stop-local.ps1`. Native process logs are in `.counterflow-state\logs`; SQLite state is `counterflow.db`. Keep `.env`, logs, and the database private. The dashboard and API use loopback by default.
