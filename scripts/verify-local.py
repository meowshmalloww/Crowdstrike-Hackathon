from __future__ import annotations

import hashlib
import json
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import httpx


ROOT = Path(__file__).resolve().parents[1]
GATEWAY = "http://127.0.0.1:8080"


def read_env() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            name, value = line.split("=", 1)
            values[name.strip()] = value
    return values


def wait_for(check, label: str, timeout: float = 12.0):
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            result = check()
            if result:
                return result
        except Exception as exc:  # The next bounded retry handles startup/event delivery races.
            last_error = exc
        time.sleep(0.25)
    detail = f" ({type(last_error).__name__})" if last_error else ""
    raise RuntimeError(f"Timed out waiting for {label}{detail}")


def main() -> None:
    env = read_env()
    control = env.get("CONTROL_API_URL", "http://127.0.0.1:8002").rstrip("/")
    origin = urlsplit(env.get("ORIGIN_URL", "http://127.0.0.1:8000"))
    if origin.scheme not in {"http", "https"} or origin.hostname not in {"127.0.0.1", "localhost", "::1"} or origin.port != 8000:
        raise RuntimeError("Local replay refused: set ORIGIN_URL to the disposable loopback storefront on port 8000 first")
    operator = {"Authorization": f"Bearer {env['CONTROL_API_TOKEN']}"}
    gateway_auth = {"Authorization": f"Bearer {env['GATEWAY_API_TOKEN']}"}
    session = "counterflow-e2e-" + uuid.uuid4().hex
    session_hash = hashlib.sha256(f"{env['SOURCE_HASH_SALT']}:{session}".encode()).hexdigest()
    with httpx.Client(timeout=5, trust_env=False) as client:
        health = client.get(f"{GATEWAY}/health/ready")
        health.raise_for_status()
        if health.json().get("status") != "ready":
            raise RuntimeError("Gateway dependencies are not ready")

        benign = client.get(f"{GATEWAY}/api/search", params={"q": "O'Reilly mug"})
        if benign.status_code != 200:
            raise RuntimeError(f"Benign search failed: HTTP {benign.status_code}")

        attack_statuses = []
        for _ in range(3):
            attack = client.get(
                f"{GATEWAY}/api/search?q=%25%27%20OR%201%3D1%20--",
                headers={"X-CounterFlow-Session": session},
            )
            attack_statuses.append(attack.status_code)
        if attack_statuses != [403, 403, 403]:
            raise RuntimeError(f"Expected three active WAF denials, got {attack_statuses}")

        def active_policy():
            response = client.get(f"{control}/api/v1/internal/policies", headers=gateway_auth)
            response.raise_for_status()
            return next((item for item in response.json() if item["match_spec"].get("session_hash") == session_hash), None)

        policy = wait_for(active_policy, "the scoped deception policy")
        if policy["action"] != "deceive":
            raise RuntimeError(f"Unexpected automatic defense action: {policy['action']}")
        def decoy_delivery():
            response = client.get(
                f"{GATEWAY}/api/search?q=%25%27%20OR%201%3D1%20--",
                headers={"X-CounterFlow-Session": session},
            )
            if response.status_code == 200 and "decoy-" in response.text and "synthetic-canary-2026" not in response.text:
                return response
            return None

        decoy = wait_for(decoy_delivery, "the gateway's next signed-policy refresh", timeout=12)

        integrations_response = client.get(f"{control}/api/v1/integrations", headers=operator)
        integrations_response.raise_for_status()
        integrations = integrations_response.json()
        local_model_configured = integrations["local_model"]["status"] == "configured"

        def persisted_state():
            events_response = client.get(f"{control}/api/v1/events?limit=100", headers=operator)
            events_response.raise_for_status()
            incidents_response = client.get(f"{control}/api/v1/incidents?limit=100", headers=operator)
            incidents_response.raise_for_status()
            metrics_response = client.get(f"{control}/api/v1/metrics", headers=operator)
            metrics_response.raise_for_status()
            events, incidents, metrics = events_response.json(), incidents_response.json(), metrics_response.json()
            blocked = any(item["action"] == "waf_blocked" and item["waf_rule_ids"] for item in events)
            deceived = any(item["action"] == "deceived" and item["origin"] == "honeypot" for item in events)
            correlated = any(item["classification"] == "sql_injection" and item["evidence_event_ids"] for item in incidents)
            if blocked and deceived and correlated and metrics["honeypot_interactions"] > 0:
                return events, incidents, metrics
            return None

        events, incidents, metrics = wait_for(persisted_state, "persisted request, incident, and honeypot evidence")
        model_incident = None
        if local_model_configured:
            def local_model_result():
                incidents_response = client.get(f"{control}/api/v1/incidents?limit=100", headers=operator)
                incidents_response.raise_for_status()
                return next((
                    item for item in incidents_response.json()
                    if item["classification"] == "sql_injection"
                    and item["local_ai_status"] == "complete"
                    and item["local_ai_summary"]
                ), None)

            model_incident = wait_for(local_model_result, "the configured advisory model response", timeout=180)
        dashboard = client.get("http://127.0.0.1:3000")
        dashboard.raise_for_status()
        if "CounterFlow" not in dashboard.text:
            raise RuntimeError("Dashboard response did not contain the CounterFlow application")

        print(json.dumps({
            "gateway": "ready",
            "benign_search_http": benign.status_code,
            "active_waf_attack_http": attack_statuses,
            "automatic_policy": {"action": policy["action"], "ttl_expires_at": policy["expires_at"]},
            "honeypot_http": decoy.status_code,
            "persisted_event_count": len(events),
            "incident_count": len(incidents),
            "honeypot_interactions": metrics["honeypot_interactions"],
            "local_model": {
                "status": "complete" if model_incident else integrations["local_model"]["status"],
                "model": integrations["local_model"]["model"],
                "advisory_characters": len(model_incident["local_ai_summary"]) if model_incident else 0,
            },
            "dashboard_http": dashboard.status_code,
        }, indent=2))


if __name__ == "__main__":
    main()
