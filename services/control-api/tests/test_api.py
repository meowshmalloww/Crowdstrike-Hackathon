from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import counterflow.db as db_module
import counterflow_api.main as api
from counterflow.db import Base
from counterflow.models import Incident
from services.detector import worker


@pytest.fixture
def operator_client(tmp_path, monkeypatch):
    test_engine = create_engine(f"sqlite:///{tmp_path / 'api.sqlite'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(test_engine)
    factory = sessionmaker(bind=test_engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(api, "SessionLocal", factory)
    monkeypatch.setattr(api, "engine", test_engine)
    monkeypatch.setattr(db_module, "SessionLocal", factory)
    test_settings = replace(api.settings, api_token="operator-token", gateway_api_token="gateway-token", origin_url="http://127.0.0.1:8000", policy_signing_key="test-signing-key", source_hash_salt="test-session-salt", site_id="lab-site", lab_mode="observe-only", local_model_api_base="", local_model_name="", repair_artifact_dir=str(tmp_path / "repairs"))
    monkeypatch.setattr(api, "settings", test_settings)
    monkeypatch.setattr(worker, "SessionLocal", factory)
    monkeypatch.setattr(worker, "settings", test_settings)
    with TestClient(api.app) as client:
        with factory() as db:
            incident_id = str(uuid.uuid4())
            db.add(Incident(
                id=incident_id, site_id="lab-site", correlation_key="test-key", status="open",
                first_seen_at=datetime.now(timezone.utc), last_seen_at=datetime.now(timezone.utc),
                classification="sql_injection", rank=40, risk_score=40, score_version="detector-v1",
                request_to_alert_latency_ms=3.0, model_status="not_configured", explanation="test evidence",
                score_contributions={"sqli_or_waf_match": 40}, evidence_event_ids=[], estimated_impact="test lab only",
            ))
            db.commit()
        yield client, incident_id
    api.app.dependency_overrides.clear()
    test_engine.dispose()


def auth_headers(request_id: str | None = None):
    headers = {"Authorization": "Bearer operator-token"}
    if request_id:
        headers["X-Request-ID"] = request_id
    return headers


def test_management_api_requires_bearer_auth(operator_client):
    client, _ = operator_client
    assert client.get("/api/v1/incidents").status_code == 401
    assert client.get("/api/v1/incidents", headers=auth_headers()).status_code == 200


def test_mutation_records_status_and_rejects_replayed_request_id(operator_client):
    client, incident_id = operator_client
    request_id = str(uuid.uuid4())
    response = client.post(f"/api/v1/incidents/{incident_id}/acknowledge", headers=auth_headers(request_id))
    assert response.status_code == 200
    assert response.json()["status"] == "acknowledged"
    replay = client.post(f"/api/v1/incidents/{incident_id}/acknowledge", headers=auth_headers(request_id))
    assert replay.status_code == 409


def test_incident_acknowledge_and_resolve_are_distinct_actions(operator_client):
    client, incident_id = operator_client
    acknowledged = client.post(f"/api/v1/incidents/{incident_id}/acknowledge", headers=auth_headers(str(uuid.uuid4())))
    assert acknowledged.status_code == 200
    assert acknowledged.json()["status"] == "acknowledged"
    resolved = client.post(f"/api/v1/incidents/{incident_id}/resolve", headers=auth_headers(str(uuid.uuid4())))
    assert resolved.status_code == 200
    assert resolved.json()["status"] == "resolved"
    duplicate = client.post(f"/api/v1/incidents/{incident_id}/resolve", headers=auth_headers(str(uuid.uuid4())))
    assert duplicate.status_code == 409


def test_policy_activation_is_signed_and_audited(operator_client):
    client, incident_id = operator_client
    proposal = client.post(
        "/api/v1/policies/proposals",
        headers=auth_headers(str(uuid.uuid4())),
        json={"action": "deceive", "reason": "Authorized controlled test session", "ttl_seconds": 180, "session_token": "demo-session-01", "source_incident_id": incident_id},
    )
    assert proposal.status_code == 200
    policy = proposal.json()
    assert policy["status"] == "proposed"
    approved = client.post(f"/api/v1/policies/{policy['id']}/approve", headers=auth_headers(str(uuid.uuid4())))
    assert approved.status_code == 200
    assert approved.json()["status"] == "active"
    stored = next(item for item in client.get("/api/v1/internal/policies", headers={"Authorization": "Bearer gateway-token"}).json() if item["id"] == policy["id"])
    signature = stored.pop("signature")
    canonical = json.dumps(stored, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    expected = hmac.new(b"test-signing-key", canonical, hashlib.sha256).hexdigest()
    assert hmac.compare_digest(signature, expected)
    audit = client.get("/api/v1/audit", headers=auth_headers()).json()
    assert any(item["action"] == "policy.approve" and item["target"] == policy["id"] for item in audit)


def test_policy_list_reports_expired_active_policy_without_mutating_gateway_state(operator_client):
    client, incident_id = operator_client
    policy_ids = []
    for index in range(2):
        proposal = client.post(
            "/api/v1/policies/proposals",
            headers=auth_headers(str(uuid.uuid4())),
            json={"action": "block", "reason": "Controlled policy expiry display test", "ttl_seconds": 180, "session_token": f"expiry-test-session-{index}", "source_incident_id": incident_id},
        )
        assert proposal.status_code == 200
        policy_id = proposal.json()["id"]
        approved = client.post(f"/api/v1/policies/{policy_id}/approve", headers=auth_headers(str(uuid.uuid4())))
        assert approved.status_code == 200
        policy_ids.append(policy_id)

    with api.SessionLocal() as db:
        expired_policy = db.get(api.Policy, policy_ids[0])
        expired_policy.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()

    listed = {item["id"]: item for item in client.get("/api/v1/policies", headers=auth_headers()).json()}
    assert listed[policy_ids[0]]["status"] == "expired"
    assert listed[policy_ids[1]]["status"] == "active"
    gateway_policy_ids = {
        item["id"]
        for item in client.get("/api/v1/internal/policies", headers={"Authorization": "Bearer gateway-token"}).json()
    }
    assert policy_ids[0] not in gateway_policy_ids
    assert policy_ids[1] in gateway_policy_ids


def test_gateway_event_ingestion_requires_internal_token_and_persists_incident(operator_client):
    client, _ = operator_client
    occurred_at = datetime.now(timezone.utc).isoformat()
    payload = {
        "event_id": "real-gateway-event-1",
        "occurred_at": occurred_at,
        "site_id": "lab-site",
        "request_id": str(uuid.uuid4()),
        "source_ip_pseudonym": "source-hash",
        "session_key_hash": "session-hash",
        "route": "/api/search",
        "method": "GET",
        "status": 403,
        "duration_ms": 5,
        "route_destination": "origin",
        "action": "waf_blocked",
        "waf_rule_ids": [942100],
        "signals": {"sqli_pattern": True, "waf_interrupted": True, "canary_exposed": False},
    }
    assert client.post("/api/v1/internal/events", json=payload).status_code == 401
    accepted = client.post("/api/v1/internal/events", headers={"Authorization": "Bearer gateway-token"}, json=payload)
    assert accepted.status_code == 200
    assert accepted.json()["result"].startswith("incident:")
    event_rows = client.get("/api/v1/events", headers=auth_headers()).json()
    incident_rows = client.get("/api/v1/incidents", headers=auth_headers()).json()
    assert any(row["event_id"] == "real-gateway-event-1" for row in event_rows)
    assert any("real-gateway-event-1" in row["evidence_event_ids"] for row in incident_rows)
