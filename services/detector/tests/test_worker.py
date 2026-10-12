import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from counterflow.db import Base
from counterflow.models import Event, Incident, Organization, Site
from services.detector import worker


def make_store(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'detector.sqlite'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(worker, "SessionLocal", factory)
    with factory() as db:
        db.add(Organization(id="counterflow-lab", name="lab"))
        db.add(Site(id="lab-site", organization_id="counterflow-lab", name="lab", allowed_origin_url="http://origin", domain="lab.local", deployment_mode="observe-only"))
        db.commit()
    return factory, engine


def attack_event(event_id: str, occurred_at: datetime, **overrides):
    event = {
        "event_id": event_id,
        "occurred_at": occurred_at.isoformat(),
        "site_id": "lab-site",
        "request_id": str(uuid.uuid4()),
        "source_ip_pseudonym": "source-hash-1",
        "session_key_hash": "session-hash-1",
        "route": "/api/search",
        "method": "GET",
        "status": 403,
        "duration_ms": 4.5,
        "route_destination": "origin",
        "action": "waf_blocked",
        "waf_rule_ids": [942100],
        "signals": {"sqli_pattern": True, "waf_interrupted": True, "canary_exposed": False},
    }
    event.update(overrides)
    return event


def test_stream_events_are_idempotent_and_correlated(monkeypatch, tmp_path):
    factory, engine = make_store(monkeypatch, tmp_path)
    now = datetime.now(timezone.utc)
    first = attack_event("event-1", now)
    first_result = worker.process_event(first)
    assert first_result.startswith("incident:")
    incident_id = first_result.split(":", 1)[1]
    assert worker.process_event(first) == "duplicate"
    assert worker.process_event(attack_event("event-2", now + timedelta(seconds=1))) == f"incident:{incident_id}"
    assert worker.process_event(attack_event("event-3", now + timedelta(seconds=2))) == f"incident:{incident_id}"
    with factory() as db:
        assert len(db.scalars(select(Event)).all()) == 3
        incidents = db.scalars(select(Incident)).all()
        assert len(incidents) == 1
        assert incidents[0].risk_score == 65
        assert len(incidents[0].evidence_event_ids) == 3
        assert incidents[0].score_version == "detector-v1"
    engine.dispose()


def test_canary_exposure_is_persisted_as_high_signal_evidence(monkeypatch, tmp_path):
    factory, engine = make_store(monkeypatch, tmp_path)
    event = attack_event(
        "event-canary",
        datetime.now(timezone.utc),
        source_ip_pseudonym="other-source",
        session_key_hash=None,
        status=200,
        action="allow",
        waf_rule_ids=[],
        signals={"sqli_pattern": True, "waf_interrupted": False, "canary_exposed": True},
    )
    result = worker.process_event(event)
    with factory() as db:
        incident = db.get(Incident, result.split(":", 1)[1])
        assert incident.classification == "sql_injection"
        assert incident.risk_score == 75
        assert incident.score_contributions["verified_canary_exposure"] == 35
    engine.dispose()


def test_model_summary_aggregates_waf_and_deception_evidence(monkeypatch, tmp_path):
    factory, engine = make_store(monkeypatch, tmp_path)
    now = datetime.now(timezone.utc)
    incident_id = None
    for index in range(3):
        result = worker.process_event(attack_event(f"blocked-{index}", now + timedelta(seconds=index)))
        incident_id = result.split(":", 1)[1]
    worker.process_event(attack_event(
        "decoy-1", now + timedelta(seconds=3), status=200,
        route_destination="honeypot", action="deceived", waf_rule_ids=[],
        signals={"sqli_pattern": True, "waf_interrupted": False, "canary_exposed": False},
    ))
    with factory() as db:
        incident = db.get(Incident, incident_id)
        summary = worker.incident_evidence_summary(db, incident)
    assert summary["related_request_count"] == 4
    assert summary["waf_blocked_count"] == 3
    assert summary["deceived_request_count"] == 1
    assert summary["honeypot_request_count"] == 1
    assert summary["waf_rule_ids"] == [942100]
    assert summary["features"]["waf_interrupted"] is True
    engine.dispose()
