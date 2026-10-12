from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import and_, desc, func, or_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from counterflow.db import Base, SessionLocal, engine, get_session
from counterflow.detection import signed_policy_payload
from counterflow.models import (
    AuditEvent,
    Event,
    HoneypotInteraction,
    IdempotencyRecord,
    Incident,
    Organization,
    Policy,
    Repair,
    RepairCheck,
    Site,
    as_utc,
    utcnow,
)
from counterflow.settings import settings


_triage_tasks: set[tuple[str, str]] = set()
log = logging.getLogger("counterflow.api")


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Production/container startup applies Alembic first. This keeps an unconfigured
    # local health process useful without masking a failed database in readiness.
    with SessionLocal() as db:
        if db.get(Organization, "counterflow-lab") is None:
            db.add(Organization(id="counterflow-lab", name="CounterFlow Lab"))
            db.flush()
        if db.get(Site, settings.site_id) is None:
            db.add(
                Site(
                    id=settings.site_id,
                    organization_id="counterflow-lab",
                    name="Protected Website",
                    allowed_origin_url=settings.origin_url,
                    domain=settings.origin_url.split("//", 1)[-1].split("/", 1)[0],
                    deployment_mode=settings.lab_mode,
                )
            )
        else:
            site = db.get(Site, settings.site_id)
            site.allowed_origin_url = settings.origin_url
            site.deployment_mode = settings.lab_mode
        stale_before = utcnow() - timedelta(hours=24)
        db.query(IdempotencyRecord).filter(IdempotencyRecord.created_at < stale_before).delete(synchronize_session=False)
        db.commit()
    yield


app = FastAPI(
    title="CounterFlow Control API",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url="/openapi.json",
    lifespan=lifespan,
)


async def require_auth(authorization: str | None = Header(default=None)) -> str:
    expected = settings.api_token
    if not expected:
        raise HTTPException(status_code=503, detail="Management authentication is not configured")
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="Valid bearer authentication is required", headers={"WWW-Authenticate": "Bearer"})
    return "local-operator"


async def require_new_request_id(request: Request, actor: str = Depends(require_auth)) -> str:
    request_id = request.headers.get("x-request-id", "")
    if not request_id or len(request_id) > 128 or any(ch.isspace() for ch in request_id):
        raise HTTPException(status_code=400, detail="Mutations require a unique X-Request-ID")
    import hashlib

    key = hashlib.sha256(f"{actor}:{request_id}".encode()).hexdigest()
    with SessionLocal() as db:
        db.add(IdempotencyRecord(key=key))
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(status_code=409, detail="This X-Request-ID was already used") from exc
    return actor


async def require_gateway_auth(authorization: str | None = Header(default=None)) -> None:
    expected = settings.gateway_api_token
    scheme, _, token = (authorization or "").partition(" ")
    if not expected or scheme.lower() != "bearer" or not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="Gateway authentication failed")


async def _run_triage(incident_id: str, kind: str) -> None:
    from services.detector.worker import triage_incident, triage_local_model

    key = (kind, incident_id)
    try:
        if kind == "jev":
            await triage_incident(incident_id)
        else:
            await triage_local_model(incident_id)
    except Exception:
        # Model failures are visible in incident state and never change gateway enforcement.
        log.exception("background_triage_failed incident_id=%s kind=%s", incident_id, kind)
    finally:
        _triage_tasks.discard(key)


@app.middleware("http")
async def bounded_management_requests(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > 65536:
                return JSONResponse(status_code=413, content={"detail": "Management request body exceeds 64 KiB"})
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Cache-Control", "no-store")
    return response


def require_signing_key() -> str:
    key = settings.policy_signing_key
    if not key:
        raise HTTPException(status_code=503, detail="Policy signing is not configured")
    return key


def record_audit(db: Session, actor: str, action: str, target: str, outcome: str, detail: dict, request_id: str | None = None) -> None:
    db.add(
        AuditEvent(
            id=str(uuid.uuid4()),
            organization_id="counterflow-lab",
            principal_id=actor,
            action=action,
            target=target,
            request_id=request_id,
            outcome=outcome,
            detail_json=detail,
        )
    )


def event_json(row: Event) -> dict:
    return {
        "event_id": row.id,
        "request_id": row.request_id,
        "occurred_at": as_utc(row.occurred_at).isoformat().replace("+00:00", "Z"),
        "source_ip_pseudonym": row.source_ip_pseudonym,
        "route": row.route_template,
        "method": row.method,
        "status": row.response_status,
        "duration_ms": row.duration_ms,
        "origin": row.origin,
        "action": row.action,
        "waf_rule_ids": row.waf_rule_ids,
        "waf_anomaly_score": row.waf_anomaly_score,
        "signals": row.signal_features,
    }


def incident_json(row: Incident) -> dict:
    return {
        "id": row.id,
        "site_id": row.site_id,
        "status": row.status,
        "first_seen_at": as_utc(row.first_seen_at).isoformat().replace("+00:00", "Z"),
        "last_seen_at": as_utc(row.last_seen_at).isoformat().replace("+00:00", "Z"),
        "classification": row.classification,
        "rank": row.rank,
        "risk_score": row.risk_score,
        "score_version": row.score_version,
        "request_to_alert_latency_ms": row.request_to_alert_latency_ms,
        "severity": "critical" if row.risk_score >= 75 else "high" if row.risk_score >= 50 else "medium" if row.risk_score >= 25 else "low",
        "model_status": row.model_status,
        "jev_choice": row.jev_choice,
        "jev_confidence": row.jev_confidence,
        "local_ai_status": row.local_ai_status,
        "local_ai_summary": row.local_ai_summary,
        "explanation": row.explanation,
        "score_contributions": row.score_contributions,
        "evidence_event_ids": row.evidence_event_ids,
        "estimated_impact": row.estimated_impact,
    }


def policy_json(row: Policy) -> dict:
    status = row.status
    if status in {"active", "proposed"} and as_utc(row.expires_at) <= utcnow():
        status = "expired"
    return {
        "id": row.id,
        "site_id": row.site_id,
        "action": row.action,
        "match_spec": row.match_spec,
        "reason": row.reason,
        "source_incident_id": row.source_incident_id,
        "created_by": row.created_by,
        "approved_by": row.approved_by,
        "status": status,
        "activated_at": as_utc(row.activated_at).isoformat().replace("+00:00", "Z") if row.activated_at else None,
        "expires_at": as_utc(row.expires_at).isoformat().replace("+00:00", "Z"),
        "version": row.version,
        "revoked_at": as_utc(row.revoked_at).isoformat().replace("+00:00", "Z") if row.revoked_at else None,
    }


def repair_json(row: Repair, checks: list[RepairCheck] | None = None) -> dict:
    result = {
        "id": row.id,
        "incident_id": row.incident_id,
        "repository": row.repository,
        "commit_base": row.commit_base,
        "branch": row.branch,
        "status": row.status,
        "model_provider": row.model_provider,
        "commit_sha": row.commit_sha,
        "pr_url": row.pr_url,
        "diff_summary": row.diff_summary,
        "proposed_at": as_utc(row.proposed_at).isoformat().replace("+00:00", "Z"),
        "approved_at": as_utc(row.approved_at).isoformat().replace("+00:00", "Z") if row.approved_at else None,
        "checks": [
            {
                "test_name": c.test_name,
                "command_reference": c.command_reference,
                "exit_code": c.exit_code,
                "outcome": c.outcome,
                "log_ref": c.log_ref,
            }
            for c in (checks or [])
        ],
    }
    if row.artifact_path:
        root = Path(settings.repair_artifact_dir).resolve()
        target = Path(row.artifact_path).resolve()
        if target.is_relative_to(root) and target.is_file() and target.name.endswith(".diff"):
            result["diff"] = target.read_text(encoding="utf-8")
    return result


@app.get("/health/live")
async def live():
    return {"status": "live"}


@app.get("/health/ready")
async def ready():
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Dependency unavailable: {type(exc).__name__}") from exc
    return {"status": "ready", "database": "connected", "event_transport": "authenticated-http"}


@app.post("/api/v1/internal/events")
async def ingest_gateway_event(payload: dict, _: None = Depends(require_gateway_auth)):
    # The gateway sends already-redacted metadata. Request bodies and credentials never enter this API.
    from services.detector.worker import process_event

    try:
        result = await asyncio.to_thread(process_event, payload)
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Gateway event has an invalid schema") from exc
    incident_id = result.split(":", 1)[1] if result.startswith("incident:") else None
    if incident_id:
        for kind, enabled in (
            ("jev", bool(os.getenv("TYPESAFE_API_KEY"))),
            ("local", bool(settings.local_model_api_base and settings.local_model_name)),
        ):
            key = (kind, incident_id)
            if enabled and key not in _triage_tasks:
                _triage_tasks.add(key)
                asyncio.create_task(_run_triage(incident_id, kind))
    return {"accepted": True, "result": result, "incident_id": incident_id}


@app.get("/api/v1/internal/policies")
async def gateway_policies(_: None = Depends(require_gateway_auth), db: Session = Depends(get_session)):
    key = require_signing_key()
    rows = db.scalars(
        select(Policy).where(
            Policy.site_id == settings.site_id,
            Policy.status == "active",
            Policy.expires_at > utcnow(),
        )
    ).all()
    return [signed_policy(row, key) for row in rows]


@app.get("/api/v1/sites")
def sites(_: str = Depends(require_auth), db: Session = Depends(get_session)):
    return [
        {"id": x.id, "name": x.name, "domain": x.domain, "deployment_mode": x.deployment_mode}
        for x in db.scalars(select(Site).order_by(Site.created_at)).all()
    ]


@app.get("/api/v1/events")
def events(
    limit: int = Query(100, ge=1, le=500),
    before: datetime | None = None,
    _: str = Depends(require_auth),
    db: Session = Depends(get_session),
):
    query = select(Event).where(Event.site_id == settings.site_id)
    if before:
        query = query.where(Event.occurred_at < before)
    rows = db.scalars(query.order_by(desc(Event.occurred_at)).limit(limit)).all()
    return [event_json(x) for x in rows]


@app.get("/api/v1/incidents")
def incidents(
    limit: int = Query(100, ge=1, le=500),
    state: str | None = Query(None, pattern="^(open|acknowledged|resolved)$"),
    _: str = Depends(require_auth),
    db: Session = Depends(get_session),
):
    query = select(Incident).where(Incident.site_id == settings.site_id)
    if state:
        query = query.where(Incident.status == state)
    return [incident_json(x) for x in db.scalars(query.order_by(desc(Incident.rank), desc(Incident.last_seen_at)).limit(limit)).all()]


@app.get("/api/v1/incidents/{incident_id}")
def incident_detail(incident_id: str, _: str = Depends(require_auth), db: Session = Depends(get_session)):
    row = db.get(Incident, incident_id)
    if row is None or row.site_id != settings.site_id:
        raise HTTPException(status_code=404, detail="Incident not found")
    result = incident_json(row)
    result["evidence"] = [
        event_json(event)
        for event in db.scalars(select(Event).where(Event.id.in_(row.evidence_event_ids or []))).all()
    ]
    result["policies"] = [policy_json(x) for x in db.scalars(select(Policy).where(Policy.source_incident_id == row.id)).all()]
    result["repairs"] = [repair_json(x, db.scalars(select(RepairCheck).where(RepairCheck.repair_id == x.id)).all()) for x in db.scalars(select(Repair).where(Repair.incident_id == row.id)).all()]
    return result


@app.post("/api/v1/incidents/{incident_id}/acknowledge")
def acknowledge(incident_id: str, request: Request, actor: str = Depends(require_new_request_id), db: Session = Depends(get_session)):
    row = db.get(Incident, incident_id)
    if row is None or row.site_id != settings.site_id:
        raise HTTPException(status_code=404, detail="Incident not found")
    if row.status != "open":
        raise HTTPException(status_code=409, detail="Only open incidents can be acknowledged")
    row.status = "acknowledged"
    record_audit(db, actor, "incident.update_status", row.id, "success", {"status": row.status}, request.headers.get("x-request-id"))
    db.commit()
    return incident_json(row)


@app.post("/api/v1/incidents/{incident_id}/resolve")
def resolve_incident(incident_id: str, request: Request, actor: str = Depends(require_new_request_id), db: Session = Depends(get_session)):
    row = db.get(Incident, incident_id)
    if row is None or row.site_id != settings.site_id:
        raise HTTPException(status_code=404, detail="Incident not found")
    if row.status == "resolved":
        raise HTTPException(status_code=409, detail="Incident is already resolved")
    row.status = "resolved"
    record_audit(db, actor, "incident.update_status", row.id, "success", {"status": row.status}, request.headers.get("x-request-id"))
    db.commit()
    return incident_json(row)


@app.get("/api/v1/policies")
def policies(_: str = Depends(require_auth), db: Session = Depends(get_session)):
    rows = db.scalars(select(Policy).where(Policy.site_id == settings.site_id).order_by(desc(Policy.expires_at))).all()
    return [policy_json(x) for x in rows]


class PolicyProposal(BaseModel):
    action: Literal["block", "rate_limit", "deceive"]
    reason: str = Field(min_length=8, max_length=400)
    ttl_seconds: int = Field(ge=30, le=3600)
    source_incident_id: str | None = None
    session_token: str = Field(min_length=8, max_length=128)
    route: Literal["/api/search"] = "/api/search"


def signed_policy(row: Policy, key: str) -> dict:
    import hashlib
    import json as json_module
    import hmac as hmac_module

    payload = {
        "id": row.id,
        "site_id": row.site_id,
        "action": row.action,
        "match_spec": row.match_spec,
        "version": row.version,
        "expires_at": as_utc(row.expires_at).isoformat().replace("+00:00", "Z"),
    }
    canonical = signed_policy_payload(payload, key)
    payload["signature"] = hmac_module.new(key.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return payload


@app.post("/api/v1/policies/proposals")
async def propose_policy(body: PolicyProposal, request: Request, actor: str = Depends(require_new_request_id), db: Session = Depends(get_session)):
    if body.action == "deceive" and settings.lab_mode not in {"observe-only", "lab-auto"}:
        raise HTTPException(status_code=403, detail="Deception policies are limited to the isolated lab")
    if body.source_incident_id and db.get(Incident, body.source_incident_id) is None:
        raise HTTPException(status_code=404, detail="Source incident not found")
    if not settings.source_hash_salt:
        raise HTTPException(status_code=503, detail="Session hashing is not configured")
    import hashlib

    session_hash = hashlib.sha256(f"{settings.source_hash_salt}:{body.session_token}".encode()).hexdigest()
    now = utcnow()
    row = Policy(
        id=str(uuid.uuid4()),
        site_id=settings.site_id,
        action=body.action,
        match_spec={"session_hash": session_hash, "route": body.route},
        reason=body.reason,
        source_incident_id=body.source_incident_id,
        created_by=actor,
        status="proposed",
        expires_at=now + timedelta(seconds=body.ttl_seconds),
        version=1,
    )
    db.add(row)
    record_audit(db, actor, "policy.propose", row.id, "success", {"action": row.action, "ttl_seconds": body.ttl_seconds}, request.headers.get("x-request-id"))
    db.commit()
    db.refresh(row)
    return policy_json(row)


@app.post("/api/v1/policies/{policy_id}/approve")
async def approve_policy(policy_id: str, request: Request, actor: str = Depends(require_new_request_id), db: Session = Depends(get_session)):
    row = db.get(Policy, policy_id)
    if row is None or row.site_id != settings.site_id:
        raise HTTPException(status_code=404, detail="Policy not found")
    if row.status != "proposed" or as_utc(row.expires_at) <= utcnow():
        raise HTTPException(status_code=409, detail="Policy is not an unexpired proposal")
    key = require_signing_key()
    row.status = "active"
    row.approved_by = actor
    row.activated_at = utcnow()
    record_audit(db, actor, "policy.approve", row.id, "success", {"action": row.action, "version": row.version}, request.headers.get("x-request-id"))
    db.commit()
    return policy_json(row)


@app.post("/api/v1/policies/{policy_id}/revoke")
async def revoke_policy(policy_id: str, request: Request, actor: str = Depends(require_new_request_id), db: Session = Depends(get_session)):
    row = db.get(Policy, policy_id)
    if row is None or row.site_id != settings.site_id:
        raise HTTPException(status_code=404, detail="Policy not found")
    if row.status == "active":
        row.status = "revoked"
        row.revoked_at = utcnow()
    record_audit(db, actor, "policy.revoke", row.id, "success", {"status": row.status}, request.headers.get("x-request-id"))
    db.commit()
    return policy_json(row)


@app.get("/api/v1/honeypot/interactions")
def honeypot_interactions(limit: int = Query(100, ge=1, le=500), _: str = Depends(require_auth), db: Session = Depends(get_session)):
    rows = db.scalars(select(HoneypotInteraction).where(HoneypotInteraction.site_id == settings.site_id).order_by(desc(HoneypotInteraction.occurred_at)).limit(limit)).all()
    return [{"id": x.id, "request_id": x.request_id, "occurred_at": as_utc(x.occurred_at).isoformat().replace("+00:00", "Z"), "decoy_id": x.decoy_id, "route": x.route, "result_status": x.result_status, "session_key_hash": x.session_key_hash} for x in rows]


@app.get("/api/v1/repairs")
def repairs(limit: int = Query(100, ge=1, le=500), _: str = Depends(require_auth), db: Session = Depends(get_session)):
    rows = db.scalars(select(Repair).where(Repair.site_id == settings.site_id).order_by(desc(Repair.proposed_at)).limit(limit)).all()
    return [repair_json(row, db.scalars(select(RepairCheck).where(RepairCheck.repair_id == row.id)).all()) for row in rows]


@app.get("/api/v1/integrations")
def integrations(_: str = Depends(require_auth)):
    return {
        "typesafe_jev": {"status": "configured_unverified" if os.getenv("TYPESAFE_API_CONFIGURED") == "true" else "not_configured", "role": "asynchronous incident triage"},
        "local_model": {
            "status": "configured" if settings.local_model_api_base and settings.local_model_name else "not_configured",
            "role": "advisory incident analysis; cannot change gateway policy",
            "provider": "OpenAI-compatible HTTP API" if settings.local_model_api_base and settings.local_model_name else None,
            "model": settings.local_model_name or None,
        },
        "coding_model": {"status": "not_configured", "role": "source repair proposal", "note": "No verified coding-model adapter is enabled in this lab build."},
        "github": {"status": "not_configured", "role": "optional reviewed pull request"},
        "crowdstrike_falcon": {"status": "not_configured", "role": "optional read-only telemetry"},
    }


@app.get("/api/v1/settings")
def settings_view(_: str = Depends(require_auth)):
    return {
        "site_id": settings.site_id,
        "lab_mode": settings.lab_mode,
        "management_authentication": "configured" if settings.api_token else "not_configured",
        "policy_signing": "configured" if settings.policy_signing_key else "not_configured",
        "source_ip_pseudonymization": "configured" if settings.source_hash_salt else "not_configured",
        "origin_url": settings.origin_url,
        "origin_profile": os.getenv("APP_PROFILE", "lab"),
        "lab_vulnerable_origin": os.getenv("LAB_VULNERABLE", "0") == "1",
    }


@app.get("/api/v1/metrics")
def metrics(_: str = Depends(require_auth), db: Session = Depends(get_session)):
    now = utcnow()
    recent_start = now - timedelta(seconds=60)
    events_last_minute = db.scalar(select(func.count()).select_from(Event).where(Event.site_id == settings.site_id, Event.occurred_at >= recent_start)) or 0
    total_events = db.scalar(select(func.count()).select_from(Event).where(Event.site_id == settings.site_id)) or 0
    open_incidents = db.scalar(select(func.count()).select_from(Incident).where(Incident.site_id == settings.site_id, Incident.status == "open")) or 0
    decoys = db.scalar(select(func.count()).select_from(HoneypotInteraction).where(HoneypotInteraction.site_id == settings.site_id)) or 0
    avg_latency = db.scalar(select(func.avg(Event.duration_ms)).where(Event.site_id == settings.site_id))
    avg_detection_latency = db.scalar(select(func.avg(Incident.request_to_alert_latency_ms)).where(Incident.site_id == settings.site_id))
    last_event = db.scalar(select(func.max(Event.occurred_at)).where(Event.site_id == settings.site_id))
    return {
        "events_per_second": round(events_last_minute / 60, 3),
        "events_last_minute": events_last_minute,
        "total_events": total_events,
        "open_incidents": open_incidents,
        "honeypot_interactions": decoys,
        "average_response_latency_ms": round(float(avg_latency), 2) if avg_latency is not None else None,
        "average_request_to_alert_latency_ms": round(float(avg_detection_latency), 2) if avg_detection_latency is not None else None,
        "last_event_at": as_utc(last_event).isoformat().replace("+00:00", "Z") if last_event else None,
        "telemetry_freshness": "empty" if last_event is None else "fresh" if (now - as_utc(last_event)).total_seconds() < 30 else "stale",
        "lab_mode": settings.lab_mode,
    }


@app.get("/api/v1/evaluations")
def evaluation_get(_: str = Depends(require_auth), db: Session = Depends(get_session)):
    from counterflow.models import EvaluationRun

    row = db.scalar(select(EvaluationRun).order_by(desc(EvaluationRun.created_at)).limit(1))
    return {"latest": {"id": row.id, "created_at": row.created_at.isoformat(), "dataset": row.dataset, "metrics": row.metrics} if row else None, "dataset_label": "synthetic"}


@app.post("/api/v1/evaluations/run")
def evaluation_run(request: Request, actor: str = Depends(require_new_request_id), db: Session = Depends(get_session)):
    from counterflow.evaluation import evaluate_file
    from counterflow.models import EvaluationRun

    dataset = Path(os.getenv("EVALUATION_DATASET", "data/evaluation/events.jsonl"))
    if not dataset.is_file():
        raise HTTPException(status_code=503, detail="Labeled evaluation fixture is unavailable")
    result = evaluate_file(dataset)
    row = EvaluationRun(id=str(uuid.uuid4()), dataset="synthetic:data/evaluation/events.jsonl", metrics=result)
    db.add(row)
    record_audit(db, actor, "evaluation.run", row.id, "success", {"dataset_size": result["dataset_size"]}, request.headers.get("x-request-id"))
    db.commit()
    return {"id": row.id, "created_at": row.created_at.isoformat(), "dataset": row.dataset, "metrics": result, "dataset_label": "synthetic"}


@app.get("/api/v1/stream")
async def stream(last_event_id: str | None = Header(default=None), _: str = Depends(require_auth)):
    cursor_time = utcnow() - timedelta(seconds=15)
    cursor_id = ""
    if last_event_id:
        with SessionLocal() as initial_db:
            cursor_event = initial_db.get(Event, last_event_id)
        if cursor_event and cursor_event.site_id == settings.site_id:
            cursor_time = as_utc(cursor_event.occurred_at)
            cursor_id = cursor_event.id
    incident_cursor_time = utcnow() - timedelta(seconds=15)
    incident_cursor_id = ""

    async def events_stream():
        nonlocal cursor_time, cursor_id, incident_cursor_time, incident_cursor_id
        while True:
            frames: list[str] = []
            with SessionLocal() as db:
                query = select(Event).where(
                    Event.site_id == settings.site_id,
                    or_(Event.occurred_at > cursor_time, and_(Event.occurred_at == cursor_time, Event.id > cursor_id)),
                )
                rows = db.scalars(query.order_by(Event.occurred_at, Event.id).limit(100)).all()
                for row in rows:
                    cursor_time, cursor_id = as_utc(row.occurred_at), row.id
                    frames.append(f"id: {row.id}\nevent: request\ndata: {json.dumps(event_json(row), separators=(',', ':'))}\n\n")
                incident_query = select(Incident).where(
                    Incident.site_id == settings.site_id,
                    or_(
                        Incident.last_seen_at > incident_cursor_time,
                        and_(Incident.last_seen_at == incident_cursor_time, Incident.id > incident_cursor_id),
                    ),
                )
                incidents_rows = db.scalars(incident_query.order_by(Incident.last_seen_at, Incident.id).limit(100)).all()
                for row in incidents_rows:
                    frames.append(f"event: incident\ndata: {json.dumps(incident_json(row), separators=(',', ':'))}\n\n")
                    incident_cursor_time, incident_cursor_id = as_utc(row.last_seen_at), row.id
            for frame in frames:
                yield frame
            yield ": keepalive\n\n"
            await asyncio.sleep(2)

    return StreamingResponse(events_stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


class RepairRequest(BaseModel):
    model_provider: Literal["configured", "deterministic-baseline"] = "configured"


@app.post("/api/v1/incidents/{incident_id}/repair")
def create_repair(incident_id: str, request: Request, body: RepairRequest = RepairRequest(), actor: str = Depends(require_new_request_id), db: Session = Depends(get_session)):
    incident = db.get(Incident, incident_id)
    if incident is None or incident.site_id != settings.site_id:
        raise HTTPException(status_code=404, detail="Incident not found")
    existing = db.scalar(select(Repair).where(Repair.incident_id == incident_id, Repair.status.not_in(["failed", "cancelled"])).limit(1))
    if existing:
        return repair_json(existing, db.scalars(select(RepairCheck).where(RepairCheck.repair_id == existing.id)).all())
    provider = "deterministic-baseline" if body.model_provider == "deterministic-baseline" else "not_configured"
    initial_status = "queued" if provider == "deterministic-baseline" else "waiting_for_model"
    row = Repair(
        id=str(uuid.uuid4()),
        site_id=settings.site_id,
        incident_id=incident_id,
        repository="local:services/lab-origin",
        commit_base="workspace-source",
        branch=None,
        status=initial_status,
        model_provider=provider,
        diff_summary="" if provider != "not_configured" else "No verified coding-model adapter is configured. No patch has been generated.",
    )
    db.add(row)
    record_audit(db, actor, "repair.create", row.id, "success", {"model_provider": provider, "status": initial_status}, request.headers.get("x-request-id"))
    db.commit()
    db.refresh(row)
    if provider == "deterministic-baseline":
        from counterflow.repair import run_baseline

        run_baseline(row.id)
        db.refresh(row)
    return repair_json(row, db.scalars(select(RepairCheck).where(RepairCheck.repair_id == row.id)).all())


@app.get("/api/v1/repairs/{repair_id}")
def get_repair(repair_id: str, _: str = Depends(require_auth), db: Session = Depends(get_session)):
    row = db.get(Repair, repair_id)
    if row is None or row.site_id != settings.site_id:
        raise HTTPException(status_code=404, detail="Repair not found")
    return repair_json(row, db.scalars(select(RepairCheck).where(RepairCheck.repair_id == row.id)).all())


@app.get("/api/v1/repairs/{repair_id}/logs")
def repair_logs(repair_id: str, _: str = Depends(require_auth), db: Session = Depends(get_session)):
    row = db.get(Repair, repair_id)
    if row is None or row.site_id != settings.site_id or not row.artifact_path:
        raise HTTPException(status_code=404, detail="Repair logs not found")
    root = Path(settings.repair_artifact_dir).resolve()
    log_path = (Path(row.artifact_path).resolve().parent / "repair.log").resolve()
    if not log_path.is_relative_to(root) or not log_path.is_file():
        raise HTTPException(status_code=404, detail="Repair logs not found")
    return {"repair_id": repair_id, "log": log_path.read_text(encoding="utf-8")[-100000:]}


@app.post("/api/v1/repairs/{repair_id}/run-baseline")
def run_repair_baseline(repair_id: str, request: Request, actor: str = Depends(require_new_request_id), db: Session = Depends(get_session)):
    row = db.get(Repair, repair_id)
    if row is None or row.site_id != settings.site_id:
        raise HTTPException(status_code=404, detail="Repair not found")
    if row.status not in {"waiting_for_model", "failed"}:
        raise HTTPException(status_code=409, detail="Repair is not eligible for a baseline run")
    row.model_provider = "deterministic-baseline"
    row.status = "queued"
    db.commit()
    from counterflow.repair import run_baseline

    run_baseline(repair_id)
    db.refresh(row)
    record_audit(db, actor, "repair.run_deterministic_baseline", row.id, "success" if row.status == "awaiting_approval" else "failure", {"status": row.status}, request.headers.get("x-request-id"))
    db.commit()
    return repair_json(row, db.scalars(select(RepairCheck).where(RepairCheck.repair_id == row.id)).all())


@app.post("/api/v1/repairs/{repair_id}/approve-lab-promotion")
def approve_lab_promotion(repair_id: str, request: Request, actor: str = Depends(require_new_request_id), db: Session = Depends(get_session)):
    row = db.get(Repair, repair_id)
    if row is None or row.site_id != settings.site_id:
        raise HTTPException(status_code=404, detail="Repair not found")
    if row.status != "awaiting_approval":
        raise HTTPException(status_code=409, detail="Only a proposed repair with passing checks can be approved")
    row.approved_at = utcnow()
    row.status = "approved_for_manual_lab_promotion"
    record_audit(db, actor, "repair.approve_lab_promotion", row.id, "success", {"status": row.status, "deployment": "not_performed"}, request.headers.get("x-request-id"))
    db.commit()
    return {**repair_json(row, db.scalars(select(RepairCheck).where(RepairCheck.repair_id == row.id)).all()), "deployment_status": "not_performed", "next_step": "Run scripts/promote-lab-repair.ps1 on Computer B after reviewing the saved diff."}


@app.get("/api/v1/audit")
def audit(limit: int = Query(100, ge=1, le=500), _: str = Depends(require_auth), db: Session = Depends(get_session)):
    rows = db.scalars(select(AuditEvent).where(AuditEvent.organization_id == "counterflow-lab").order_by(desc(AuditEvent.created_at)).limit(limit)).all()
    return [{"id": x.id, "principal_id": x.principal_id, "action": x.action, "target": x.target, "created_at": x.created_at.isoformat(), "outcome": x.outcome, "detail": x.detail_json} for x in rows]
