from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class Site(Base):
    __tablename__ = "sites"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    allowed_origin_url: Mapped[str] = mapped_column(String(512), nullable=False)
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    deployment_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class IdempotencyRecord(Base):
    __tablename__ = "idempotency_records"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)


class Event(Base):
    __tablename__ = "events"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    site_id: Mapped[str] = mapped_column(ForeignKey("sites.id"), nullable=False)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    source_ip_pseudonym: Mapped[str | None] = mapped_column(String(64))
    session_key_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    route_template: Mapped[str] = mapped_column(String(255), nullable=False)
    method: Mapped[str] = mapped_column(String(16), nullable=False)
    response_status: Mapped[int] = mapped_column(Integer, nullable=False)
    duration_ms: Mapped[float] = mapped_column(Float, nullable=False)
    origin: Mapped[str] = mapped_column(String(32), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    waf_rule_ids: Mapped[list[int]] = mapped_column(JSON, default=list, nullable=False)
    waf_anomaly_score: Mapped[int | None] = mapped_column(Integer)
    anomaly_score: Mapped[int | None] = mapped_column(Integer)
    signal_features: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    payload_hash: Mapped[str | None] = mapped_column(String(64))
    raw_record_ref: Mapped[str | None] = mapped_column(String(255))


Index("ix_events_site_route_time", Event.site_id, Event.route_template, Event.occurred_at)
Index("ix_events_site_source_time", Event.site_id, Event.source_ip_pseudonym, Event.occurred_at)


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    site_id: Mapped[str] = mapped_column(ForeignKey("sites.id"), nullable=False)
    correlation_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False, index=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    classification: Mapped[str] = mapped_column(String(64), nullable=False)
    rank: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    score_version: Mapped[str] = mapped_column(String(32), nullable=False, default="detector-v1")
    request_to_alert_latency_ms: Mapped[float | None] = mapped_column(Float)
    model_status: Mapped[str] = mapped_column(String(32), nullable=False, default="not_configured")
    jev_choice: Mapped[str | None] = mapped_column(String(64))
    jev_confidence: Mapped[float | None] = mapped_column(Float)
    local_ai_status: Mapped[str] = mapped_column(String(32), nullable=False, default="not_configured")
    local_ai_summary: Mapped[str | None] = mapped_column(Text)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    score_contributions: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    evidence_event_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    estimated_impact: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class Policy(Base):
    __tablename__ = "policies"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    site_id: Mapped[str] = mapped_column(ForeignKey("sites.id"), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    match_spec: Mapped[dict] = mapped_column(JSON, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    source_incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id"))
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="proposed", index=True)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class HoneypotInteraction(Base):
    __tablename__ = "honeypot_interactions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    site_id: Mapped[str] = mapped_column(ForeignKey("sites.id"), nullable=False)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    decoy_id: Mapped[str] = mapped_column(String(64), nullable=False)
    route: Mapped[str] = mapped_column(String(255), nullable=False)
    result_status: Mapped[int] = mapped_column(Integer, nullable=False)
    session_key_hash: Mapped[str | None] = mapped_column(String(64))


class Repair(Base):
    __tablename__ = "repairs"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    site_id: Mapped[str] = mapped_column(ForeignKey("sites.id"), nullable=False)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), nullable=False)
    repository: Mapped[str] = mapped_column(String(512), nullable=False)
    commit_base: Mapped[str] = mapped_column(String(64), nullable=False)
    branch: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    model_provider: Mapped[str] = mapped_column(String(64), nullable=False)
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    pr_url: Mapped[str | None] = mapped_column(String(512))
    diff_summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    artifact_path: Mapped[str | None] = mapped_column(String(1024))
    proposed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RepairCheck(Base):
    __tablename__ = "repair_checks"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    repair_id: Mapped[str] = mapped_column(ForeignKey("repairs.id"), nullable=False, index=True)
    test_name: Mapped[str] = mapped_column(String(255), nullable=False)
    command_reference: Mapped[str] = mapped_column(String(255), nullable=False)
    exit_code: Mapped[int] = mapped_column(Integer, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ended_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    log_ref: Mapped[str] = mapped_column(String(1024), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (UniqueConstraint("organization_id", "principal_id", "request_id", name="uq_audit_request_id"),)
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    principal_id: Mapped[str] = mapped_column(String(128), nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    detail_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class EvaluationRun(Base):
    __tablename__ = "evaluation_runs"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    dataset: Mapped[str] = mapped_column(String(255), nullable=False)
    metrics: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
