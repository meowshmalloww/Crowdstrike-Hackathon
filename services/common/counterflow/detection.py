from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

SQLI_RE = re.compile(
    r"(?:\bunion\s+(?:all\s+)?select\b|\b(?:or|and)\s+\d+\s*=\s*\d+\b|"
    r"\bselect\b.{0,40}\bfrom\b|\bsleep\s*\(|\bbenchmark\s*\(|--\s|/\*.*?\*/)",
    re.IGNORECASE | re.DOTALL,
)
SCANNER_RE = re.compile(r"(?:\.\./|/\.env\b|/wp-admin\b|/phpmyadmin\b|/cgi-bin\b)", re.I)


def detect_query(query: str) -> dict[str, bool]:
    """Return only bounded booleans; raw query text is never persisted."""
    return {"sqli_pattern": bool(SQLI_RE.search(query)), "scanner_probe": bool(SCANNER_RE.search(query))}


def correlation_key(site_id: str, route: str, source_hash: str | None, classification: str) -> str:
    raw = "|".join((site_id, route, source_hash or "unknown-source", classification))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def assess_event(event: dict[str, Any], repeated_count: int) -> dict[str, Any]:
    signals = event.get("signal_features") or event.get("signals") or {}
    rule_ids = event.get("waf_rule_ids") or []
    sqli = bool(signals.get("sqli_pattern") or any(942000 <= int(r) < 943000 for r in rule_ids))
    scanner = bool(signals.get("scanner_probe"))
    canary = bool(signals.get("canary_exposed"))
    waf = bool(rule_ids) or bool(signals.get("waf_interrupted"))
    contributions = {
        "sqli_or_waf_match": 40 if (sqli or waf) else 0,
        "repeated_attempts": 25 if repeated_count >= 2 else 0,
        "verified_canary_exposure": 35 if canary else 0,
        "scanner_probe": 15 if scanner and not (sqli or waf) else 0,
    }
    score = min(100, sum(contributions.values()))
    classification = "sql_injection" if (sqli or canary) else "scanner_probe" if scanner else "waf_rule_match" if waf else "uncertain"
    severity = "critical" if score >= 75 else "high" if score >= 50 else "medium" if score >= 25 else "low"
    evidence = []
    if sqli:
        evidence.append("Request features matched a bounded SQL-injection signature.")
    if waf:
        evidence.append("The configured WAF reported an interruption or rule match.")
    if repeated_count >= 2:
        evidence.append(f"The same source and route produced {repeated_count} related requests in the correlation window.")
    if canary:
        evidence.append("The response contained the synthetic canary marker from the disposable lab origin.")
    if scanner:
        evidence.append("The route included a known scanner or path-probe pattern.")
    if not evidence:
        evidence.append("No high-confidence malicious feature was observed; review the captured request metadata.")
    explanation = " ".join(evidence) + " Deterministic prototype score v1; this score is a ranking heuristic, not a probability."
    return {
        "score_version": "detector-v1",
        "classification": classification,
        "score": score,
        "severity": severity,
        "contributions": contributions,
        "explanation": explanation,
        "repeated_count": repeated_count,
    }


def signed_policy_payload(payload: dict[str, Any], key: str) -> str:
    """Canonical JSON body used by the Python and Go HMAC verifiers."""
    unsigned = {k: v for k, v in payload.items() if k != "signature"}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)
