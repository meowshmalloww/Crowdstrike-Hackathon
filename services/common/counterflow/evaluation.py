from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .detection import assess_event, detect_query


def evaluate_rows(rows: Iterable[dict]) -> dict:
    tp = fp = tn = fn = 0
    alerts = 0
    alert_groups: set[str] = set()
    latency_samples: list[float] = []
    for row in rows:
        expected = bool(row["label"])
        event = dict(row["event"])
        query = row.get("query", "")
        event.setdefault("signal_features", {}).update(detect_query(query))
        predicted = assess_event(event, int(row.get("related_count", 1)))["score"] >= 15
        alerts += int(predicted)
        if predicted:
            alert_groups.add(str(row.get("correlation_id", row.get("id", alerts))))
            if row.get("alert_latency_ms") is not None:
                latency_samples.append(float(row["alert_latency_ms"]))
        if predicted and expected:
            tp += 1
        elif predicted:
            fp += 1
        elif expected:
            fn += 1
        else:
            tn += 1
    size = tp + fp + tn + fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {
        "dataset_size": size,
        "labels": "synthetic",
        "threshold": 15,
        "confusion_matrix": {"true_positive": tp, "false_positive": fp, "true_negative": tn, "false_negative": fn},
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "alert_dedup_ratio": round(1 - len(alert_groups) / alerts, 4) if alerts else 0.0,
        "request_to_alert_latency_ms": round(sum(latency_samples) / len(latency_samples), 2) if latency_samples else None,
        "limitation": "A small labeled synthetic fixture measures only this deterministic rule set; it is not a field-performance estimate.",
    }


def evaluate_file(path: str | Path) -> dict:
    rows = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    return evaluate_rows(rows)
