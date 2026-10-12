import json
from pathlib import Path

from counterflow.detection import assess_event, detect_query
from counterflow.evaluation import evaluate_file


def test_detection_does_not_flag_apostrophes_unicode_or_punctuation_by_themselves():
    for value in ["O'Reilly", "children's books", "café ☕", "100% useful!", "Tokyo / map"]:
        features = detect_query(value)
        assert features == {"sqli_pattern": False, "scanner_probe": False}


def test_detection_flags_the_controlled_injection_and_scanner_examples():
    assert detect_query("%' OR 1=1 --")["sqli_pattern"] is True
    assert detect_query("' UNION SELECT id FROM products -- ")["sqli_pattern"] is True
    assert detect_query("/../../.env")["scanner_probe"] is True


def test_ranked_score_is_transparent_and_not_a_probability():
    base = {"signals": {"sqli_pattern": True}, "waf_rule_ids": [], "status": 403}
    single = assess_event(base, 1)
    repeated = assess_event(base, 3)
    canary = assess_event({"signals": {"sqli_pattern": True, "canary_exposed": True}}, 1)
    assert single["score"] == 40
    assert repeated["score"] == 65
    assert canary["score"] == 75
    assert single["score_version"] == "detector-v1"
    assert "not a probability" in single["explanation"]


def test_labeled_fixture_reports_measured_confusion_matrix():
    dataset = Path(__file__).resolve().parents[3] / "data" / "evaluation" / "events.jsonl"
    result = evaluate_file(dataset)
    assert result["labels"] == "synthetic"
    assert result["dataset_size"] == 20
    assert result["confusion_matrix"]["false_positive"] == 0
    assert result["false_positive_rate"] == 0
    assert result["request_to_alert_latency_ms"] is None
