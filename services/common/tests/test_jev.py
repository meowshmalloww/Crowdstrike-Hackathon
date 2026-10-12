import asyncio
import sys
from types import SimpleNamespace

from counterflow.jev import classify_incident


def test_jev_adapter_requests_a_typed_choice_from_the_redacted_summary(monkeypatch):
    observed = {}

    class FakeChoice:
        def __init__(self, *, instructions, criteria):
            self.instructions = instructions
            self.criteria = criteria

    class FakeClient:
        def __init__(self, *, model):
            observed["model"] = model

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return None

        async def system_one(self, *, state, questions):
            observed["state"] = state
            observed["question"] = questions["classification"]
            return SimpleNamespace(choices={
                "classification": SimpleNamespace(choice="sql_injection", confidence=0.91),
            })

    monkeypatch.setitem(sys.modules, "typesafe_sdk", SimpleNamespace(
        AsyncTypeSafeClient=FakeClient,
        Choice=FakeChoice,
    ))
    summary = {
        "route": "/api/search", "method": "GET", "response_status": 200,
        "related_request_count": 4,
        "features": {"sqli_pattern": True, "waf_interrupted": True},
        "waf_rule_ids": [942100], "action_counts": {"waf_blocked": 3, "deceived": 1},
        "waf_blocked_count": 3, "deceived_request_count": 1, "honeypot_request_count": 1,
    }

    choice, confidence = asyncio.run(classify_incident(summary))

    assert observed["model"] == "jev-latest"
    assert observed["state"]["waf_blocked_count"] == 3
    assert observed["state"]["waf_rule_ids"] == [942100]
    assert set(observed["question"].criteria) == {
        "sql_injection", "scanner_probe", "benign", "uncertain",
    }
    assert (choice, confidence) == ("sql_injection", 0.91)
