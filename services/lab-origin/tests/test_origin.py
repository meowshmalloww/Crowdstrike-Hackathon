import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.mark.baseline_only
def test_disposable_baseline_canary_is_really_exposed_by_injection():
    with TestClient(create_app(vulnerable=True)) as client:
        response = client.get("/api/search", params={"q": "%' OR 1=1 --"})
    assert response.status_code == 200
    assert any(p["id"] == "synthetic-canary-2026" for p in response.json()["products"])


def test_safe_query_parameterization_hides_canary_and_keeps_search_working():
    with TestClient(create_app(vulnerable=False)) as client:
        benign = client.get("/api/search", params={"q": "mug"})
        injected = client.get("/api/search", params={"q": "%' OR 1=1 --"})
    assert benign.status_code == 200
    assert any(p["id"] == "prod-mug" for p in benign.json()["products"])
    assert all(p["id"] != "synthetic-canary-2026" for p in injected.json()["products"])


def test_apostrophe_in_normal_search_text_does_not_change_query_structure():
    with TestClient(create_app(vulnerable=False)) as client:
        response = client.get("/api/search", params={"q": "O'Reilly"})
    assert response.status_code == 200
    assert all(p["id"] != "synthetic-canary-2026" for p in response.json()["products"])


@pytest.mark.safe_after_patch
def test_lab_vulnerability_flag_cannot_reenable_injection_after_patch(monkeypatch):
    monkeypatch.setenv("APP_PROFILE", "lab")
    monkeypatch.setenv("LAB_VULNERABLE", "1")
    with TestClient(create_app()) as client:
        response = client.get("/api/search", params={"q": "%' OR 1=1 --"})
    assert response.status_code == 200
    assert all(p["id"] != "synthetic-canary-2026" for p in response.json()["products"])
