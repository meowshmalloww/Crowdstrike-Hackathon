from fastapi.testclient import TestClient

from services.honeypot.app.main import app


def test_unmatched_injection_search_returns_only_fictional_decoys():
    response = TestClient(app).get("/api/search", params={"q": "' OR 1=1 --"})

    assert response.status_code == 200
    products = response.json()["products"]
    assert products
    assert all(product["id"].startswith("decoy-") for product in products)
    assert "synthetic-canary-2026" not in response.text
