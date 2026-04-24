"""Health endpoint tests."""

from __future__ import annotations


def test_liveness(client) -> None:
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_readiness_has_model_version(client) -> None:
    resp = client.get("/readyz")
    assert resp.status_code == 200
    assert "model_version" in resp.json()
