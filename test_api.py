"""
PHANTOM — Basic Tests
Run with: pytest -v
"""
import pytest
import asyncio
from fastapi.testclient import TestClient
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Mock env before importing app
os.environ.setdefault("MODEL_API_KEY", "test-meta-key")
os.environ.setdefault("PHANTOM_API_TOKEN", "test-phantom-token")
os.environ.setdefault("MIZAN_PHANTOM_SIGNING_KEY", "test-signing-key-that-is-at-least-32-chars")
os.environ.setdefault("PHANTOM_ALLOWED_TARGETS", "https://example.com")

import main
app = main.app

client = TestClient(app)


def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["phantom"] == "online"


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "ai_engine" in data
    assert "apis_configured" in data


def test_scan_not_found():
    response = client.get("/scan/NOTEXIST/status", headers={"X-Phantom-API-Token": "test-phantom-token"})
    assert response.status_code == 404


def test_list_scans_empty():
    response = client.get("/scans", headers={"X-Phantom-API-Token": "test-phantom-token"})
    assert response.status_code == 200
    assert isinstance(response.json(), list)


@pytest.mark.parametrize("method,path", [
    ("get", "/scans"),
    ("get", "/scan/NOTEXIST/report"),
    ("delete", "/scan/NOTEXIST"),
])
def test_sensitive_scan_routes_require_token(method, path):
    response = getattr(client, method)(path)
    assert response.status_code == 401


def test_report_and_delete_routes_accept_valid_token():
    headers = {"X-Phantom-API-Token": "test-phantom-token"}
    assert client.get("/scan/NOTEXIST/report", headers=headers).status_code == 404
    assert client.delete("/scan/NOTEXIST", headers=headers).status_code == 200


def test_scan_timeout_is_recorded_without_network_or_model_calls(monkeypatch):
    main.scan_store["TIMEOUT"] = {"status": "queued", "phase": "queued", "message": "queued", "progress": 0}

    async def timeout_without_running(coro, timeout):
        coro.close()
        raise asyncio.TimeoutError

    monkeypatch.setattr(main.asyncio, "wait_for", timeout_without_running)
    asyncio.run(main.run_scan("TIMEOUT", object(), []))
    assert main.scan_store["TIMEOUT"]["status"] == "error"
    assert "20 minutes" in main.scan_store["TIMEOUT"]["message"]


def test_scan_request_validation():
    # Empty target should fail
    response = client.post("/scan/start", json={"target": ""})
    assert response.status_code == 422


def test_scan_request_valid_structure():
    # Direct scans are rejected in secure mode even when the schema is valid.
    response = client.post("/scan/start", json={
        "target": "https://example.com",
        "target_type": "web",
        "scope": ["XSS", "SQLi"]
    }, headers={"X-Phantom-API-Token": "test-phantom-token"})
    assert response.status_code == 403
