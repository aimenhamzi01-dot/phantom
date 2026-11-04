"""
PHANTOM — Basic Tests
Run with: pytest tests/ -v
"""
import pytest
from fastapi.testclient import TestClient
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Mock env before importing app
os.environ.setdefault("MODEL_API_KEY", "test-meta-key")
os.environ.setdefault("PHANTOM_API_TOKEN", "test-phantom-token")
os.environ.setdefault("MIZAN_PHANTOM_SIGNING_KEY", "test-signing-key-that-is-at-least-32-chars")
os.environ.setdefault("PHANTOM_ALLOWED_TARGETS", "https://example.com")

from main import app

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
    response = client.get("/scans")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


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
