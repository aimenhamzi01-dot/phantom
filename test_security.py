import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from security import verify_manifest, canonical_manifest

KEY = "test-signing-key-that-is-at-least-32-chars"


def signed_manifest(**changes):
    now = datetime.now(timezone.utc)
    value = {
        "format": "mizan-phantom-task-v1",
        "task_id": "task-1",
        "created_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "target": "https://example.com/app",
        "target_type": "web",
        "scope": ["xss"],
        "execution": {"mode": "manual-handoff-only", "automatic_execution": False},
    }
    value.update(changes)
    value["signature_algorithm"] = "HMAC-SHA256"
    value["signature"] = hmac.new(KEY.encode(), canonical_manifest(value), hashlib.sha256).hexdigest()
    return value


def test_accepts_valid_manifest(monkeypatch):
    monkeypatch.setenv("MIZAN_PHANTOM_SIGNING_KEY", KEY)
    monkeypatch.setenv("PHANTOM_ALLOWED_TARGETS", "https://example.com")
    target, target_type, scope = verify_manifest(signed_manifest())
    assert target == "https://example.com/app"
    assert target_type == "web"
    assert scope == ["xss"]


def test_rejects_tampered_manifest(monkeypatch):
    monkeypatch.setenv("MIZAN_PHANTOM_SIGNING_KEY", KEY)
    monkeypatch.setenv("PHANTOM_ALLOWED_TARGETS", "https://example.com")
    manifest = signed_manifest()
    manifest["scope"] = ["rce"]
    with pytest.raises(ValueError, match="invalid Mizan manifest"):
        verify_manifest(manifest)


def test_rejects_expired_manifest(monkeypatch):
    monkeypatch.setenv("MIZAN_PHANTOM_SIGNING_KEY", KEY)
    monkeypatch.setenv("PHANTOM_ALLOWED_TARGETS", "https://example.com")
    manifest = signed_manifest(expires_at="2000-01-01T00:00:00Z")
    manifest["signature"] = hmac.new(KEY.encode(), canonical_manifest(manifest), hashlib.sha256).hexdigest()
    with pytest.raises(ValueError, match="expired"):
        verify_manifest(manifest)


def test_rejects_target_outside_allowlist(monkeypatch):
    monkeypatch.setenv("MIZAN_PHANTOM_SIGNING_KEY", KEY)
    monkeypatch.setenv("PHANTOM_ALLOWED_TARGETS", "https://authorized.example")
    with pytest.raises(ValueError, match="PHANTOM_ALLOWED_TARGETS"):
        verify_manifest(signed_manifest())
