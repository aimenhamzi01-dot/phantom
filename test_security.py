import hashlib
import hmac
import socket
from datetime import datetime, timedelta, timezone

import pytest

from engines import pinned_http
from security import resolve_public_ips, validate_target, verify_manifest, canonical_manifest

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
        "execution": {
            "mode": "manual-handoff-only",
            "automatic_execution": False,
            "network_access_by_mizan": False,
            "max_duration_minutes": 20,
            "result_format": "phantom-scan-result-v1",
        },
    }
    value.update(changes)
    value["signature_algorithm"] = "HMAC-SHA256"
    value["signature"] = hmac.new(KEY.encode(), canonical_manifest(value), hashlib.sha256).hexdigest()
    return value


def set_public_dns(monkeypatch, address="93.184.216.34"):
    monkeypatch.setattr(
        "security.socket.getaddrinfo",
        lambda host, port, type=None: [
            (socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))
        ],
    )


def test_accepts_valid_manifest(monkeypatch):
    monkeypatch.setenv("MIZAN_PHANTOM_SIGNING_KEY", KEY)
    monkeypatch.setenv("PHANTOM_ALLOWED_TARGETS", "https://example.com")
    set_public_dns(monkeypatch)
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


def test_rejects_manifest_expiry_without_timezone(monkeypatch):
    monkeypatch.setenv("MIZAN_PHANTOM_SIGNING_KEY", KEY)
    manifest = signed_manifest(expires_at="2099-01-01T00:00:00")
    manifest["signature"] = hmac.new(KEY.encode(), canonical_manifest(manifest), hashlib.sha256).hexdigest()
    with pytest.raises(ValueError, match="timezone"):
        verify_manifest(manifest)


@pytest.mark.parametrize("field,value", [
    ("max_duration_minutes", 21),
    ("network_access_by_mizan", True),
    ("result_format", "unexpected-format"),
])
def test_rejects_execution_policy_changes(monkeypatch, field, value):
    monkeypatch.setenv("MIZAN_PHANTOM_SIGNING_KEY", KEY)
    manifest = signed_manifest()
    manifest["execution"][field] = value
    manifest["signature"] = hmac.new(KEY.encode(), canonical_manifest(manifest), hashlib.sha256).hexdigest()
    with pytest.raises(ValueError, match="execution policy"):
        verify_manifest(manifest)


def test_rejects_target_outside_allowlist(monkeypatch):
    monkeypatch.setenv("PHANTOM_ALLOWED_TARGETS", "https://authorized.example")
    with pytest.raises(ValueError, match="PHANTOM_ALLOWED_TARGETS"):
        verify_manifest(signed_manifest())


def test_allowlist_rejection_happens_before_dns_lookup(monkeypatch):
    monkeypatch.setenv("PHANTOM_ALLOWED_TARGETS", "https://authorized.example")
    monkeypatch.setattr("security.socket.getaddrinfo", lambda *args, **kwargs: pytest.fail("unexpected DNS lookup"))
    with pytest.raises(ValueError, match="PHANTOM_ALLOWED_TARGETS"):
        validate_target("https://other.example/path", "web")


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "169.254.1.1", "::1", "fc00::1"])
def test_rejects_non_global_dns_answers(monkeypatch, address):
    set_public_dns(monkeypatch, address)
    with pytest.raises(ValueError, match="globally routable"):
        resolve_public_ips("target.example")


def test_pinned_connection_uses_validated_ip_and_original_tls_name(monkeypatch):
    seen = {}

    class FakeSocket:
        def close(self):
            seen["closed"] = True

    class FakeTLSContext:
        def wrap_socket(self, sock, server_hostname):
            seen["sni"] = server_hostname
            return sock

    def fake_create_connection(address, timeout):
        seen["connect"] = address
        return FakeSocket()

    connection = pinned_http.PinnedHTTPSConnection("target.example", "93.184.216.34", timeout=2)
    connection._context = FakeTLSContext()
    monkeypatch.setattr(pinned_http.socket, "create_connection", fake_create_connection)
    connection.connect()
    assert seen["connect"] == ("93.184.216.34", 443)
    assert seen["sni"] == "target.example"
    connection.close()


def test_pinned_connection_refuses_private_ip():
    with pytest.raises(ValueError, match="globally routable"):
        pinned_http.PinnedHTTPSConnection("target.example", "127.0.0.1", timeout=2)
