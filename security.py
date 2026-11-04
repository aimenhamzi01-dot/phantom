"""Security controls for the Mizan -> Phantom handoff."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

SIGNATURE_ALGORITHM = "HMAC-SHA256"
ALLOWED_TYPES = {"web", "mobile", "hardware", "code"}
ALLOWED_SCOPES = {"xss", "sqli", "ssrf", "idor", "logic", "auth", "rce", "crypto", "secrets", "misconfiguration"}


def _signing_key() -> bytes:
    value = os.getenv("MIZAN_PHANTOM_SIGNING_KEY", "").strip()
    if len(value) < 32:
        raise ValueError("MIZAN_PHANTOM_SIGNING_KEY is required and must be at least 32 characters.")
    return value.encode()


def canonical_manifest(manifest: dict) -> bytes:
    unsigned = {k: v for k, v in manifest.items() if k not in {"signature", "signature_algorithm"}}
    return json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def verify_signature(manifest: dict) -> bool:
    signature = manifest.get("signature")
    if manifest.get("signature_algorithm") != SIGNATURE_ALGORITHM or not isinstance(signature, str):
        return False
    if len(signature) != 64:
        return False
    try:
        expected = hmac.new(_signing_key(), canonical_manifest(manifest), hashlib.sha256).hexdigest()
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(signature, expected)


def _allowed_targets() -> list[str]:
    return [item.strip().rstrip("/") for item in os.getenv("PHANTOM_ALLOWED_TARGETS", "").split(",") if item.strip()]


def resolve_public_ips(host: str) -> list[str]:
    """Resolve once and return only public IPs; callers must pin subsequent sockets to these."""
    try:
        answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError("Target hostname could not be resolved.") from exc
    addresses = set()
    for item in answers:
        try:
            address = ipaddress.ip_address(item[4][0].split("%", 1)[0])
        except ValueError as exc:
            raise ValueError("Target resolved to an invalid IP address.") from exc
        if not address.is_global:
            raise ValueError("Only globally routable target addresses are permitted.")
        addresses.add(str(address))
    if not addresses:
        raise ValueError("Target hostname has no address.")
    return sorted(addresses)


def _target_is_allowlisted(target: str) -> None:
    allowed = _allowed_targets()
    if not allowed:
        raise ValueError("PHANTOM_ALLOWED_TARGETS must contain an authorized target.")
    normalized = target.rstrip("/")
    if not any(normalized == item or normalized.startswith(item + "/") for item in allowed):
        raise ValueError("Target is not in PHANTOM_ALLOWED_TARGETS.")


def validate_target(target: str, target_type: str) -> str:
    target = target.strip()
    if target_type in {"web", "code"}:
        parsed = urlparse(target)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Web and code targets must be HTTPS URLs without embedded credentials.")
        if parsed.port not in (None, 443):
            raise ValueError("Only the default HTTPS port is allowed.")
        if parsed.fragment:
            raise ValueError("Target fragments are not allowed.")
    _target_is_allowlisted(target)
    if target_type in {"web", "code"}:
        resolve_public_ips(parsed.hostname)
    return target


def resolve_target_ips(target: str, target_type: str) -> list[str]:
    """Resolve a previously allowlisted target immediately before scheduling its pinned request."""
    if target_type not in {"web", "code"}:
        return []
    parsed = urlparse(target)
    if parsed.scheme != "https" or not parsed.hostname or parsed.port not in (None, 443):
        raise ValueError("Web and code targets must be default-port HTTPS URLs.")
    _target_is_allowlisted(target)
    return resolve_public_ips(parsed.hostname)


def verify_manifest(manifest: dict) -> tuple[str, str, list[str]]:
    if not isinstance(manifest, dict) or not verify_signature(manifest):
        raise ValueError("Unsigned or invalid Mizan manifest.")
    if manifest.get("format") != "mizan-phantom-task-v1":
        raise ValueError("Unsupported Mizan manifest format.")
    try:
        expires = datetime.fromisoformat(str(manifest["expires_at"]).replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Manifest expiry is invalid.") from exc
    if expires.tzinfo is None or expires.utcoffset() is None:
        raise ValueError("Manifest expiry must include a timezone.")
    if expires <= datetime.now(timezone.utc):
        raise ValueError("Mizan manifest has expired.")
    target = manifest.get("target")
    target_type = manifest.get("target_type")
    scope = manifest.get("scope")
    if not isinstance(target, str) or target_type not in ALLOWED_TYPES or not isinstance(scope, list) or not scope:
        raise ValueError("Manifest target or scope is invalid.")
    normalized_scope = [str(item).strip().lower() for item in scope]
    if len(normalized_scope) > 12 or any(item not in ALLOWED_SCOPES for item in normalized_scope):
        raise ValueError("Manifest scope is outside the allowed categories.")
    execution = manifest.get("execution")
    if (
        not isinstance(execution, dict)
        or execution.get("mode") != "manual-handoff-only"
        or execution.get("automatic_execution") is not False
        or execution.get("network_access_by_mizan") is not False
        or type(execution.get("max_duration_minutes")) is not int
        or execution.get("max_duration_minutes") != 20
        or execution.get("result_format") != "phantom-scan-result-v1"
    ):
        raise ValueError("Manifest execution policy is not allowed.")
    return validate_target(target, target_type), target_type, normalized_scope


def require_api_token(value: str | None) -> None:
    expected = os.getenv("PHANTOM_API_TOKEN", "").strip()
    if not expected or not value or not hmac.compare_digest(value, expected):
        raise PermissionError("A valid Phantom API token is required.")
