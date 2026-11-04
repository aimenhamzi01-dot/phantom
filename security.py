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
    except ValueError:
        return False
    return hmac.compare_digest(signature, expected)


def _allowed_targets() -> list[str]:
    return [item.strip().rstrip("/") for item in os.getenv("PHANTOM_ALLOWED_TARGETS", "").split(",") if item.strip()]


def _host_is_public(host: str) -> bool:
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
    except OSError as exc:
        raise ValueError("Target hostname could not be resolved.") from exc
    if not addresses:
        raise ValueError("Target hostname has no address.")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise ValueError("Private, loopback, link-local, reserved, or multicast targets are forbidden.")
    return True


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
        _host_is_public(parsed.hostname)
    allowed = _allowed_targets()
    if not allowed:
        raise ValueError("PHANTOM_ALLOWED_TARGETS must contain an authorized target.")
    normalized = target.rstrip("/")
    if not any(normalized == item or normalized.startswith(item + "/") for item in allowed):
        raise ValueError("Target is not in PHANTOM_ALLOWED_TARGETS.")
    return target


def verify_manifest(manifest: dict) -> tuple[str, str, list[str]]:
    if not isinstance(manifest, dict) or not verify_signature(manifest):
        raise ValueError("Unsigned or invalid Mizan manifest.")
    if manifest.get("format") != "mizan-phantom-task-v1":
        raise ValueError("Unsupported Mizan manifest format.")
    try:
        expires = datetime.fromisoformat(str(manifest["expires_at"]).replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Manifest expiry is invalid.") from exc
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
    if not isinstance(execution, dict) or execution.get("mode") != "manual-handoff-only" or execution.get("automatic_execution") is not False:
        raise ValueError("Manifest execution policy is not allowed.")
    return validate_target(target, target_type), target_type, normalized_scope


def require_api_token(value: str | None) -> None:
    expected = os.getenv("PHANTOM_API_TOKEN", "").strip()
    if not expected or not value or not hmac.compare_digest(value, expected):
        raise PermissionError("A valid Phantom API token is required.")
