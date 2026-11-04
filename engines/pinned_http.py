"""HTTPS requests pinned to already-validated public IP addresses."""
from __future__ import annotations

import asyncio
import http.client
import ipaddress
import socket
import ssl
from urllib.parse import urlsplit


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to a pinned IP while validating TLS against the original hostname."""

    def __init__(self, hostname: str, address: str, *, timeout: float):
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ValueError("Only globally routable addresses may be contacted.")
        self._pinned_address = str(ip)
        super().__init__(hostname, port=443, timeout=timeout, context=ssl.create_default_context())

    def connect(self) -> None:
        sock = socket.create_connection((self._pinned_address, 443), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise


def _request_sync(url: str, addresses: list[str], timeout: float, max_bytes: int | None):
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.port not in (None, 443):
        raise ValueError("Pinned HTTPS client accepts only default-port HTTPS URLs.")
    if not addresses:
        raise ValueError("No validated destination addresses were supplied.")
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    host_header = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    last_error = None
    for address in addresses:
        connection = PinnedHTTPSConnection(parsed.hostname, address, timeout=timeout)
        try:
            connection.request("GET", path, headers={"Host": host_header, "User-Agent": "PHANTOM/secure-mizan-worker"})
            response = connection.getresponse()
            headers = {key.lower(): value for key, value in response.getheaders()}
            body = b""
            if max_bytes is not None:
                length = headers.get("content-length")
                if length and length.isdecimal() and int(length) > max_bytes:
                    raise ValueError("Remote response exceeds the configured size limit.")
                chunks = []
                total = 0
                while True:
                    chunk = response.read(min(64 * 1024, max_bytes + 1 - total))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValueError("Remote response exceeds the configured size limit.")
                    chunks.append(chunk)
                body = b"".join(chunks)
            return response.status, headers, body
        except ValueError:
            raise
        except Exception as exc:
            last_error = exc
        finally:
            connection.close()
    if last_error:
        raise last_error
    raise OSError("No validated destination address could be reached.")


async def request_https(url: str, addresses: list[str], *, timeout: float = 15.0, max_bytes: int | None = None):
    """Perform a request without resolving the URL hostname during connection."""
    return await asyncio.to_thread(_request_sync, url, addresses, timeout, max_bytes)


def _tls_info_sync(hostname: str, addresses: list[str], timeout: float):
    context = ssl.create_default_context()
    last_error = None
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ValueError("Only globally routable addresses may be contacted.")
        raw = None
        try:
            raw = socket.create_connection((str(ip), 443), timeout=timeout)
            with context.wrap_socket(raw, server_hostname=hostname) as secure:
                certificate = secure.getpeercert()
                return {
                    "issuer": dict(item[0] for item in certificate.get("issuer", [])),
                    "notAfter": certificate.get("notAfter"),
                    "protocol": secure.version(),
                }
        except Exception as exc:
            last_error = exc
            if raw is not None:
                raw.close()
    if last_error:
        raise last_error
    raise OSError("No validated destination address could be reached.")


async def tls_info(hostname: str, addresses: list[str], *, timeout: float = 5.0):
    return await asyncio.to_thread(_tls_info_sync, hostname, addresses, timeout)
