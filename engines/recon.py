import asyncio
import logging
import socket
import ssl
from urllib.parse import urlparse

import dns.resolver
import httpx

from config import config
from engines.static_analysis import StaticAnalysisEngine
from models.schemas import ReconResult

logger = logging.getLogger("phantom.recon")


class ReconEngine:
    def __init__(self):
        self.http = httpx.AsyncClient(
            timeout=config.HTTP_TIMEOUT,
            follow_redirects=False,
            verify=True,
            headers={"User-Agent": "PHANTOM/secure-mizan-worker"},
        )
        self.static_engine = StaticAnalysisEngine()

    async def run(self, target: str, target_type: str) -> ReconResult:
        result = ReconResult()
        if target_type == "web":
            parsed = urlparse(target)
            result.domain = parsed.hostname or parsed.netloc
            await asyncio.gather(
                self._probe_http(target, result),
                self._resolve_dns(result.domain, result),
                self._check_ssl(result.domain, result),
                return_exceptions=True,
            )
        elif target_type == "mobile":
            result.domain = target
            result.technologies = ["Android/iOS", "Mobile Application"]
        elif target_type == "hardware":
            result.domain = target
            result.technologies = ["Embedded System", "Firmware"]
        elif target_type == "code":
            result.domain = target
            await self._analyze_source(target, result)
        return result

    async def _analyze_source(self, url, result):
        try:
            analysis = await self.static_engine.analyze(url)
            result.source_fetched = analysis["fetched"]
            result.lines_of_code = analysis["loc"]
            result.static_findings = analysis["findings"]
            if not analysis["fetched"]:
                logger.warning("Could not fetch source for %s: %s", url, analysis["error"])
            else:
                logger.info("Fetched %d LOC, Semgrep found %d raw findings", result.lines_of_code, len(result.static_findings))
        except Exception as exc:
            logger.error("Static analysis failed for %s: %s", url, exc)

    async def _probe_http(self, url, result):
        try:
            response = await self.http.get(url)
            result.status_code = response.status_code
            result.headers = dict(response.headers)
            result.server = response.headers.get("server", response.headers.get("x-powered-by", "Unknown"))
            header_text = str(response.headers).lower()
            signatures = {
                "nginx": "Nginx", "apache": "Apache", "cloudflare": "Cloudflare",
                "express": "Express.js", "django": "Django", "php": "PHP",
                "asp.net": "ASP.NET", "node": "Node.js", "next": "Next.js", "aws": "AWS",
            }
            result.technologies = list({name for signature, name in signatures.items() if signature in header_text})
        except Exception as exc:
            logger.warning("HTTP probe failed: %s", exc)

    async def _resolve_dns(self, domain, result):
        try:
            records = {}
            for record_type in ("A", "MX", "TXT", "NS"):
                try:
                    answers = dns.resolver.resolve(domain, record_type, lifetime=5)
                    records[record_type] = [str(answer) for answer in answers]
                    if record_type == "A" and records[record_type]:
                        result.ip = records[record_type][0]
                except Exception:
                    continue
            result.dns_records = records
            result.subdomains = []
            for prefix in ("www", "api", "admin", "dev", "staging", "app", "portal"):
                try:
                    socket.gethostbyname(f"{prefix}.{domain}")
                    result.subdomains.append(f"{prefix}.{domain}")
                except OSError:
                    continue
        except Exception as exc:
            logger.warning("DNS failed: %s", exc)

    async def _check_ssl(self, domain, result):
        try:
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket(), server_hostname=domain) as sock:
                sock.settimeout(5)
                sock.connect((domain, 443))
                certificate = sock.getpeercert()
                result.ssl_info = {
                    "issuer": dict(item[0] for item in certificate.get("issuer", [])),
                    "notAfter": certificate.get("notAfter"),
                    "protocol": sock.version(),
                }
        except Exception as exc:
            result.ssl_info = {"error": str(exc)}

    async def close(self):
        await self.http.aclose()
        await self.static_engine.close()
