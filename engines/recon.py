import asyncio
import logging
import socket
from urllib.parse import urlparse

import dns.resolver

from config import config
from engines.pinned_http import request_https, tls_info
from engines.static_analysis import StaticAnalysisEngine
from models.schemas import ReconResult

logger = logging.getLogger("phantom.recon")


class ReconEngine:
    def __init__(self):
        self.static_engine = StaticAnalysisEngine()

    async def run(self, target: str, target_type: str, pinned_ips: list[str] | None = None) -> ReconResult:
        result = ReconResult()
        pinned_ips = pinned_ips or []
        if target_type == "web":
            parsed = urlparse(target)
            result.domain = parsed.hostname or parsed.netloc
            await asyncio.gather(
                self._probe_http(target, result, pinned_ips),
                self._resolve_dns(result.domain, result),
                self._check_ssl(result.domain, result, pinned_ips),
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
            await self._analyze_source(target, result, pinned_ips)
        return result

    async def _analyze_source(self, url, result, pinned_ips):
        try:
            analysis = await self.static_engine.analyze(url, pinned_ips)
            result.source_fetched = analysis["fetched"]
            result.lines_of_code = analysis["loc"]
            result.static_findings = analysis["findings"]
            result.analysis_status = analysis.get("status", "unknown")
            result.analysis_engine = analysis.get("engine")
            result.analysis_config = analysis.get("config")
            result.source_sha256 = analysis.get("source_sha256")
            result.source_bytes = analysis.get("source_bytes", 0)
            if not analysis["fetched"]:
                logger.warning("Could not fetch source for %s: %s", url, analysis["error"])
            else:
                logger.info("Fetched %d LOC, Semgrep found %d raw findings", result.lines_of_code, len(result.static_findings))
        except Exception as exc:
            logger.error("Static analysis failed for %s: %s", url, exc)

    async def _probe_http(self, url, result, pinned_ips):
        try:
            status_code, headers, _ = await request_https(
                url, pinned_ips, timeout=config.HTTP_TIMEOUT, max_bytes=None
            )
            result.status_code = status_code
            result.headers = headers
            result.server = headers.get("server", headers.get("x-powered-by", "Unknown"))
            header_text = str(headers).lower()
            signatures = {
                "nginx": "Nginx", "apache": "Apache", "cloudflare": "Cloudflare",
                "express": "Express.js", "django": "Django", "php": "PHP",
                "asp.net": "ASP.NET", "node": "Node.js", "next": "Next.js", "aws": "AWS",
            }
            result.technologies = list({name for signature, name in signatures.items() if signature in header_text})
        except Exception as exc:
            logger.warning("HTTP probe failed: %s", exc)

    async def _resolve_dns(self, domain, result):
        await asyncio.to_thread(self._resolve_dns_sync, domain, result)

    @staticmethod
    def _resolve_dns_sync(domain, result):
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

    async def _check_ssl(self, domain, result, pinned_ips):
        try:
            result.ssl_info = await tls_info(domain, pinned_ips, timeout=5.0)
        except Exception as exc:
            result.ssl_info = {"error": str(exc)}

    async def close(self):
        await self.static_engine.close()
