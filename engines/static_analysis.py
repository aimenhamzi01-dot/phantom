"""
PHANTOM — Static Analysis Engine
Fetches authorized source over pinned HTTPS and runs Semgrep against inert text.
"""
import asyncio
import hashlib
import json
import logging
import os
import tempfile
from urllib.parse import urlsplit

from engines.pinned_http import request_https

logger = logging.getLogger("phantom.static")
MAX_SOURCE_BYTES = 2 * 1024 * 1024

SEMGREP_CONFIGS = {
    ".c": "p/c", ".cpp": "p/cpp", ".cc": "p/cpp", ".h": "p/c", ".hpp": "p/cpp",
    ".py": "p/python", ".js": "p/javascript", ".ts": "p/typescript",
    ".java": "p/java", ".go": "p/golang", ".rb": "p/ruby", ".php": "p/php",
}


class StaticAnalysisEngine:
    def _pick_config(self, filename: str) -> str:
        ext = os.path.splitext(filename)[1].lower()
        return SEMGREP_CONFIGS.get(ext, "p/security-audit")

    async def fetch_source(self, url: str, resolved_ips: list[str]):
        try:
            status, headers, content = await request_https(
                url, resolved_ips, timeout=30.0, max_bytes=MAX_SOURCE_BYTES
            )
            if status != 200:
                logger.warning("Source fetch failed: HTTP %s for %s", status, url)
                return None
            content_type = headers.get("content-type", "")
            charset = "utf-8"
            for part in content_type.split(";")[1:]:
                key, sep, value = part.strip().partition("=")
                if sep and key.lower() == "charset":
                    charset = value.strip(" \"'")[:40]
            text = content.decode(charset, errors="replace")
            if "?format=TEXT" in url:
                import base64
                try:
                    text = base64.b64decode(text, validate=True).decode("utf-8", errors="replace")
                except Exception as exc:
                    logger.warning("Base64 source decode failed: %s", exc)
                    return None
            return text
        except Exception as exc:
            logger.warning("Source fetch error for %s: %s", url, exc)
            return None

    async def analyze(self, url: str, resolved_ips: list[str]) -> dict:
        source = await self.fetch_source(url, resolved_ips)
        if source is None:
            return {
                "fetched": False, "loc": 0, "findings": [],
                "error": "Could not fetch source", "status": "source-unavailable",
                "engine": "semgrep", "config": None, "source_sha256": None, "source_bytes": 0,
            }
        filename = os.path.basename(urlsplit(url).path) or "source.txt"
        if filename in {".", ".."}:
            filename = "source.txt"
        config = self._pick_config(filename)
        loc = len(source.splitlines())
        source_bytes = len(source.encode("utf-8"))
        source_sha256 = hashlib.sha256(source.encode("utf-8")).hexdigest()
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, filename)
            with open(filepath, "w", encoding="utf-8", errors="replace") as f:
                f.write(source)
            findings, status = await self._run_semgrep(filepath, config)
        return {
            "fetched": True, "loc": loc, "findings": findings,
            "error": None if status == "complete" else status, "status": status,
            "engine": "semgrep", "config": config,
            "source_sha256": source_sha256, "source_bytes": source_bytes,
        }

    async def _run_semgrep(self, filepath: str, config: str) -> tuple[list, str]:
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                "semgrep", "--config", config, "--json", "--quiet", "--timeout", "60", filepath,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=90)
            if not stdout:
                logger.warning("Semgrep produced no output: %s", stderr.decode(errors="replace")[:300])
                return [], "semgrep-empty"
            data = json.loads(stdout)
            results = []
            for item in data.get("results", []):
                results.append({
                    "rule_id": item.get("check_id"),
                    "message": item.get("extra", {}).get("message"),
                    "severity": item.get("extra", {}).get("severity"),
                    "line_start": item.get("start", {}).get("line"),
                    "line_end": item.get("end", {}).get("line"),
                    "code_snippet": item.get("extra", {}).get("lines", "")[:500],
                    "cwe": item.get("extra", {}).get("metadata", {}).get("cwe"),
                    "owasp": item.get("extra", {}).get("metadata", {}).get("owasp"),
                    "confidence": item.get("extra", {}).get("metadata", {}).get("confidence"),
                })
            return results, "complete"
        except FileNotFoundError:
            logger.error("semgrep is not installed. Run: pip install semgrep")
            return [], "semgrep-unavailable"
        except asyncio.TimeoutError:
            logger.warning("Semgrep timed out")
            if proc is not None and proc.returncode is None:
                proc.kill()
                await proc.wait()
            return [], "semgrep-timeout"
        except asyncio.CancelledError:
            if proc is not None and proc.returncode is None:
                proc.kill()
                await proc.wait()
            raise
        except json.JSONDecodeError as exc:
            logger.warning("Semgrep JSON parse error: %s", exc)
            return [], "semgrep-invalid-output"

    async def close(self):
        return None
