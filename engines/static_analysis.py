"""
PHANTOM — Static Analysis Engine
Fetches REAL source code and runs Semgrep against it.
"""
import asyncio
import json
import logging
import tempfile
import os
import httpx

logger = logging.getLogger("phantom.static")

SEMGREP_CONFIGS = {
    ".c": "p/c", ".cpp": "p/cpp", ".cc": "p/cpp", ".h": "p/c", ".hpp": "p/cpp",
    ".py": "p/python", ".js": "p/javascript", ".ts": "p/typescript",
    ".java": "p/java", ".go": "p/golang", ".rb": "p/ruby", ".php": "p/php",
}

class StaticAnalysisEngine:
    def __init__(self):
        self.http = httpx.AsyncClient(timeout=30.0, follow_redirects=False, verify=True)

    async def fetch_source(self, url: str):
        try:
            r = await self.http.get(url)
            if r.status_code != 200:
                logger.warning(f"Source fetch failed: HTTP {r.status_code} for {url}")
                return None
            if len(r.content) > 2 * 1024 * 1024:
                logger.warning("Source fetch rejected: response exceeds 2MB")
                return None
            text = r.text
            if "?format=TEXT" in url:
                import base64
                try:
                    text = base64.b64decode(text).decode("utf-8", errors="replace")
                except Exception as e:
                    logger.warning(f"Base64 decode failed: {e}")
                    return None
            return text
        except Exception as e:
            logger.warning(f"Source fetch error: {e}")
            return None

    def _pick_config(self, filename: str) -> str:
        ext = os.path.splitext(filename)[1].lower()
        return SEMGREP_CONFIGS.get(ext, "p/security-audit")

    async def analyze(self, url: str) -> dict:
        source = await self.fetch_source(url)
        if source is None:
            return {"fetched": False, "loc": 0, "findings": [], "error": "Could not fetch source"}
        filename = url.split("/")[-1].split("?")[0]
        config = self._pick_config(filename)
        loc = len(source.splitlines())
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, filename)
            with open(filepath, "w", encoding="utf-8", errors="replace") as f:
                f.write(source)
            findings = await self._run_semgrep(filepath, config)
        return {"fetched": True, "loc": loc, "findings": findings, "error": None}

    async def _run_semgrep(self, filepath: str, config: str) -> list:
        try:
            proc = await asyncio.create_subprocess_exec(
                "semgrep", "--config", config, "--json", "--quiet", "--timeout", "60", filepath,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=90)
            if not stdout:
                logger.warning(f"Semgrep produced no output: {stderr.decode(errors='replace')[:300]}")
                return []
            data = json.loads(stdout)
            results = []
            for r in data.get("results", []):
                results.append({
                    "rule_id": r.get("check_id"),
                    "message": r.get("extra", {}).get("message"),
                    "severity": r.get("extra", {}).get("severity"),
                    "line_start": r.get("start", {}).get("line"),
                    "line_end": r.get("end", {}).get("line"),
                    "code_snippet": r.get("extra", {}).get("lines", "")[:500],
                    "cwe": r.get("extra", {}).get("metadata", {}).get("cwe"),
                    "owasp": r.get("extra", {}).get("metadata", {}).get("owasp"),
                    "confidence": r.get("extra", {}).get("metadata", {}).get("confidence"),
                })
            return results
        except FileNotFoundError:
            logger.error("semgrep is not installed. Run: pip install semgrep")
            return []
        except asyncio.TimeoutError:
            logger.warning("Semgrep timed out")
            return []
        except json.JSONDecodeError as e:
            logger.warning(f"Semgrep JSON parse error: {e}")
            return []

    async def close(self):
        await self.http.aclose()
