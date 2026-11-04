import asyncio, socket, ssl, httpx, dns.resolver
from urllib.parse import urlparse
from config import config
from models.schemas import ReconResult
from engines.static_analysis import StaticAnalysisEngine
import logging
logger = logging.getLogger("phantom.recon")

class ReconEngine:
    def __init__(self):
        self.http = httpx.AsyncClient(timeout=config.HTTP_TIMEOUT, follow_redirects=False, verify=True, headers={"User-Agent": "PHANTOM/secure-authorized-scan"})
        self.static_engine = StaticAnalysisEngine()

    async def run(self, target: str, target_type: str) -> ReconResult:
        result = ReconResult()
        if target_type == "web":
            if not target.startswith(("http://","https://")):
                target = "https://" + target
            parsed = urlparse(target)
            result.domain = parsed.netloc or parsed.path
            await asyncio.gather(self._probe_http(target, result), self._resolve_dns(result.domain, result), self._check_ssl(result.domain, result), return_exceptions=True)
            if config.SHODAN_API_KEY:
                await self._query_shodan(result.domain, result)
            if config.VIRUSTOTAL_API_KEY:
                await self._query_virustotal(result.domain, result)
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
                logger.warning(f"Could not fetch source for {url}: {analysis['error']}")
            else:
                logger.info(f"Fetched {analysis['loc']} LOC, semgrep found {len(analysis['findings'])} raw findings")
        except Exception as e:
            logger.error(f"Static analysis failed for {url}: {e}")

    async def _probe_http(self, url, result):
        try:
            r = await self.http.get(url)
            result.status_code = r.status_code
            result.headers = dict(r.headers)
            result.server = r.headers.get("server", r.headers.get("x-powered-by", "Unknown"))
            techs = []
            h = str(r.headers).lower()
            for sig, name in [("nginx","Nginx"),("apache","Apache"),("cloudflare","Cloudflare"),("express","Express.js"),("django","Django"),("php","PHP"),("asp.net","ASP.NET"),("node","Node.js"),("next","Next.js"),("aws","AWS")]:
                if sig in h: techs.append(name)
            result.technologies = list(set(techs))
        except Exception as e:
            logger.warning(f"HTTP probe failed: {e}")

    async def _resolve_dns(self, domain, result):
        try:
            dns_info = {}
            for rtype in ["A","MX","TXT","NS"]:
                try:
                    answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                    dns_info[rtype] = [str(r) for r in answers]
                    if rtype == "A": result.ip = dns_info[rtype][0]
                except: pass
            result.dns_records = dns_info
            subs = []
            for sub in ["www","api","admin","dev","staging","app","portal"]:
                try:
                    socket.gethostbyname(f"{sub}.{domain}")
                    subs.append(f"{sub}.{domain}")
                except: pass
            result.subdomains = subs
        except Exception as e:
            logger.warning(f"DNS failed: {e}")

    async def _check_ssl(self, domain, result):
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(5)
                s.connect((domain, 443))
                cert = s.getpeercert()
                result.ssl_info = {"issuer": dict(x[0] for x in cert.get("issuer",[])), "notAfter": cert.get("notAfter"), "protocol": s.version()}
        except Exception as e:
            result.ssl_info = {"error": str(e)}

    async def _query_shodan(self, domain, result):
        try:
            if not result.ip: return
            r = await self.http.get(f"https://api.shodan.io/shodan/host/{result.ip}?key={config.SHODAN_API_KEY}")
            if r.status_code == 200:
                d = r.json()
                result.open_ports = d.get("ports", [])
                result.shodan_info = {"org": d.get("org"), "country": d.get("country_name"), "vulns": d.get("vulns", [])}
        except Exception as e:
            logger.warning(f"Shodan failed: {e}")

    async def _query_virustotal(self, domain, result):
        try:
            r = await self.http.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers={"x-apikey": config.VIRUSTOTAL_API_KEY})
            if r.status_code == 200:
                attrs = r.json().get("data",{}).get("attributes",{})
                stats = attrs.get("last_analysis_stats",{})
                result.virustotal_info = {"malicious": stats.get("malicious",0), "reputation": attrs.get("reputation",0)}
        except Exception as e:
            logger.warning(f"VirusTotal failed: {e}")

    async def close(self):
        await self.http.aclose()
        await self.static_engine.close()
