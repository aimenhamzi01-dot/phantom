import json
import logging

from meta_client import MetaAPIError, chat

logger = logging.getLogger("phantom.ai")

SYSTEM_PROMPT = """You are PHANTOM's evidence-analysis worker inside Mizan.

CRITICAL RULE: You do NOT invent vulnerabilities. You only triage, explain, and write up findings that
were ALREADY DETECTED by a real static-analysis tool (Semgrep) and are provided below.
If STATIC_FINDINGS is empty, return an empty vulnerabilities array. Do not speculate or produce generic
findings about code you have not actually seen.

Respond ONLY with valid JSON and no markdown. Preserve the distinction between scanner evidence and your
analysis. The human reviewer in Mizan makes the final decision.

JSON Schema:
{"tech_stack":["technologies"],"risk_rating":"CRITICAL|HIGH|MEDIUM|LOW|INFO","vulnerabilities":[{"id":"VULN-001","title":"name","severity":"critical|high|medium|low","cvss_score":0.0,"cvss_vector":"CVSS:3.1/...","description":"grounded technical description","endpoint":"file:line","impact":"business impact","attack_vector":"attack steps","cwe":"CWE-XXX","cve_refs":[],"verified":false,"source_line":0,"source_snippet":"actual snippet"}],"cvss_breakdown":{},"executive_summary":"professional summary","technical_details":"analysis grounded in evidence","proof_of_concept":"non-executing reproduction outline","remediation":"fix recommendations","submission_guide":"review guidance","estimated_bounty":{"low":0,"high":0,"most_likely":0,"currency":"USD"},"recommended_programs":[]}"""


def build_prompt(target, target_type, scope, recon):
    static_section = "N/A (not a code target)"
    if target_type == "code":
        if not recon.static_findings:
            static_section = (
                f"Source fetched: {recon.source_fetched} | Lines of code: {recon.lines_of_code}\n"
                "STATIC_FINDINGS: [] (Semgrep found ZERO issues — report zero vulnerabilities.)"
            )
        else:
            findings_text = "\n".join(
                f"- [{f.get('severity','?')}] {f.get('rule_id')} at line {f.get('line_start')}: "
                f"{f.get('message')}\n  CWE: {f.get('cwe')} | Code:\n  {f.get('code_snippet','')[:300]}"
                for f in recon.static_findings
            )
            static_section = (
                f"Source fetched: {recon.source_fetched} | Lines of code: {recon.lines_of_code}\n"
                f"STATIC_FINDINGS ({len(recon.static_findings)} real Semgrep results):\n{findings_text}"
            )

    return f"""Analyze this authorized assessment using ONLY the evidence below:
TARGET: {target}
TYPE: {target_type.upper()}
SCOPE: {', '.join(scope)}
DOMAIN: {recon.domain}
IP: {recon.ip or 'Not resolved'}
SERVER: {recon.server or 'Unknown'}
STATUS: {recon.status_code or 'N/A'}
TECHNOLOGIES: {', '.join(recon.technologies) if recon.technologies else 'Unknown'}
SSL: {json.dumps(recon.ssl_info)}
DNS: {json.dumps(recon.dns_records)}
SUBDOMAINS: {', '.join(recon.subdomains) if recon.subdomains else 'None'}
OPEN PORTS: {recon.open_ports}
SHODAN: {json.dumps(recon.shodan_info)}
VIRUSTOTAL: {json.dumps(recon.virustotal_info)}

{static_section}

Remember: do not report any vulnerability that is not directly grounded in the data above."""


class AIEngine:
    async def analyze(self, target, target_type, scope, recon):
        prompt = build_prompt(target, target_type, scope, recon)
        logger.info("Sending evidence to Meta Muse Spark...")
        try:
            raw = chat(
                [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                max_completion_tokens=3000,
                temperature=None,
                timeout=120,
            ).strip()
            if raw.startswith("```"):
                raw = raw.split("```", 2)[1]
                if raw.lstrip().startswith("json"):
                    raw = raw.lstrip()[4:]
            result = json.loads(raw.strip())
            logger.info("Meta analysis done: %d findings", len(result.get("vulnerabilities", [])))
            return result
        except json.JSONDecodeError as exc:
            raise ValueError(f"Meta API returned invalid JSON: {exc}") from exc
        except MetaAPIError:
            logger.exception("Meta API error")
            raise
