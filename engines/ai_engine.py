import json, logging
from openai import OpenAI
from config import config
from models.schemas import ReconResult
import os
logger = logging.getLogger("phantom.ai")

SYSTEM_PROMPT = """You are PHANTOM's AI core — elite security analysis engine for authorized bug bounty hunting only.
Analyze real reconnaissance data and identify genuine vulnerabilities.
Respond ONLY with valid JSON. No markdown. No text outside JSON.
JSON Schema:
{"tech_stack":["technologies"],"risk_rating":"CRITICAL|HIGH|MEDIUM|LOW","vulnerabilities":[{"id":"VULN-001","title":"name","severity":"critical|high|medium|low","cvss_score":0.0,"cvss_vector":"CVSS:3.1/...","description":"technical description","endpoint":"affected endpoint","impact":"business impact","attack_vector":"attack steps","cwe":"CWE-XXX","cve_refs":[]}],"cvss_breakdown":{"Attack Vector":0,"Complexity":0,"Privileges":0,"User Interaction":0,"Confidentiality":0,"Integrity":0},"executive_summary":"professional summary","technical_details":"deep analysis","proof_of_concept":"reproduction steps","remediation":"fix recommendations","submission_guide":"programs and strategy","estimated_bounty":{"low":0,"high":0,"most_likely":0,"currency":"USD"},"recommended_programs":[{"name":"program","platform":"HackerOne|Bugcrowd|Direct","reward_range":"$X-$Y","match_score":0,"url":"https://..."}]}"""

def build_prompt(target, target_type, scope, recon):
    return f"""Analyze this bug bounty target using real recon data:
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
Based on actual data above, identify realistic vulnerabilities specific to this target."""

class AIEngine:
    def __init__(self):
        self.client = OpenAI(
            base_url="https://models.inference.ai.azure.com",
            api_key=os.getenv("GITHUB_TOKEN"),
        )

    async def analyze(self, target, target_type, scope, recon):
        prompt = build_prompt(target, target_type, scope, recon)
        logger.info(f"Sending to GitHub Models...")
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=4000,
                temperature=0.1,
            )
            raw = response.choices[0].message.content.strip()
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"): raw = raw[4:]
            raw = raw.strip()
            result = json.loads(raw)
            logger.info(f"AI done: {len(result.get('vulnerabilities',[]))} findings")
            return result
        except json.JSONDecodeError as e:
            raise ValueError(f"AI returned invalid JSON: {e}")
        except Exception as e:
            logger.error(f"AI error: {e}")
            raise
