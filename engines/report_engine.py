import uuid, logging
from datetime import datetime, timezone
from models.schemas import ScanResult, ReconResult, Vulnerability, BountyEstimate, RecommendedProgram
logger = logging.getLogger("phantom.report")

def parse_cwe(cwe_raw):
    if not cwe_raw: return None
    if isinstance(cwe_raw, list):
        return cwe_raw[0] if cwe_raw else None
    return str(cwe_raw)

class ReportEngine:
    def build(self, target, target_type, recon, ai_result):
        vulns = []
        for i, v in enumerate(ai_result.get("vulnerabilities",[]), 1):
            try:
                vulns.append(Vulnerability(
                    id=v.get("id", f"VULN-{i:03d}"),
                    title=v.get("title","Unknown"),
                    severity=v.get("severity","medium").lower(),
                    cvss_score=float(v.get("cvss_score",0.0)),
                    cvss_vector=v.get("cvss_vector"),
                    description=v.get("description",""),
                    endpoint=v.get("endpoint"),
                    impact=v.get("impact",""),
                    attack_vector=v.get("attack_vector",""),
                    cwe=parse_cwe(v.get("cwe")),
                    cve_refs=v.get("cve_refs",[]),
                ))
            except Exception as e:
                logger.warning(f"Vuln parse error: {e}")

        order = {"critical":0,"high":1,"medium":2,"low":3}
        vulns.sort(key=lambda v: order.get(v.severity,4))

        b = ai_result.get("estimated_bounty",{})
        bounty = BountyEstimate(low=int(b.get("low",0)), high=int(b.get("high",0)), most_likely=int(b.get("most_likely",0)))

        programs = []
        for p in ai_result.get("recommended_programs",[]):
            try:
                programs.append(RecommendedProgram(name=p.get("name",""), platform=p.get("platform",""), reward_range=p.get("reward_range",""), match_score=int(p.get("match_score",0)), url=p.get("url")))
            except: pass

        if any(v.severity=="critical" for v in vulns): risk="CRITICAL"
        elif any(v.severity=="high" for v in vulns): risk="HIGH"
        elif any(v.severity=="medium" for v in vulns): risk="MEDIUM"
        elif vulns: risk="LOW"
        else: risk="INFO"

        return ScanResult(
            target=target, target_type=target_type,
            scan_id=str(uuid.uuid4())[:8].upper(),
            timestamp=datetime.now(timezone.utc).isoformat(),
            recon=recon,
            tech_stack=ai_result.get("tech_stack", recon.technologies),
            vulnerabilities=vulns,
            cvss_breakdown=ai_result.get("cvss_breakdown",{}),
            executive_summary=ai_result.get("executive_summary",""),
            technical_details=ai_result.get("technical_details",""),
            proof_of_concept=ai_result.get("proof_of_concept",""),
            remediation=ai_result.get("remediation",""),
            submission_guide=ai_result.get("submission_guide",""),
            estimated_bounty=bounty,
            recommended_programs=programs,
            risk_rating=risk,
        )

    def to_text(self, result):
        sep = "="*72
        return f"""{sep}
PHANTOM // SECURITY ASSESSMENT REPORT
{sep}
Scan ID : {result.scan_id}
Target  : {result.target}
Risk    : {result.risk_rating}
Time    : {result.timestamp}
{sep}
EXECUTIVE SUMMARY
{result.executive_summary}
VULNERABILITIES ({len(result.vulnerabilities)})
{"".join([f'''
[{v.id}] {v.title} | {v.severity.upper()} | CVSS {v.cvss_score}
Endpoint: {v.endpoint or "Multiple"}
Impact  : {v.impact}
''' for v in result.vulnerabilities])}
PROOF OF CONCEPT
{result.proof_of_concept}
REMEDIATION
{result.remediation}
ESTIMATED BOUNTY: ${result.estimated_bounty.most_likely:,}
{sep}"""
