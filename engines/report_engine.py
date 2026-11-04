import logging
import uuid
from datetime import datetime, timezone

from models.schemas import ReconResult, ScanResult, Vulnerability

logger = logging.getLogger("phantom.report")


def parse_cwe(cwe_raw):
    if not cwe_raw:
        return None
    if isinstance(cwe_raw, list):
        return cwe_raw[0] if cwe_raw else None
    return str(cwe_raw)


class ReportEngine:
    def build(self, target, target_type, recon: ReconResult, ai_result):
        vulnerabilities = []
        for index, value in enumerate(ai_result.get("vulnerabilities", []), 1):
            try:
                vulnerabilities.append(
                    Vulnerability(
                        id=value.get("id", f"VULN-{index:03d}"),
                        title=value.get("title", "Unknown"),
                        severity=value.get("severity", "medium").lower(),
                        cvss_score=float(value.get("cvss_score", 0.0)),
                        cvss_vector=value.get("cvss_vector"),
                        description=value.get("description", ""),
                        endpoint=value.get("endpoint"),
                        impact=value.get("impact", ""),
                        attack_vector=value.get("attack_vector", ""),
                        cwe=parse_cwe(value.get("cwe")),
                        cve_refs=value.get("cve_refs", []),
                        verified=False,
                        source_line=value.get("source_line"),
                        source_snippet=value.get("source_snippet"),
                    )
                )
            except Exception as exc:
                logger.warning("Vulnerability parse error: %s", exc)

        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        vulnerabilities.sort(key=lambda item: order.get(item.severity, 4))
        if any(item.severity == "critical" for item in vulnerabilities):
            risk = "CRITICAL"
        elif any(item.severity == "high" for item in vulnerabilities):
            risk = "HIGH"
        elif any(item.severity == "medium" for item in vulnerabilities):
            risk = "MEDIUM"
        elif vulnerabilities:
            risk = "LOW"
        else:
            risk = "INFO"

        return ScanResult(
            target=target,
            target_type=target_type,
            scan_id=str(uuid.uuid4())[:8].upper(),
            timestamp=datetime.now(timezone.utc).isoformat(),
            recon=recon,
            tech_stack=ai_result.get("tech_stack", recon.technologies),
            vulnerabilities=vulnerabilities,
            cvss_breakdown=ai_result.get("cvss_breakdown", {}),
            executive_summary=ai_result.get("executive_summary", ""),
            technical_details=ai_result.get("technical_details", ""),
            proof_of_concept=ai_result.get("proof_of_concept", ""),
            remediation=ai_result.get("remediation", ""),
            risk_rating=risk,
        )

    def to_text_report(self, result):
        separator = "=" * 72
        findings = "".join(
            f"\n[{item.id}] {item.title} | {item.severity.upper()} | CVSS {item.cvss_score}\n"
            f"Endpoint: {item.endpoint or 'Multiple'}\nImpact: {item.impact}\n"
            for item in result.vulnerabilities
        )
        return f"""{separator}
PHANTOM // MIZAN EVIDENCE WORKER REPORT
{separator}
Scan ID : {result.scan_id}
Target  : {result.target}
Risk    : {result.risk_rating}
Time    : {result.timestamp}
{separator}
EXECUTIVE SUMMARY
{result.executive_summary}
FINDINGS ({len(result.vulnerabilities)})
{findings}
NON-EXECUTING REPRODUCTION OUTLINE
{result.proof_of_concept}
REMEDIATION
{result.remediation}

This report is untrusted evidence for Mizan review. It is not a final vulnerability verdict.
{separator}"""
