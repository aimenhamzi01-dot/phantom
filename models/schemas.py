from pydantic import BaseModel, field_validator
from typing import Optional, List
from enum import Enum

class TargetType(str, Enum):
    web = "web"
    mobile = "mobile"
    hardware = "hardware"
    code = "code"

class ScanRequest(BaseModel):
    target: str
    target_type: TargetType = TargetType.web
    scope: List[str] = ["XSS","SQLi","SSRF","IDOR","Logic","Auth","RCE","Crypto"]

    @field_validator("target")
    @classmethod
    def validate_target(cls, v):
        v = v.strip()
        if not v: raise ValueError("Target cannot be empty")
        if len(v) > 512: raise ValueError("Target too long")
        return v

class ReconResult(BaseModel):
    domain: Optional[str] = None
    ip: Optional[str] = None
    server: Optional[str] = None
    technologies: List[str] = []
    open_ports: List[int] = []
    dns_records: dict = {}
    whois_info: dict = {}
    shodan_info: dict = {}
    virustotal_info: dict = {}
    headers: dict = {}
    subdomains: List[str] = []
    endpoints: List[str] = []
    status_code: Optional[int] = None
    ssl_info: dict = {}
    source_fetched: bool = False
    lines_of_code: int = 0
    static_findings: List[dict] = []

class Vulnerability(BaseModel):
    id: str
    title: str
    severity: str
    cvss_score: float
    cvss_vector: Optional[str] = None
    description: str
    endpoint: Optional[str] = None
    impact: str
    attack_vector: str
    cwe: Optional[str] = None
    cve_refs: List[str] = []
    verified: bool = False
    source_line: Optional[int] = None
    source_snippet: Optional[str] = None

class BountyEstimate(BaseModel):
    low: int
    high: int
    most_likely: int
    currency: str = "USD"

class RecommendedProgram(BaseModel):
    name: str
    platform: str
    reward_range: str
    match_score: int
    url: Optional[str] = None

class ScanResult(BaseModel):
    target: str
    target_type: str
    scan_id: str
    timestamp: str
    recon: ReconResult
    tech_stack: List[str] = []
    vulnerabilities: List[Vulnerability] = []
    cvss_breakdown: dict = {}
    executive_summary: str = ""
    technical_details: str = ""
    proof_of_concept: str = ""
    remediation: str = ""
    submission_guide: str = ""
    estimated_bounty: BountyEstimate = BountyEstimate(low=0,high=0,most_likely=0)
    recommended_programs: List[RecommendedProgram] = []
    risk_rating: str = "Unknown"

class HealthResponse(BaseModel):
    status: str
    version: str
    ai_engine: str
    apis_configured: dict
