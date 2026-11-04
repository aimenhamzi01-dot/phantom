from enum import Enum
from typing import Any, List, Optional

from pydantic import BaseModel, field_validator, model_validator


class TargetType(str, Enum):
    web = "web"
    mobile = "mobile"
    hardware = "hardware"
    code = "code"


class ScanRequest(BaseModel):
    target: Optional[str] = None
    target_type: TargetType = TargetType.web
    scope: List[str] = []
    manifest: Optional[dict[str, Any]] = None

    @field_validator("target")
    @classmethod
    def validate_target(cls, value):
        if value is None:
            return value
        value = value.strip()
        if not value:
            raise ValueError("Target cannot be empty")
        if len(value) > 512:
            raise ValueError("Target too long")
        return value

    @model_validator(mode="after")
    def require_manifest_or_target(self):
        if self.manifest is None and not self.target:
            raise ValueError("A signed manifest is required in secure mode.")
        return self


class ReconResult(BaseModel):
    domain: Optional[str] = None
    ip: Optional[str] = None
    server: Optional[str] = None
    technologies: List[str] = []
    open_ports: List[int] = []
    dns_records: dict = {}
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
    risk_rating: str = "Unknown"


class HealthResponse(BaseModel):
    status: str
    version: str
    ai_engine: str
    apis_configured: dict
