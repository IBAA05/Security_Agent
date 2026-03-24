# schemas.py
from pydantic import BaseModel, field_validator
from typing import Literal, Optional
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class OrchestratorInput(BaseModel):
    """
    What the Security Agent receives from the Orchestrator.
    The Orchestrator reads the YAML sent by the Context Agent
    and forwards only the security-relevant slice here.
    """
    scan_id: str
    files: list[str]                        # absolute paths on disk
    languages: list[str]                    # e.g. ["python", "javascript"]
    environment: Literal["pr", "staging"]   # controls which tools run
    live_endpoint: Optional[str] = None     # required only in staging (for ZAP)
    metadata: dict = {}

    @field_validator("live_endpoint")
    @classmethod
    def endpoint_required_for_staging(cls, v, info):
        if info.data.get("environment") == "staging" and not v:
            raise ValueError("live_endpoint is required when environment is staging")
        return v


class NormalizedFinding(BaseModel):
    """
    The single unified format that ALL tools must output.
    Every tool wrapper (semgrep, gitleaks, trivy, zap) converts
    its native output into this shape. This is what the LLM receives.
    """
    tool: Literal["semgrep", "gitleaks", "trivy", "zap"]
    rule_id: str
    title: str
    description: str
    severity: Severity
    file_path: Optional[str] = None     # None for ZAP (no file, it scans URLs)
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    owasp_category: Optional[str] = None   # e.g. "A03"
    cwe: Optional[str] = None              # e.g. "CWE-89"
    evidence: Optional[str] = None         # the actual code/secret/payload matched
    base_confidence: float = 0.0           # filled by scorer.py, not the tool itself


class NormalizedBundle(BaseModel):
    """
    Everything the LLM agent receives in one package:
    the scored findings + the actual file contents for context.
    """
    scan_id: str
    findings: list[NormalizedFinding]
    file_contents: dict[str, str]       # filepath → file text (for LLM to read)


class LLMFinding(BaseModel):
    """
    One finding after the LLM has reasoned about it.
    """
    rule_id: str
    title: str
    severity: Severity
    owasp_category: Optional[str]
    cwe: Optional[str]
    base_confidence: float
    llm_confidence_adjustment: float    # LLM's delta: -0.5 to +0.3
    final_confidence: float             # base + adjustment, clamped to [0.0, 1.0]
    is_false_positive: bool
    reasoning: str                      # LLM must cite the code line
    remediation: str                    # specific fix, not generic advice
    linked_finding_ids: list[str] = []  # attack chain grouping


class LLMOutput(BaseModel):
    """
    Complete output from the LLM agent.
    """
    scan_id: str
    summary: str
    findings: list[LLMFinding]
    critical_count: int
    high_count: int
    overall_risk: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN"]