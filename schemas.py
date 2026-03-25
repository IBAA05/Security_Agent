# schemas.py
from pydantic import BaseModel, field_validator
from typing import Optional, Literal
from enum import Enum


# ─── Enums ────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


# ─── A2A Protocol envelope ────────────────────────────────────────────────────

class A2AMetadata(BaseModel):
    """
    Protocol-level metadata. Your agent reads this to know
    who sent the message and how to correlate the response.
    """
    message_id: str
    correlation_id: str
    timestamp: str
    sender: str
    version: str


class RoutingInstructions(BaseModel):
    """
    Tells your agent how urgently to treat this scan.
    priority HIGH means needs_reflexion should default to True
    unless the Orchestrator explicitly says otherwise.
    """
    priority: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    target_specialist: str
    ttl_seconds: int


# ─── Knowledge graph ──────────────────────────────────────────────────────────

class KnowledgeGraphNode(BaseModel):
    """
    One file in the dependency graph.
    PRIMARY_SOURCE = file that was actually changed.
    DEPENDENCY = file affected by the change but not modified.
    Your agent uses this to understand blast radius even without
    seeing the content of DEPENDENCY nodes.
    """
    id: str
    file: str
    role: Literal["PRIMARY_SOURCE", "DEPENDENCY", "TEST", "CONFIG"]
    symbols_changed: list[str] = []
    logic_delta: Optional[str] = None
    impact: Optional[str] = None
    status: Optional[str] = None    # e.g. "AFFECTED_BUT_NOT_MODIFIED"


class KnowledgeGraph(BaseModel):
    nodes: list[KnowledgeGraphNode]

    def primary_files(self) -> list[str]:
        """Files that were actually changed — these get tool scanning."""
        return [n.file for n in self.nodes if n.role == "PRIMARY_SOURCE"]

    def affected_files(self) -> list[str]:
        """Files impacted but not modified — context only, no tool scan."""
        return [n.file for n in self.nodes if n.role == "DEPENDENCY"]

    def get_node(self, file: str) -> Optional[KnowledgeGraphNode]:
        return next((n for n in self.nodes if n.file == file), None)


# ─── Payload content ──────────────────────────────────────────────────────────

class CodeSnippet(BaseModel):
    """
    High-signal code extracted by the Librarian Agent.
    Only the relevant parts of each file are sent — not the whole file.
    This is called 'dehydrated' because it's a compressed representation.
    """
    file: str
    snippet: str


class ActiveProblem(BaseModel):
    """
    Issues already identified by upstream agents (Librarian, Context Agent).
    Your agent must cross-reference these with its own tool findings.
    remediation_hint comes from the Librarian — your LLM should
    validate and enrich it, not ignore it.
    """
    type: str                       # e.g. "LOGIC_INCONSISTENCY"
    location: str                   # e.g. "config_loader.py:45"
    problem: str
    remediation_hint: Optional[str] = None


class DehydratedContent(BaseModel):
    """
    The actual code and constraints your agent works with.
    policy_constraints are plain strings from company standards —
    your agent must check every finding against these.
    """
    high_signal_code: list[CodeSnippet]
    policy_constraints: list[str] = []


class A2APayload(BaseModel):
    """
    The business content of the message.
    Everything your agent needs to do its job.
    """
    intent: str
    knowledge_graph: KnowledgeGraph
    dehydrated_content: DehydratedContent
    active_problem_set: list[ActiveProblem] = []


# ─── Full A2A message ─────────────────────────────────────────────────────────

class A2AMessage(BaseModel):
    """
    The complete message your agent receives from the Orchestrator.
    This replaces OrchestratorInput entirely.
    """
    protocol: str
    metadata: A2AMetadata
    routing_instructions: RoutingInstructions
    payload: A2APayload

    # Reflexion control — injected by Orchestrator
    # Default: True when priority is HIGH or CRITICAL
    needs_reflexion: bool = False
    reflexion_threshold: float = 0.75
    reflexion_max_retries: int = 2
    environment: Literal["pr", "staging"] = "pr"
    live_endpoint: Optional[str] = None

    @field_validator("needs_reflexion", mode="before")
    @classmethod
    def auto_reflexion_for_high_priority(cls, v, info):
        """
        If Orchestrator didn't explicitly set needs_reflexion,
        default to True for HIGH and CRITICAL priority.
        This is the only decision your agent makes autonomously —
        and even this can be overridden by the Orchestrator.
        """
        if v is not None:
            return v
        routing = info.data.get("routing_instructions")
        if routing and routing.priority in ("HIGH", "CRITICAL"):
            return True
        return False

    def get_files_to_scan(self) -> list[str]:
        """
        Returns only PRIMARY_SOURCE files — the ones tools should scan.
        DEPENDENCY nodes give context but don't need tool scanning
        because they weren't modified.
        """
        primary = self.payload.knowledge_graph.primary_files()
        # Also include any file that has a code snippet provided
        snippet_files = [
            s.file for s in self.payload.dehydrated_content.high_signal_code
        ]
        return list(set(primary + snippet_files))

    def get_file_snippets(self) -> dict[str, str]:
        """
        Returns {filename: code_snippet} for all provided snippets.
        Used to write temp files for tool scanning.
        """
        return {
            s.file: s.snippet
            for s in self.payload.dehydrated_content.high_signal_code
        }


# ─── Internal processing models ───────────────────────────────────────────────

class NormalizedFinding(BaseModel):
    """
    Single unified format for ALL tool outputs.
    Unchanged — tools don't care about the input format.
    """
    tool: Literal["semgrep", "gitleaks", "trivy", "zap", "policy_check"]
    rule_id: str
    title: str
    description: str
    severity: Severity
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    owasp_category: Optional[str] = None
    cwe: Optional[str] = None
    evidence: Optional[str] = None
    base_confidence: float = 0.0
    violated_policy_id: Optional[str] = None


class NormalizedBundle(BaseModel):
    """
    Everything the LLM receives in one package.
    Now includes knowledge graph context and active problems.
    """
    scan_id: str
    findings: list[NormalizedFinding]
    file_contents: dict[str, str]
    # NEW — passed through so LLM has full context
    knowledge_graph_summary: str = ""
    active_problems: list[ActiveProblem] = []
    policy_constraints: list[str] = []
    intent: str = ""
    priority: str = "MEDIUM"


# ─── Output models ────────────────────────────────────────────────────────────

class LLMFinding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    owasp_category: Optional[str] = None
    cwe: Optional[str] = None
    base_confidence: float
    llm_confidence_adjustment: float
    final_confidence: float
    is_false_positive: bool
    reasoning: str
    remediation: str
    linked_finding_ids: list[str] = []
    violated_policy_id: Optional[str] = None
    # NEW — did this finding correlate with an active problem?
    correlates_with_problem: Optional[str] = None


class LLMOutput(BaseModel):
    scan_id: str
    summary: str
    findings: list[LLMFinding]
    critical_count: int
    high_count: int
    overall_risk: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN"]
    # NEW — explicit list of active problems that were confirmed by tools
    confirmed_active_problems: list[str] = []
    # NEW — correlation_id to route response back correctly
    correlation_id: str = ""