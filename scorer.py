# scorer.py
from schemas import NormalizedFinding, Severity

SEVERITY_WEIGHT = {
    Severity.CRITICAL: 0.9,
    Severity.HIGH:     0.75,
    Severity.MEDIUM:   0.5,
    Severity.LOW:      0.25,
    Severity.INFO:     0.1,
}

OWASP_WEIGHT = {
    "A01": 0.9,    # Broken Access Control
    "A02": 0.85,   # Crypto Failures
    "A03": 0.85,   # Injection
    "A07": 0.8,    # Identification Failures (secrets/tokens)
    "A10": 0.8,    # SSRF
    "A04": 0.7,    # Insecure Design
    "A08": 0.75,   # Integrity Failures
    "A05": 0.65,   # Security Misconfiguration
    "A06": 0.6,    # Vulnerable Components
    "A09": 0.4,    # Logging Failures
}

# If these words appear in evidence, it's more likely real
SENSITIVE_KEYWORDS = [
    "password", "passwd", "secret", "token", "apikey", "api_key",
    "private_key", "credential", "auth", "bearer", "authorization",
    "access_key", "client_secret",
]

# Test-related paths reduce confidence — findings in tests are often intentional
TEST_PATH_INDICATORS = ["test", "spec", "mock", "fixture", "example", "sample", "__test__"]


def score(finding: NormalizedFinding, all_findings: list[NormalizedFinding]) -> float:
    """
    Calculates a base_confidence score from 0.0 to 1.0
    using 4 objective signals. The LLM will later adjust this.

    Signal 1 (weight 0.35): How severe is the finding?
    Signal 2 (weight 0.30): How dangerous is the OWASP category?
    Signal 3 (weight 0.20): Does evidence contain real sensitive data?
    Signal 4 (weight 0.15): Is the same file flagged by multiple tools?
    """
    s = 0.0

    # Signal 1: severity
    s += SEVERITY_WEIGHT.get(finding.severity, 0.1) * 0.35

    # Signal 2: OWASP category danger
    if finding.owasp_category:
        s += OWASP_WEIGHT.get(finding.owasp_category, 0.5) * 0.30

    # Signal 3: evidence contains sensitive keywords
    evidence_lower = (finding.evidence or "").lower()
    title_lower = finding.title.lower()
    combined = evidence_lower + " " + title_lower
    if any(kw in combined for kw in SENSITIVE_KEYWORDS):
        s += 0.20

    # Signal 4: corroboration — same file flagged by a different tool
    if finding.file_path:
        other_tools = {
            f.tool for f in all_findings
            if f.file_path == finding.file_path and f.tool != finding.tool
        }
        if other_tools:
            s += 0.15

    # Penalty: finding is in a test file (reduce by 30%)
    path_lower = (finding.file_path or "").lower()
    if any(indicator in path_lower for indicator in TEST_PATH_INDICATORS):
        s *= 0.7

    return round(min(max(s, 0.0), 1.0), 3)


def score_all(findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
    """Apply scoring to all findings. Mutates in-place and returns the list."""
    for f in findings:
        f.base_confidence = score(f, findings)
    return findings

from memory.store import get_file_context

def score_with_memory(
    findings: list[NormalizedFinding],
    file_paths: list[str]
) -> list[NormalizedFinding]:
    """
    Score findings using both signals AND historical memory.
    """
    memory_ctx = get_file_context(file_paths)

    for f in findings:
        # Base score from signals
        f.base_confidence = score(f, findings)

        # Memory boost
        if f.file_path and f.file_path in memory_ctx:
            file_mem = memory_ctx[f.file_path]
            known = file_mem["known_findings"].get(f.rule_id, {})

            if known:
                times_seen = known.get("times_seen", 0)
                confirmed = known.get("confirmed_count", 0)
                fp_count = known.get("was_false_positive_count", 0)
                human_verdict = known.get("human_verdict")

                # If human confirmed this finding before — big boost
                if human_verdict == "confirmed":
                    f.base_confidence = min(f.base_confidence + 0.25, 1.0)

                # If human dismissed as FP before — big reduction
                elif human_verdict == "false_positive":
                    f.base_confidence = max(f.base_confidence - 0.4, 0.0)

                # Seen many times and always real — moderate boost
                elif times_seen >= 3 and confirmed > fp_count:
                    boost = min(times_seen * 0.05, 0.2)
                    f.base_confidence = min(f.base_confidence + boost, 1.0)

        f.base_confidence = round(f.base_confidence, 3)

    return findings