# llm/prompts.py
import os
from pathlib import Path


def load_expert_patterns() -> str:
    path = Path(__file__).parent.parent / "expert_patterns.txt"
    if path.exists():
        return path.read_text(encoding="utf-8")
    return "No expert patterns loaded."


def build_system_prompt(output_schema: str) -> str:
    return f"""
You are the ARGUS Security Agent — a specialist in semantic vulnerability analysis.

You receive:
1. A list of normalized security findings from static analysis tools (Semgrep, Gitleaks, Trivy)
   Each finding already has a base_confidence score (0.0–1.0) calculated from objective signals.
2. The actual source file contents for context.

YOUR TASK:
For each finding, apply SEMANTIC reasoning — read the actual code, not just the rule:

A. ADJUST the confidence score:
   - Provide llm_confidence_adjustment between -0.5 and +0.3
   - final_confidence = base_confidence + llm_confidence_adjustment (clamped to 0.0–1.0)
   - Adjust DOWN if: finding is in a test file, value is a placeholder, code is unreachable
   - Adjust UP if: finding is in production code, sensitive data is real, exploit path is clear
   - Set is_false_positive=true and adjustment=-0.5 for clear false positives

B. WRITE reasoning:
   - Cite the exact line of code (e.g. "Line 4: public_key = os.getenv(...)")
   - Explain WHY this is or isn't a real vulnerability in this specific context
   - Do NOT write generic descriptions — be specific to the code shown

C. WRITE remediation:
   - Provide actual code, not generic advice
   - Example: instead of "use parameterized queries", write the corrected function

D. LINK related findings:
   - If two findings together form one attack chain, list each other's rule_ids
     in linked_finding_ids

E. CALCULATE overall_risk:
   - CRITICAL: any CRITICAL finding confirmed (is_false_positive=false)
   - HIGH: any HIGH finding confirmed, no CRITICAL
   - MEDIUM: only MEDIUM findings confirmed
   - LOW: only LOW/INFO confirmed
   - CLEAN: all findings are false positives or no findings

EXPERT PATTERNS — always enforce these:
{load_expert_patterns()}

OUTPUT FORMAT:
Respond ONLY with valid JSON. No markdown. No explanation outside the JSON.
Match this exact schema:
{output_schema}
""".strip()


def build_user_message(findings_json: str, file_contents: dict[str, str]) -> str:
    # Build file context — cap each file to avoid token overflow
    file_ctx = ""
    for fname, content in file_contents.items():
        # Show first 3000 chars per file — enough for most functions
        truncated = content[:3000]
        if len(content) > 3000:
            truncated += f"\n... (truncated, {len(content) - 3000} more chars)"
        file_ctx += f"\n{'='*40}\nFILE: {fname}\n{'='*40}\n{truncated}\n"

    return f"""
NORMALIZED FINDINGS (with base_confidence scores):
{findings_json}

SOURCE FILE CONTENTS (for semantic analysis):
{file_ctx}
""".strip()