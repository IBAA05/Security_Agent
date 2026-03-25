# llm/prompts.py
from pathlib import Path
from schemas import NormalizedBundle


def load_expert_patterns() -> str:
    path = Path(__file__).parent.parent / "expert_patterns.txt"
    if path.exists():
        return path.read_text(encoding="utf-8")
    return "No expert patterns loaded."


def build_system_prompt(output_schema: str) -> str:
    return f"""
You are the ARGUS Security Agent — a specialist in semantic vulnerability analysis.

You receive a complete security analysis package containing:
1. Tool findings (Semgrep, Gitleaks, Trivy) with pre-calculated base_confidence scores
2. Source code snippets of the changed files
3. A knowledge graph showing which files are affected and how they relate
4. Active problems already identified by the Librarian Agent upstream
5. Company policy constraints that are non-negotiable

YOUR TASK — in this exact order:

STEP 1 — CROSS-REFERENCE ACTIVE PROBLEMS
  Read every item in active_problem_set carefully.
  These were found by the Librarian Agent which has broader codebase visibility.
  Check if your tool findings confirm, contradict, or extend these problems.
  Set correlates_with_problem on any finding that relates to an active problem.

STEP 2 — CHECK POLICY CONSTRAINTS
  Every policy_constraint is a company rule — not a suggestion.
  Violations are always CRITICAL regardless of context.
  Check every snippet against every constraint explicitly.

STEP 3 — SEMANTIC ANALYSIS
  Read the actual code. Reason about:
  - Is the vulnerable path reachable in production?
  - What happens if a key/secret is None or empty?
  - Are old and new code paths simultaneously active? (migration risk)
  - Does the knowledge graph reveal blast radius beyond the changed file?

STEP 4 — ADJUST CONFIDENCE
  base_confidence is pre-calculated from objective signals.
  Your job is to adjust it based on semantic context:
  - llm_confidence_adjustment: between -0.5 and +0.3
  - final_confidence = base_confidence + adjustment (clamped 0.0–1.0)
  - Cite the exact code line in your reasoning

STEP 5 — WRITE REMEDIATION
  Provide actual corrected code — not generic advice.
  Reference the remediation_hint from active problems when relevant.

EXPERT PATTERNS — always enforce:
{load_expert_patterns()}

CRITICAL RULE:
Respond ONLY with valid JSON matching this schema exactly.
No markdown. No explanation outside the JSON.

SCHEMA:
{output_schema}
""".strip()


def build_user_message(bundle: NormalizedBundle) -> str:
    """
    Builds the complete user message for the LLM.
    Now includes knowledge graph, active problems, and policies
    from the A2A payload — not just findings and file contents.
    """

    # ── Section 1: Scan context ───────────────────────────────────────────────
    context_section = f"""
SCAN CONTEXT:
  Intent:      {bundle.intent}
  Priority:    {bundle.priority}
  Scan ID:     {bundle.scan_id}
""".strip()

    # ── Section 2: Knowledge graph ────────────────────────────────────────────
    kg_section = f"""
KNOWLEDGE GRAPH (file dependency map):
{bundle.knowledge_graph_summary}

What this means for your analysis:
- PRIMARY_SOURCE files were modified — your tools scanned these
- DEPENDENCY files were NOT modified but are impacted by the change
- Vulnerabilities in PRIMARY_SOURCE may break DEPENDENCY nodes silently
""".strip()

    # ── Section 3: Active problems from upstream agents ───────────────────────
    if bundle.active_problems:
        problems_text = "\n".join([
            f"  [{i+1}] Type: {p.type}\n"
            f"       Location: {p.location}\n"
            f"       Problem: {p.problem}\n"
            f"       Hint: {p.remediation_hint or 'none provided'}"
            for i, p in enumerate(bundle.active_problems)
        ])
        problems_section = f"""
ACTIVE PROBLEMS (from Librarian Agent — cross-reference these):
{problems_text}
""".strip()
    else:
        problems_section = "ACTIVE PROBLEMS: None reported by upstream agents."

    # ── Section 4: Policy constraints ─────────────────────────────────────────
    if bundle.policy_constraints:
        policies_text = "\n".join([
            f"  [{i+1}] {p}" for i, p in enumerate(bundle.policy_constraints)
        ])
        policy_section = f"""
POLICY CONSTRAINTS (non-negotiable — violations are always CRITICAL):
{policies_text}
""".strip()
    else:
        policy_section = "POLICY CONSTRAINTS: None provided."

    # ── Section 5: Tool findings ──────────────────────────────────────────────
    import json
    findings_list = [f.model_dump() for f in bundle.findings]
    findings_section = f"""
TOOL FINDINGS ({len(bundle.findings)} total, with base_confidence scores):
{json.dumps(findings_list, indent=2)}
""".strip()

    # ── Section 6: Source code ────────────────────────────────────────────────
    code_section = "SOURCE CODE SNIPPETS:"
    for fname, content in bundle.file_contents.items():
        truncated = content[:3000]
        if len(content) > 3000:
            truncated += f"\n... ({len(content)-3000} chars truncated)"
        code_section += f"\n{'='*50}\nFILE: {fname}\n{'='*50}\n{truncated}"

    return "\n\n".join([
        context_section,
        kg_section,
        problems_section,
        policy_section,
        findings_section,
        code_section,
    ])