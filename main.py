# main.py
import json
import sys
import tempfile
import os
from schemas import (
    A2AMessage, NormalizedBundle,
    ActiveProblem
)
from tools.runner import route_and_run
from scorer import score_with_memory
from llm.agent import analyze
from memory.store import get_file_context, update_after_scan


def _build_kg_summary(msg: A2AMessage) -> str:
    """
    Convert knowledge graph nodes into a readable summary
    for the LLM prompt.
    """
    lines = []
    for node in msg.payload.knowledge_graph.nodes:
        line = f"  [{node.id}] {node.file} — role: {node.role}"
        if node.logic_delta:
            line += f"\n       change: {node.logic_delta}"
        if node.impact:
            line += f"\n       impact: {node.impact}"
        if node.status:
            line += f"\n       status: {node.status}"
        if node.symbols_changed:
            line += f"\n       symbols: {node.symbols_changed}"
        lines.append(line)
    return "\n".join(lines)


def run_security_agent(input_path: str) -> dict:
    """
    Main pipeline. Accepts either:
    - A JSON file containing the full A2A message
    - A raw JSON string (for testing)
    """

    # ── 1. Parse the A2A message ──────────────────────────────────────────────
    with open(input_path, encoding="utf-8") as f:
        raw = json.load(f)

    msg = A2AMessage.model_validate(raw)

    print(f"\n{'='*60}")
    print(f"Scan ID:        {msg.metadata.message_id}")
    print(f"Correlation:    {msg.metadata.correlation_id}")
    print(f"Sender:         {msg.metadata.sender}")
    print(f"Intent:         {msg.payload.intent}")
    print(f"Priority:       {msg.routing_instructions.priority}")
    print(f"Needs reflexion:{msg.needs_reflexion}")
    print(f"Files to scan:  {msg.get_files_to_scan()}")
    print(f"Affected (not scanned): "
          f"{msg.payload.knowledge_graph.affected_files()}")
    print(f"{'='*60}\n")

    # ── 2. Get memory context for scanned files ───────────────────────────────
    files_to_scan = msg.get_files_to_scan()
    memory_ctx = get_file_context(files_to_scan)

    print("[memory] File priority scores:")
    for fpath, ctx in memory_ctx.items():
        print(f"  {fpath}: priority={ctx['priority_score']} "
              f"scans={ctx['scan_count']}")

    # ── 3. Run tools on snippets ──────────────────────────────────────────────
    raw_findings, _ = route_and_run(msg)

    # ── 4. Score with memory ──────────────────────────────────────────────────
    scored_findings = score_with_memory(raw_findings, files_to_scan)

    # ── 5. Build bundle with full A2A context ─────────────────────────────────
    bundle = NormalizedBundle(
        scan_id=msg.metadata.message_id,
        findings=scored_findings,
        # File contents come from the dehydrated snippets
        file_contents=msg.get_file_snippets(),
        # Knowledge graph as readable summary for LLM
        knowledge_graph_summary=_build_kg_summary(msg),
        # Active problems from Librarian — LLM must cross-reference
        active_problems=msg.payload.active_problem_set,
        # Policy constraints — LLM must enforce
        policy_constraints=msg.payload.dehydrated_content.policy_constraints,
        # Intent and priority for context
        intent=msg.payload.intent,
        priority=msg.routing_instructions.priority,
    )

    # ── 6. LLM analysis ───────────────────────────────────────────────────────
    llm_output = analyze(bundle, msg)

    # Attach correlation_id so Orchestrator can route the response
    llm_output.correlation_id = msg.metadata.correlation_id

    # ── 7. Update memory ──────────────────────────────────────────────────────
    update_after_scan(llm_output, files_to_scan)

    # ── 8. Print summary ──────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"OVERALL RISK:    {llm_output.overall_risk}")
    print(f"SUMMARY:         {llm_output.summary}")
    print(f"Critical:        {llm_output.critical_count}")
    print(f"High:            {llm_output.high_count}")
    print(f"Total findings:  {len(llm_output.findings)}")
    if llm_output.confirmed_active_problems:
        print(f"Confirmed upstream problems: "
              f"{llm_output.confirmed_active_problems}")
    print(f"{'='*60}")

    for finding in llm_output.findings:
        fp = " [FALSE POSITIVE]" if finding.is_false_positive else ""
        corr = (f" [correlates: {finding.correlates_with_problem}]"
                if finding.correlates_with_problem else "")
        print(f"\n[{finding.severity.value}]{fp}{corr} {finding.title}")
        print(f"  Rule:        {finding.rule_id}")
        print(f"  OWASP:       {finding.owasp_category or 'N/A'}")
        print(f"  Confidence:  {finding.base_confidence} base "
              f"→ {finding.llm_confidence_adjustment:+.2f} adj "
              f"→ {finding.final_confidence} final")
        print(f"  Reasoning:   {finding.reasoning[:150]}")
        print(f"  Remediation: {finding.remediation[:150]}")

    return llm_output.model_dump()


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "test_a2a_input.json"
    result = run_security_agent(path)
    print(f"\nFull JSON output:")
    print(json.dumps(result, indent=2, default=str))