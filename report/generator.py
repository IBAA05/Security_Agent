# report/generator.py
from datetime import datetime, timezone
from schemas import A2AMessage, LLMOutput, NormalizedFinding, Severity


def generate(
    msg: A2AMessage,
    raw_findings: list[NormalizedFinding],
    llm_output: LLMOutput,
) -> dict:
    """
    Builds the final JSON report sent back to the Orchestrator.

    Structure follows the A2A response convention so the Orchestrator
    can parse it without knowing the internals of your agent.
    """
    confirmed = [f for f in llm_output.findings if not f.is_false_positive]
    false_positives = [f for f in llm_output.findings if f.is_false_positive]

    # OWASP categories actually hit in this scan
    owasp_hits = sorted({
        f.owasp_category
        for f in confirmed
        if f.owasp_category
    })

    # Attack chains — findings linked to each other
    attack_chains = _extract_attack_chains(confirmed)

    # Policy violations — findings that violated a company rule
    policy_violations = [
        {
            "policy_id": f.violated_policy_id,
            "finding": f.rule_id,
            "severity": f.severity.value,
            "file": f.file_path,
        }
        for f in confirmed
        if f.violated_policy_id
    ]

    return {
        # ── A2A routing fields ─────────────────────────────────────────────
        "protocol": "A2A/1.0",
        "response_to": msg.metadata.message_id,
        "correlation_id": msg.metadata.correlation_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sender": "argus-security-agent",
        "version": "1.0.0",

        # ── Executive summary ──────────────────────────────────────────────
        "summary": {
            "overall_risk": llm_output.overall_risk,
            "assessment": llm_output.summary,
            "intent_analyzed": msg.payload.intent,
            "priority_received": msg.routing_instructions.priority,
            "block_merge_recommended": _should_block(llm_output),
        },

        # ── Counts ────────────────────────────────────────────────────────
        "statistics": {
            "raw_findings_from_tools": len(raw_findings),
            "confirmed_findings": len(confirmed),
            "false_positives_dismissed": len(false_positives),
            "critical_count": llm_output.critical_count,
            "high_count": llm_output.high_count,
            "medium_count": sum(
                1 for f in confirmed if f.severity == Severity.MEDIUM
            ),
            "low_count": sum(
                1 for f in confirmed if f.severity == Severity.LOW
            ),
            "owasp_categories_hit": owasp_hits,
        },

        # ── Tool coverage ─────────────────────────────────────────────────
        "tool_coverage": {
            "semgrep": len([f for f in raw_findings if f.tool == "semgrep"]),
            "gitleaks": len([f for f in raw_findings if f.tool == "gitleaks"]),
            "trivy": len([f for f in raw_findings if f.tool == "trivy"]),
            "zap": len([f for f in raw_findings if f.tool == "zap"]),
            "policy_check": len(
                [f for f in raw_findings if f.tool == "policy_check"]
            ),
            "environment": msg.environment,
            "zap_ran": msg.environment == "staging",
        },

        # ── Knowledge graph context ────────────────────────────────────────
        "knowledge_graph_context": {
            "files_scanned": msg.get_files_to_scan(),
            "files_affected_not_scanned": (
                msg.payload.knowledge_graph.affected_files()
            ),
            "blast_radius_note": _blast_radius_note(msg, confirmed),
        },

        # ── Active problems correlation ────────────────────────────────────
        "active_problems_correlation": {
            "received": len(msg.payload.active_problem_set),
            "confirmed_by_scan": llm_output.confirmed_active_problems,
            "details": [
                {
                    "problem": p.problem,
                    "location": p.location,
                    "confirmed": p.location in str(
                        llm_output.confirmed_active_problems
                    ),
                }
                for p in msg.payload.active_problem_set
            ],
        },

        # ── Policy violations ──────────────────────────────────────────────
        "policy_violations": policy_violations,

        # ── Attack chains ──────────────────────────────────────────────────
        "attack_chains": attack_chains,

        # ── Full confirmed findings ────────────────────────────────────────
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity.value,
                "owasp_category": f.owasp_category,
                "cwe": f.cwe,
                "confidence": {
                    "base": f.base_confidence,
                    "llm_adjustment": f.llm_confidence_adjustment,
                    "final": f.final_confidence,
                },
                "file_path": f.file_path,
                "reasoning": f.reasoning,
                "remediation": f.remediation,
                "correlates_with_problem": f.correlates_with_problem,
                "violated_policy_id": f.violated_policy_id,
                "linked_to": f.linked_finding_ids,
            }
            for f in confirmed
        ],

        # ── Dismissed false positives ──────────────────────────────────────
        "false_positives": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "reasoning": f.reasoning,
                "confidence": f.final_confidence,
            }
            for f in false_positives
        ],

        # ── Reflexion metadata ─────────────────────────────────────────────
        "reflexion": {
            "was_requested": msg.needs_reflexion,
            "threshold": msg.reflexion_threshold,
            "max_retries": msg.reflexion_max_retries,
        },
    }


def _should_block(llm_output: LLMOutput) -> bool:
    """
    Recommend blocking the merge if there are confirmed
    CRITICAL or HIGH findings with high confidence.
    The Orchestrator makes the final call — this is a recommendation.
    """
    if llm_output.overall_risk == "CRITICAL":
        return True
    if llm_output.overall_risk == "HIGH":
        high_confidence = [
            f for f in llm_output.findings
            if not f.is_false_positive
            and f.final_confidence >= 0.8
        ]
        return len(high_confidence) > 0
    return False


def _extract_attack_chains(
    confirmed: list
) -> list[dict]:
    """
    Finds groups of findings that are linked to each other —
    these represent a single exploit path, not independent issues.
    """
    chains = []
    visited = set()

    for f in confirmed:
        if f.rule_id in visited or not f.linked_finding_ids:
            continue
        chain = [f.rule_id] + f.linked_finding_ids
        visited.update(chain)
        chains.append({
            "chain_id": f"chain_{len(chains) + 1}",
            "finding_ids": chain,
            "description": (
                f"These {len(chain)} findings form a single attack path"
            ),
        })

    return chains


def _blast_radius_note(
    msg: A2AMessage,
    confirmed: list
) -> str:
    """
    If there are confirmed findings AND there are affected-but-not-scanned
    files in the knowledge graph, warn the Orchestrator that the impact
    may extend beyond what was scanned.
    """
    affected = msg.payload.knowledge_graph.affected_files()
    if confirmed and affected:
        return (
            f"WARNING: {len(confirmed)} confirmed findings in scanned files. "
            f"Files {affected} are affected but were not scanned. "
            f"Consider requesting a full scan of dependent files."
        )
    return "No blast radius concerns identified."