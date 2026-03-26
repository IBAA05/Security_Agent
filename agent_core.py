# agent_core.py
import json
from schemas import A2AMessage, NormalizedBundle
from tools.runner import route_and_run
from scorer import score_with_memory
from llm.agent import analyze
from report.generator import generate
from memory.store import get_file_context, update_after_scan


def _build_kg_summary(msg: A2AMessage) -> str:
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


class SecurityReviewerAgent:
    """
    The core agent class.
    Called by the executor — contains the full pipeline.
    Also callable directly from main.py for testing.
    """

    async def review(self, raw_payload: str) -> dict:
        """
        Main entry point. Receives the raw JSON string from
        the Orchestrator via the A2A executor.
        Returns {"result": report_dict, "confidence": float}
        """

        # ── 1. Parse and validate ──────────────────────────────────────────
        try:
            data = json.loads(raw_payload)
            msg = A2AMessage.model_validate(data)
        except Exception as e:
            return {
                "result": {
                    "error": f"Invalid A2A payload: {str(e)}",
                    "correlation_id": "unknown",
                },
                "confidence": 0.0,
            }

        print(f"\n[agent] Intent:    {msg.payload.intent}")
        print(f"[agent] Priority:  {msg.routing_instructions.priority}")
        print(f"[agent] Reflexion: {msg.needs_reflexion}")
        print(f"[agent] Files:     {msg.get_files_to_scan()}")

        # ── 2. Memory context ──────────────────────────────────────────────
        files_to_scan = msg.get_files_to_scan()
        memory_ctx = get_file_context(files_to_scan)

        # ── 3. Run tools ───────────────────────────────────────────────────
        raw_findings, _ = route_and_run(msg)

        # ── 4. Score with memory ───────────────────────────────────────────
        scored_findings = score_with_memory(raw_findings, files_to_scan)

        # ── 5. Build bundle ────────────────────────────────────────────────
        bundle = NormalizedBundle(
            scan_id=msg.metadata.message_id,
            findings=scored_findings,
            file_contents=msg.get_file_snippets(),
            knowledge_graph_summary=_build_kg_summary(msg),
            active_problems=msg.payload.active_problem_set,
            policy_constraints=(
                msg.payload.dehydrated_content.policy_constraints
            ),
            intent=msg.payload.intent,
            priority=msg.routing_instructions.priority,
        )

        # ── 6. LLM analysis ────────────────────────────────────────────────
        llm_output = analyze(bundle, msg)
        llm_output.correlation_id = msg.metadata.correlation_id

        # ── 7. Generate report ─────────────────────────────────────────────
        report = generate(msg, raw_findings, llm_output)

        # ── 8. Update memory ───────────────────────────────────────────────
        update_after_scan(llm_output, files_to_scan)

        # ── 9. Calculate overall confidence ───────────────────────────────
        overall_confidence = self._calculate_confidence(llm_output)

        return {
            "result": report,
            "confidence": overall_confidence,
        }

    def _calculate_confidence(self, llm_output) -> float:
        """
        Single confidence value for the A2A TaskStatusUpdateEvent.
        High confidence means the agent is sure about its findings.
        """
        if llm_output.overall_risk == "CRITICAL":
            # If we found critical issues we're very confident something
            # is wrong — but not necessarily confident in every detail
            confirmed = [
                f for f in llm_output.findings
                if not f.is_false_positive
            ]
            if confirmed:
                return round(
                    sum(f.final_confidence for f in confirmed)
                    / len(confirmed), 3
                )
        if not llm_output.findings:
            return 0.99  # confident the scan is clean
        confirmed = [
            f for f in llm_output.findings
            if not f.is_false_positive
        ]
        if not confirmed:
            return 0.99
        return round(
            sum(f.final_confidence for f in confirmed) / len(confirmed), 3
        )