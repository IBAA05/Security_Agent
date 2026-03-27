# executor.py — replace the a2a imports block with this
import json
import uvicorn

from agent_core import SecurityReviewerAgent

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.tasks import InMemoryTaskStore
from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.types import (
    AgentCard,
    AgentSkill,
    AgentCapabilities,
    TaskState,
    TaskStatusUpdateEvent,
)
from a2a.utils import new_agent_text_message


class SecurityReviewerExecutor:
    """
    A2A executor wrapper around SecurityReviewerAgent.
    Handles the A2A protocol layer — receiving tasks,
    emitting events, and returning results.
    """

    def __init__(self):
        self.agent = SecurityReviewerAgent()

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        # Extract the JSON payload from the A2A message
        # Assuming the first part contains the code/content to scan
        payload = context.message.parts[0].text

        # Notify Orchestrator that scan has started
        event_queue.enqueue_event(TaskStatusUpdateEvent(
            state=TaskState.running,
            message="Security analysis pipeline started (Semgrep, Gitleaks, Trivy)..."
        ))

        try:
            # Call the core logic from agent_core.py
            result = await self.agent.review(payload)

            # Send the full JSON report as a text message back to the Orchestrator
            event_queue.enqueue_event(
                new_agent_text_message(
                    json.dumps(result["result"], indent=2)
                )
            )

            # Complete the task with summary and confidence metrics
            event_queue.enqueue_event(TaskStatusUpdateEvent(
                state=TaskState.completed,
                confidence=result["confidence"],
                message=(
                    f"Scan complete. "
                    f"Risk: {result['result']['summary']['overall_risk']}. "
                    f"Block recommended: "
                    f"{result['result']['summary']['block_merge_recommended']}"
                )
            ))

        except Exception as e:
            # Handle failures gracefully by notifying the Orchestrator
            event_queue.enqueue_event(TaskStatusUpdateEvent(
                state=TaskState.failed,
                message=f"Security agent error: {str(e)}"
            ))

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        event_queue.enqueue_event(TaskStatusUpdateEvent(
            state=TaskState.canceled,
            message="Security scan canceled by Orchestrator"
        ))


def build_agent_card() -> AgentCard:
    skill = AgentSkill(
        id="security_review",
        name="Security Review",
        description=(
            "Analyzes code changes for OWASP Top 10 vulnerabilities, "
            "hardcoded secrets, CVEs, policy violations, and semantic "
            "security flaws using static tools + LLM reasoning."
        ),
        tags=["security", "owasp", "sast", "secrets", "cve", "jwt", "auth"],
        examples=[
            "Review this auth refactor for security issues",
            "Check this PR for hardcoded secrets",
        ],
    )

    return AgentCard(
        name="ARGUS Security Agent",
        description=(
            "Multi-tool security analysis with LLM semantic reasoning, "
            "policy enforcement, and historical memory."
        ),
        url="http://localhost:9999/",
        version="1.0.0",
        defaultInputModes=["application/json"],
        defaultOutputModes=["application/json"],
        capabilities=AgentCapabilities(),
        skills=[skill],
    )


def start_server(host: str = "0.0.0.0", port: int = 9999):
    """Initializes and starts the A2A server."""

    # Initialize the handler with our custom executor logic
    request_handler = DefaultRequestHandler(
        agent_executor=SecurityReviewerExecutor(),
        task_store=InMemoryTaskStore(),
    )

    # Build the Starlette application with the agent card and handler
    server_app = A2AStarletteApplication(
        agent_card=build_agent_card(),
        http_handler=request_handler,
    )

    print(f"\n{'=' * 50}")
    print(f"🛡️  ARGUS Security Agent (v1.0.0) starting...")
    print(f"🌍 Listening on http://{host}:{port}")
    print(f"📜 Agent card: http://{host}:{port}/.well-known/agent.json")
    print(f"{'=' * 50}\n")

    uvicorn.run(server_app.build(), host=host, port=port)


if __name__ == "__main__":
    start_server()