# llm/agent.py
import os
import json
from openai import OpenAI
from dotenv import load_dotenv
from schemas import NormalizedBundle, LLMOutput, LLMFinding, Severity
from llm.prompts import build_system_prompt, build_user_message

load_dotenv()

client = OpenAI(
    api_key=os.getenv("DEEPSEEK_API_KEY"),
    base_url="https://api.deepseek.com",
)

MODEL = "deepseek-chat"


def analyze(bundle: NormalizedBundle) -> LLMOutput:
    """
    Send normalized findings + file contents to DeepSeek.
    Returns a fully validated LLMOutput object.
    Falls back to a safe degraded output if the API call fails.
    """
    if not bundle.findings:
        return _clean_output(bundle.scan_id)

    # Build the output schema string so LLM knows exactly what to return
    output_schema = json.dumps(LLMOutput.model_json_schema(), indent=2)

    system_prompt = build_system_prompt(output_schema)
    user_message  = build_user_message(
        findings_json=bundle.model_dump_json(indent=2),
        file_contents=bundle.file_contents,
    )

    print(f"[llm] Sending {len(bundle.findings)} findings to DeepSeek...")

    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_message},
            ],
            temperature=0.1,
            max_tokens=4000,
            response_format={"type": "json_object"},
        )

        raw_text = response.choices[0].message.content
        print(f"[llm] Response received ({len(raw_text)} chars)")

        return _parse_and_validate(raw_text, bundle.scan_id)

    except Exception as e:
        print(f"[llm] ERROR: {e}")
        return _fallback_output(bundle, str(e))


def _parse_and_validate(raw_text: str, scan_id: str) -> LLMOutput:
    """
    Parse the JSON response and validate it against LLMOutput schema.
    Handles common LLM formatting mistakes.
    """
    # Strip markdown fences if the LLM added them despite instructions
    cleaned = raw_text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        cleaned = "\n".join(lines[1:-1])

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as e:
        raise ValueError(f"LLM returned invalid JSON: {e}\nRaw: {raw_text[:300]}")

    # Inject scan_id if missing (LLM sometimes forgets it)
    data.setdefault("scan_id", scan_id)

    # Clamp final_confidence values to [0.0, 1.0] and compute if missing
    for finding in data.get("findings", []):
        base = finding.get("base_confidence", 0.0)
        adj  = finding.get("llm_confidence_adjustment", 0.0)
        # Always recompute final — don't trust LLM's arithmetic
        finding["final_confidence"] = round(
            min(max(base + adj, 0.0), 1.0), 3
        )

    return LLMOutput.model_validate(data)


def _clean_output(scan_id: str) -> LLMOutput:
    """No findings — return a clean result."""
    return LLMOutput(
        scan_id=scan_id,
        summary="No security findings detected in the analyzed files.",
        findings=[],
        critical_count=0,
        high_count=0,
        overall_risk="CLEAN",
    )


def _fallback_output(bundle: NormalizedBundle, error: str) -> LLMOutput:
    """
    If DeepSeek fails (network error, invalid response, etc.),
    return a degraded output using the raw tool findings without LLM reasoning.
    This ensures the pipeline never crashes — it degrades gracefully.
    """
    print(f"[llm] Using fallback output due to error: {error}")

    fallback_findings = []
    critical_count = 0
    high_count = 0

    for f in bundle.findings:
        llm_finding = LLMFinding(
            rule_id=f.rule_id,
            title=f.title,
            severity=f.severity,
            owasp_category=f.owasp_category,
            cwe=f.cwe,
            base_confidence=f.base_confidence,
            llm_confidence_adjustment=0.0,
            final_confidence=f.base_confidence,
            is_false_positive=False,
            reasoning="LLM analysis unavailable — showing raw tool finding.",
            remediation="Manual review required.",
        )
        fallback_findings.append(llm_finding)

        if f.severity == Severity.CRITICAL:
            critical_count += 1
        elif f.severity == Severity.HIGH:
            high_count += 1

    overall = "CLEAN"
    if critical_count > 0:
        overall = "CRITICAL"
    elif high_count > 0:
        overall = "HIGH"
    elif fallback_findings:
        overall = "MEDIUM"

    return LLMOutput(
        scan_id=bundle.scan_id,
        summary=f"LLM analysis failed ({error}). Showing raw tool findings only.",
        findings=fallback_findings,
        critical_count=critical_count,
        high_count=high_count,
        overall_risk=overall,
    )