# llm/agent.py
import os
import json
from openai import OpenAI
from dotenv import load_dotenv
from schemas import NormalizedBundle, LLMOutput, LLMFinding, Severity, A2AMessage
from llm.prompts import build_system_prompt, build_user_message

load_dotenv()

client = OpenAI(
    api_key=os.getenv("DEEPSEEK_API_KEY"),
    base_url="https://api.deepseek.com",
)

MODEL = "deepseek-chat"


def analyze(bundle: NormalizedBundle, msg: A2AMessage) -> LLMOutput:
    """
    Send normalized findings + full A2A context to DeepSeek.
    """
    if not bundle.findings:
        return _clean_output(bundle.scan_id)

    import json
    output_schema = json.dumps(LLMOutput.model_json_schema(), indent=2)

    system_prompt = build_system_prompt(output_schema)
    user_message  = build_user_message(bundle)

    print(f"[llm] Sending {len(bundle.findings)} findings to DeepSeek...")
    print(f"[llm] Reflexion enabled: {msg.needs_reflexion}")

    try:
        result = _single_llm_call(system_prompt, user_message, bundle.scan_id)

        if msg.needs_reflexion:
            result = _run_reflexion_loop(
                bundle=bundle,
                system_prompt=system_prompt,
                draft=result,
                threshold=msg.reflexion_threshold,
                max_retries=msg.reflexion_max_retries,
            )

        return result

    except Exception as e:
        print(f"[llm] ERROR: {e}")
        return _fallback_output(bundle, str(e))

def _single_llm_call(
    system_prompt: str,
    user_message: str,
    scan_id: str
) -> LLMOutput:
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
    return _parse_and_validate(raw_text, scan_id)


def _run_reflexion_loop(
    bundle: NormalizedBundle,
    system_prompt: str,
    draft: LLMOutput,
    threshold: float,
    max_retries: int,
) -> LLMOutput:
    import json
    for attempt in range(max_retries):
        avg = _average_confidence(draft)
        print(f"[llm] Reflexion check: avg_confidence={avg:.2f} threshold={threshold}")
        if avg >= threshold:
            print(f"[llm] Threshold met — stopping reflexion")
            break

        print(f"[llm] Reflexion pass {attempt + 1}/{max_retries}")
        reflexion_prompt = f"""
You previously produced this security analysis:
{draft.model_dump_json(indent=2)}

Critique your own findings:
- Are any confidence scores too high or too low given the code context?
- Did you miss attack chain connections between findings?
- Are any findings clearly false positives on reflection?
- Does the remediation actually fix the root cause?

Return a corrected version in the same JSON schema.
""".strip()

        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": reflexion_prompt},
            ],
            temperature=0.1,
            max_tokens=4000,
            response_format={"type": "json_object"},
        )
        draft = _parse_and_validate(
            response.choices[0].message.content, bundle.scan_id
        )

    return draft


def _average_confidence(result: LLMOutput) -> float:
    confirmed = [f for f in result.findings if not f.is_false_positive]
    if not confirmed:
        return 1.0
    return sum(f.final_confidence for f in confirmed) / len(confirmed)

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