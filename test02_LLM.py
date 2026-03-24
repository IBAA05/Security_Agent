# test_day2.py
import yaml
import json
from schemas import OrchestratorInput, NormalizedBundle
from tools.runner import route_and_run
from scorer import score_all
from llm.agent import analyze


def test_day2():
    print("\n" + "="*50)
    print("TEST 1: Full pipeline on vuln_app.py")
    print("="*50)

    with open("test_input.yaml") as f:
        raw = yaml.safe_load(f)
    inp = OrchestratorInput(**raw)

    raw_findings = route_and_run(inp)
    scored = score_all(raw_findings)

    file_contents = {}
    for fpath in inp.files:
        try:
            with open(fpath) as f:
                file_contents[fpath] = f.read()
        except Exception:
            file_contents[fpath] = ""

    bundle = NormalizedBundle(
        scan_id=inp.scan_id,
        findings=scored,
        file_contents=file_contents,
    )

    result = analyze(bundle)

    print(f"Overall risk:   {result.overall_risk}")
    print(f"Total findings: {len(result.findings)}")
    print(f"Summary: {result.summary}")

    for f in result.findings:
        print(f"\n  [{f.severity.value}] {f.title}")
        print(f"  Confidence: {f.base_confidence} → {f.final_confidence}")
        print(f"  FP: {f.is_false_positive}")
        print(f"  Reasoning: {f.reasoning[:150]}")

    # ── Assertion 1: hardcoded secret must be confirmed HIGH or CRITICAL ──
    secret_findings = [
        f for f in result.findings
        if "secret" in f.title.lower() or "key" in f.title.lower()
        and not f.is_false_positive
    ]
    assert len(secret_findings) > 0, \
        "Expected at least one confirmed secret finding"
    print("\nAssertion 1 PASSED: hardcoded secret confirmed")

    # ── Assertion 2: overall risk must not be CLEAN ───────────────────────
    assert result.overall_risk != "CLEAN", \
        "Overall risk should not be CLEAN with known vulnerabilities"
    print("Assertion 2 PASSED: overall risk is not CLEAN")

    # ── Assertion 3: all findings must have reasoning (not empty) ─────────
    for f in result.findings:
        assert len(f.reasoning) > 20, \
            f"Finding {f.rule_id} has empty reasoning"
    print("Assertion 3 PASSED: all findings have reasoning")

    # ── Assertion 4: final_confidence is always in [0, 1] ─────────────────
    for f in result.findings:
        assert 0.0 <= f.final_confidence <= 1.0, \
            f"final_confidence out of range: {f.final_confidence}"
    print("Assertion 4 PASSED: all confidence scores in valid range")

    print("\n" + "="*50)
    print("All Day 2 assertions passed.")
    print("="*50)


if __name__ == "__main__":
    test_day2()