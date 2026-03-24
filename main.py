# main.py
import yaml
import json
import sys
from schemas import OrchestratorInput, NormalizedBundle
from tools.runner import route_and_run
from scorer import score_all
from llm.agent import analyze


def run_security_agent(yaml_input_path: str) -> dict:

    # ── 1. Load orchestrator input ───────────────────────────────────────────
    with open(yaml_input_path) as f:
        raw = yaml.safe_load(f)
    inp = OrchestratorInput(**raw)

    print(f"\n{'='*50}")
    print(f"Scan ID:     {inp.scan_id}")
    print(f"Environment: {inp.environment}")
    print(f"Files:       {inp.files}")
    print(f"{'='*50}\n")

    # ── 2. Run tools and normalize ───────────────────────────────────────────
    raw_findings = route_and_run(inp)

    # ── 3. Score findings with rule-based scorer ─────────────────────────────
    scored_findings = score_all(raw_findings)

    # ── 4. Read file contents for LLM context ───────────────────────────────
    import os
    file_contents = {}
    for fpath in inp.files:
        try:
            with open(fpath, encoding="utf-8") as f:
                file_contents[fpath] = f.read()
        except Exception:
            file_contents[fpath] = "[could not read file]"

    # ── 5. Build bundle and call LLM ────────────────────────────────────────
    bundle = NormalizedBundle(
        scan_id=inp.scan_id,
        findings=scored_findings,
        file_contents=file_contents,
    )
    llm_output = analyze(bundle)

    # ── 6. Print results ────────────────────────────────────────────────────
    print(f"\n{'='*50}")
    print(f"OVERALL RISK:  {llm_output.overall_risk}")
    print(f"SUMMARY:       {llm_output.summary}")
    print(f"Critical:      {llm_output.critical_count}")
    print(f"High:          {llm_output.high_count}")
    print(f"Total findings:{len(llm_output.findings)}")
    print(f"{'='*50}")

    for finding in llm_output.findings:
        fp_tag = " [FALSE POSITIVE]" if finding.is_false_positive else ""
        print(f"\n[{finding.severity.value}]{fp_tag} {finding.title}")
        print(f"  Rule:        {finding.rule_id}")
        print(f"  OWASP:       {finding.owasp_category or 'N/A'}")
        print(f"  Confidence:  {finding.base_confidence} base "
              f"→ {finding.llm_confidence_adjustment:+.2f} adj "
              f"→ {finding.final_confidence} final")
        print(f"  Reasoning:   {finding.reasoning[:120]}")
        print(f"  Remediation: {finding.remediation[:120]}")

    return llm_output.model_dump()


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "test_input.yaml"
    result = run_security_agent(path)
    print(f"\n{'='*50}")
    print("Full JSON output:")
    print(json.dumps(result, indent=2, default=str))