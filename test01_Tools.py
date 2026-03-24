# test_day1.py
import yaml
import json
from schemas import OrchestratorInput
from tools.runner import route_and_run
from scorer import score_all

def test_day1():
    # Load the test YAML
    with open("test_input.yaml") as f:
        raw = yaml.safe_load(f)

    inp = OrchestratorInput(**raw)
    print(f"\n{'='*50}")
    print(f"Scan ID: {inp.scan_id}")
    print(f"Environment: {inp.environment}")
    print(f"Files: {inp.files}")
    print(f"{'='*50}\n")

    # Run all tools
    findings = route_and_run(inp)

    # Score them
    scored = score_all(findings)

    # Print results
    print(f"\n{'='*50}")
    print(f"RESULTS: {len(scored)} total findings")
    print(f"{'='*50}")

    for f in scored:
        print(f"\n[{f.tool.upper()}] {f.severity.value} — {f.title}")
        print(f"  Rule:       {f.rule_id}")
        print(f"  File:       {f.file_path}:{f.line_start}")
        print(f"  OWASP:      {f.owasp_category or 'N/A'}")
        print(f"  CWE:        {f.cwe or 'N/A'}")
        print(f"  Evidence:   {(f.evidence or '')[:80]}")
        print(f"  Confidence: {f.base_confidence}")

    # Verify we got findings from each tool
    tools_found = {f.tool for f in scored}
    print(f"\n{'='*50}")
    print(f"Tools that produced findings: {tools_found}")

    # Assertions
    assert len(scored) > 0, "Expected at least one finding"
    assert "semgrep" in tools_found, "Semgrep should have found the SQL injection"
    assert "gitleaks" in tools_found, "Gitleaks should have found the hardcoded secret"
    assert "trivy" in tools_found, "Trivy should have found CVEs in requirements.txt"

    print("\nAll assertions passed — Day 1 complete.")

if __name__ == "__main__":
    test_day1()