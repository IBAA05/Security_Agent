# main.py
import json
import sys
import asyncio
from agent_core import SecurityReviewerAgent


async def run(input_path: str) -> dict:
    agent = SecurityReviewerAgent()

    with open(input_path, encoding="utf-8") as f:
        raw_payload = f.read()

    result = await agent.review(raw_payload)

    print(f"\n{'='*60}")
    report = result["result"]
    summary = report.get("summary", {})
    stats = report.get("statistics", {})

    print(f"OVERALL RISK:     {summary.get('overall_risk')}")
    print(f"BLOCK MERGE:      {summary.get('block_merge_recommended')}")
    print(f"ASSESSMENT:       {summary.get('assessment', '')[:100]}")
    print(f"Confirmed:        {stats.get('confirmed_findings')}")
    print(f"False positives:  {stats.get('false_positives_dismissed')}")
    print(f"Critical:         {stats.get('critical_count')}")
    print(f"High:             {stats.get('high_count')}")
    print(f"OWASP hits:       {stats.get('owasp_categories_hit')}")
    print(f"Overall confidence: {result['confidence']}")
    print(f"{'='*60}")

    for f in report.get("findings", []):
        print(f"\n[{f['severity']}] {f['title']}")
        print(f"  OWASP:      {f.get('owasp_category', 'N/A')}")
        conf = f.get("confidence", {})
        print(f"  Confidence: {conf.get('base')} base "
              f"→ {conf.get('llm_adjustment', 0):+.2f} adj "
              f"→ {conf.get('final')} final")
        print(f"  Reasoning:  {f.get('reasoning', '')[:150]}")
        print(f"  Fix:        {f.get('remediation', '')[:150]}")
        if f.get("correlates_with_problem"):
            print(f"  Correlates: {f['correlates_with_problem']}")

    if report.get("policy_violations"):
        print(f"\nPOLICY VIOLATIONS:")
        for v in report["policy_violations"]:
            print(f"  [{v['policy_id']}] {v['severity']} — {v['finding']}")

    if report.get("attack_chains"):
        print(f"\nATTACK CHAINS:")
        for c in report["attack_chains"]:
            print(f"  {c['chain_id']}: {c['finding_ids']}")

    return result


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "test_a2a_input.json"
    result = asyncio.run(run(path))

    output_path = "scan_report.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result["result"], f, indent=2, default=str)
    print(f"\nFull report saved to: {output_path}")