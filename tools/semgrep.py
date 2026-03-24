# tools/semgrep.py
import subprocess
import json
from schemas import NormalizedFinding, Severity

# Maps Semgrep rule IDs to OWASP categories and CWE numbers.
# This grows as you test. Start with the most common ones.
OWASP_MAP: dict[str, tuple[str, str]] = {
    # Injection
    "python.django.security.injection.tainted-sql-string":      ("A03", "CWE-89"),
    "python.flask.security.injection.tainted-sql-string":       ("A03", "CWE-89"),
    "javascript.sequelize.security.audit.sequelize-injection":  ("A03", "CWE-89"),
    # Crypto
    "python.cryptography.security.insecure-cipher-algorithm":   ("A02", "CWE-327"),
    "javascript.crypto.security.crypto-weak-random":            ("A02", "CWE-338"),
    # Hardcoded secrets (Semgrep also catches some)
    "python.lang.security.audit.hardcoded-password-funcarg":    ("A07", "CWE-798"),
    "python.lang.security.audit.hardcoded-password-string":     ("A07", "CWE-798"),
    # Logging
    "python.lang.security.audit.logging.logging-exception-without-logging": ("A09", "CWE-778"),
}

SEVERITY_MAP: dict[str, Severity] = {
    "ERROR":   Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO":    Severity.LOW,
}


def run(files: list[str]) -> list[NormalizedFinding]:
    """
    Run Semgrep against the given files.
    --config=auto uses Semgrep's default community ruleset.
    --json gives us machine-readable output.
    --quiet suppresses progress messages so only JSON goes to stdout.
    """
    if not files:
        return []

    result = subprocess.run(
        ["semgrep", "--config=auto", "--json", "--quiet"] + files,
        capture_output=True,
        text=True,
        timeout=180      # 3 min max — large codebases can be slow
    )

    # Semgrep returns exit code 1 when it finds issues — that is NOT an error.
    # Exit code 2 means a real error (bad config, file not found, etc.)
    if result.returncode == 2:
        print(f"[semgrep] ERROR: {result.stderr[:500]}")
        return []

    try:
        raw = json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"[semgrep] Failed to parse output: {result.stdout[:200]}")
        return []

    findings = []
    for r in raw.get("results", []):
        rule_id  = r.get("check_id", "unknown")
        owasp, cwe = OWASP_MAP.get(rule_id, (None, None))
        severity_str = r.get("extra", {}).get("severity", "WARNING").upper()

        findings.append(NormalizedFinding(
            tool="semgrep",
            rule_id=rule_id,
            title=r.get("extra", {}).get("message", rule_id),
            description=r.get("extra", {}).get("metadata", {}).get("description", ""),
            severity=SEVERITY_MAP.get(severity_str, Severity.MEDIUM),
            file_path=r.get("path"),
            line_start=r.get("start", {}).get("line"),
            line_end=r.get("end", {}).get("line"),
            owasp_category=owasp,
            cwe=cwe,
            evidence=r.get("extra", {}).get("lines", "").strip(),
        ))

    print(f"[semgrep] {len(findings)} findings")
    return findings