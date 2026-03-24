# tools/gitleaks.py
import subprocess
import json
import tempfile
import os
from schemas import NormalizedFinding, Severity

# Gitleaks rule IDs map to A07 (Identification Failures) by default
# because exposed secrets break authentication
RULE_OWASP_MAP: dict[str, tuple[str, str]] = {
    "generic-api-key":          ("A07", "CWE-798"),
    "aws-access-token":         ("A07", "CWE-798"),
    "github-pat":               ("A07", "CWE-798"),
    "private-key":              ("A02", "CWE-321"),
    "jwt":                      ("A07", "CWE-798"),
    "stripe-access-token":      ("A07", "CWE-798"),
    "google-api-key":           ("A07", "CWE-798"),
    "generic-secret":           ("A07", "CWE-798"),
}


def run(files: list[str]) -> list[NormalizedFinding]:
    """
    Gitleaks works on a directory or a list of files.
    We write the file list to a temp file and pass it to gitleaks.
    --no-git tells it to scan raw files, not a git history.
    --report-format json gives us structured output.
    """
    if not files:
        return []

    # Write findings to a temp JSON file — gitleaks can't output to stdout directly
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_path = tmp.name

    findings = []
    for fpath in files:
        if not os.path.isfile(fpath):
            continue

        result = subprocess.run(
            [
                "gitleaks", "detect",
                "--source", fpath,
                "--no-git",
                "--report-format", "json",
                "--report-path", report_path,
                "--exit-code", "0",   # always exit 0 so we control flow
            ],
            capture_output=True,
            text=True,
            timeout=60
        )

        try:
            with open(report_path) as f:
                content = f.read().strip()
            if not content:
                continue
            leaks = json.loads(content)
        except (json.JSONDecodeError, FileNotFoundError):
            continue

        for leak in leaks:
            rule_id = leak.get("RuleID", "generic-secret")
            owasp, cwe = RULE_OWASP_MAP.get(rule_id, ("A07", "CWE-798"))
            findings.append(NormalizedFinding(
                tool="gitleaks",
                rule_id=rule_id,
                title=f"Hardcoded secret: {leak.get('Description', rule_id)}",
                description=f"Secret of type '{rule_id}' found in file.",
                severity=Severity.HIGH,     # secrets are always at least HIGH
                file_path=leak.get("File"),
                line_start=leak.get("StartLine"),
                line_end=leak.get("EndLine"),
                owasp_category=owasp,
                cwe=cwe,
                # IMPORTANT: we redact the actual secret value in evidence
                # we only keep the match context, not the secret itself
                evidence=f"Match at line {leak.get('StartLine')} — secret redacted",
            ))

    os.unlink(report_path)   # clean up temp file
    print(f"[gitleaks] {len(findings)} findings")
    return findings