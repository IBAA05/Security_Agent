# tools/trivy.py
import subprocess
import json
from schemas import NormalizedFinding, Severity

SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH":     Severity.HIGH,
    "MEDIUM":   Severity.MEDIUM,
    "LOW":      Severity.LOW,
    "UNKNOWN":  Severity.INFO,
}

OWASP_MAP = {
    "CWE-89":   "A03",   # Injection
    "CWE-79":   "A03",   # XSS (also injection)
    "CWE-502":  "A08",   # Insecure Deserialization
    "CWE-22":   "A01",   # Path Traversal → Access Control
    "CWE-276":  "A05",   # Incorrect Permissions → Misconfiguration
    "CWE-400":  "A05",   # DoS
    "CWE-640":  "A07",   # Weak Password Reset
    "CWE-918":  "A10",   # SSRF
    "CWE-200":  "A02",   # Info Exposure → Crypto/Secrets
    "CWE-670":  "A05",   # Incorrect Implementation
    "CWE-522":  "A07",   # Insufficiently Protected Credentials
    "CWE-1321": "A03",   # Prototype Pollution
    "CWE-319":  "A02",   # Cleartext Transmission
    "CWE-1035": "A06",   # Vulnerable Components (default)
}


def run(files: list[str]) -> list[NormalizedFinding]:
    if not files:
        return []

    findings = []

    for fpath in files:
        result = subprocess.run(
            [
                "trivy", "fs",
                "--format", "json",
                "--scanners", "vuln",   # vuln only — faster, no secret/config overlap
                "--exit-code", "0",
                "--quiet",
                fpath,
            ],
            capture_output=True,
            text=True,
            timeout=300    # 5 min — first run needs to download the DB
        )

        if result.returncode not in (0, 1):
            print(f"[trivy] ERROR on {fpath}: {result.stderr[:300]}")
            continue

        try:
            raw = json.loads(result.stdout)
        except json.JSONDecodeError:
            print(f"[trivy] Failed to parse JSON for {fpath}")
            continue

        # Trivy v0.50+ uses "Results" at top level
        for target in raw.get("Results", []):
            for vuln in target.get("Vulnerabilities") or []:
                # Get the first CWE if available
                cwe_list = vuln.get("CweIDs", [])
                cwe = cwe_list[0] if cwe_list else None

                # Map CWE → OWASP, fallback to A06 (Vulnerable Components)
                owasp = None
                if cwe:
                    owasp = OWASP_MAP.get(cwe, "A06")
                else:
                    owasp = "A06"

                severity_str = vuln.get("Severity", "UNKNOWN").upper()

                findings.append(NormalizedFinding(
                    tool="trivy",
                    rule_id=vuln.get("VulnerabilityID", "unknown"),
                    title=vuln.get("Title") or vuln.get("VulnerabilityID", "Unknown"),
                    description=(vuln.get("Description") or "")[:400],
                    severity=SEVERITY_MAP.get(severity_str, Severity.INFO),
                    file_path=fpath,
                    owasp_category=owasp,
                    cwe=cwe,
                    evidence=(
                        f"{vuln.get('PkgName', '')} {vuln.get('InstalledVersion', '')} "
                        f"→ fix: {vuln.get('FixedVersion', 'no fix available')}"
                    ),
                ))

    print(f"[trivy] {len(findings)} findings")
    return findings