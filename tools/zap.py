# tools/zap.py
import requests
import time
import os
from schemas import NormalizedFinding, Severity

ZAP_HOST = os.getenv("ZAP_HOST", "http://localhost:8080")
ZAP_KEY  = os.getenv("ZAP_API_KEY", "")

PLUGIN_OWASP_MAP: dict[str, tuple[str, str]] = {
    "40012": ("A03", "CWE-79"),    # Reflected XSS
    "40014": ("A03", "CWE-89"),    # SQL Injection
    "40018": ("A03", "CWE-78"),    # Command Injection
    "10202": ("A01", "CWE-285"),   # Broken Access Control
    "10096": ("A10", "CWE-918"),   # SSRF
    "10105": ("A07", "CWE-287"),   # Weak Authentication
}

RISK_MAP: dict[str, Severity] = {
    "High":          Severity.HIGH,
    "Medium":        Severity.MEDIUM,
    "Low":           Severity.LOW,
    "Informational": Severity.INFO,
}


def run(target_url: str) -> list[NormalizedFinding]:
    """
    Runs an OWASP ZAP active scan against a live endpoint.
    Only called when environment == 'staging'.
    Returns empty list and logs a warning if ZAP is not reachable.
    """
    if not _zap_is_reachable():
        print("[zap] WARNING: ZAP daemon not reachable — skipping DAST scan")
        print(f"[zap] Start ZAP with: zap.sh -daemon -port 8080 -config api.key={ZAP_KEY}")
        return []

    print(f"[zap] Starting active scan against {target_url}")

    # 1. Launch active scan
    resp = requests.get(
        f"{ZAP_HOST}/JSON/ascan/action/scan/",
        params={"url": target_url, "apikey": ZAP_KEY},
        timeout=10
    )
    scan_id = resp.json().get("scan")

    # 2. Poll until complete (ZAP reports 0–100)
    while True:
        status_resp = requests.get(
            f"{ZAP_HOST}/JSON/ascan/view/status/",
            params={"scanId": scan_id, "apikey": ZAP_KEY},
            timeout=10
        )
        progress = int(status_resp.json().get("status", 0))
        print(f"[zap] Scan progress: {progress}%")
        if progress >= 100:
            break
        time.sleep(5)

    # 3. Retrieve alerts
    alerts_resp = requests.get(
        f"{ZAP_HOST}/JSON/core/view/alerts/",
        params={"apikey": ZAP_KEY},
        timeout=10
    )
    alerts = alerts_resp.json().get("alerts", [])

    findings = []
    for a in alerts:
        plugin_id = str(a.get("pluginId", ""))
        owasp, cwe = PLUGIN_OWASP_MAP.get(plugin_id, (None, None))
        findings.append(NormalizedFinding(
            tool="zap",
            rule_id=f"zap-{plugin_id}",
            title=a.get("name", "Unknown"),
            description=a.get("description", ""),
            severity=RISK_MAP.get(a.get("risk", "Low"), Severity.LOW),
            file_path=None,          # ZAP has no file — it's a URL-based scan
            owasp_category=owasp,
            cwe=cwe,
            evidence=a.get("evidence", "")[:300],
        ))

    print(f"[zap] {len(findings)} findings")
    return findings


def _zap_is_reachable() -> bool:
    try:
        requests.get(f"{ZAP_HOST}/JSON/core/view/version/",
                     params={"apikey": ZAP_KEY}, timeout=3)
        return True
    except Exception:
        return False