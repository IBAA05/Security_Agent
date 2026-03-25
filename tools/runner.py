# tools/runner.py
import os
import tempfile
from schemas import A2AMessage, NormalizedFinding
from tools import semgrep, gitleaks, trivy, zap

CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx",
                   ".java", ".go", ".php", ".rb", ".cs"}

SCA_FILENAMES = {
    "requirements.txt", "requirements-dev.txt",
    "Pipfile", "Pipfile.lock",
    "package.json", "package-lock.json", "yarn.lock",
    "go.mod", "go.sum",
    "pom.xml", "build.gradle",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
}


def route_and_run(msg: A2AMessage) -> tuple[list[NormalizedFinding], dict[str, str]]:
    """
    Extracts code snippets from the A2A message, writes them to
    temp files, runs the appropriate tools, then cleans up.

    Returns:
        findings: all normalized findings from all tools
        temp_map: {original_filename: temp_path} for cleanup tracking
    """
    snippets = msg.get_file_snippets()

    if not snippets:
        print("[router] No code snippets provided — nothing to scan")
        return [], {}

    # Write snippets to temp files so CLI tools can scan them
    temp_map = _write_temp_files(snippets)

    print(f"[router] Scanning {len(temp_map)} file(s) from A2A payload")

    try:
        findings = _run_tools(msg, temp_map)
    finally:
        # Always clean up temp files even if tools crash
        _cleanup(temp_map)

    return findings, temp_map


def _write_temp_files(snippets: dict[str, str]) -> dict[str, str]:
    """
    Write each snippet to a real temp file on disk.
    Preserve the original extension so Semgrep applies
    the correct language rules.

    Returns {original_name: temp_path}
    """
    temp_map = {}
    for original_name, content in snippets.items():
        ext = os.path.splitext(original_name)[1] or ".py"
        tmp = tempfile.NamedTemporaryFile(
            suffix=ext,
            delete=False,
            mode="w",
            encoding="utf-8",
            prefix=f"argus_{os.path.basename(original_name)}_"
        )
        tmp.write(content)
        tmp.close()
        temp_map[original_name] = tmp.name
        print(f"[router] {original_name} → {tmp.name}")

    return temp_map


def _run_tools(
    msg: A2AMessage,
    temp_map: dict[str, str]
) -> list[NormalizedFinding]:
    """
    Route temp files to the correct tools based on file type.
    ZAP only runs in staging environment.
    """
    findings: list[NormalizedFinding] = []

    temp_paths = list(temp_map.values())
    original_names = list(temp_map.keys())

    # Semgrep — code files only
    code_temps = [
        temp_map[name] for name in original_names
        if os.path.splitext(name)[1].lower() in CODE_EXTENSIONS
    ]
    if code_temps:
        print(f"[router] {len(code_temps)} code file(s) → Semgrep")
        findings += semgrep.run(code_temps)

    # Gitleaks — all files (secrets can be anywhere)
    print(f"[router] {len(temp_paths)} file(s) → Gitleaks")
    findings += gitleaks.run(temp_paths)

    # Trivy — dependency/IaC files only
    sca_temps = [
        temp_map[name] for name in original_names
        if os.path.basename(name) in SCA_FILENAMES
    ]
    if sca_temps:
        print(f"[router] {len(sca_temps)} SCA/IaC file(s) → Trivy")
        findings += trivy.run(sca_temps)

    # ZAP — staging only, requires live endpoint
    if msg.environment == "staging" and msg.live_endpoint:
        print(f"[router] Staging → ZAP against {msg.live_endpoint}")
        findings += zap.run(msg.live_endpoint)
    else:
        print("[router] PR environment → ZAP skipped")

    # Remap temp file paths back to original names in all findings
    # so the report shows auth_service.py, not /tmp/argus_auth_service_xyz.py
    path_remap = {v: k for k, v in temp_map.items()}
    for f in findings:
        if f.file_path and f.file_path in path_remap:
            f.file_path = path_remap[f.file_path]

    print(f"[router] Total raw findings: {len(findings)}")
    return findings


def _cleanup(temp_map: dict[str, str]) -> None:
    for temp_path in temp_map.values():
        try:
            os.unlink(temp_path)
        except Exception:
            pass