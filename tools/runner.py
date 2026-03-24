# tools/runner.py
import os
from schemas import OrchestratorInput, NormalizedFinding
from tools import semgrep, gitleaks, trivy, zap

# Which extensions go to Semgrep (source code analysis)
CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".php", ".rb"}

# Which filenames go to Trivy (dependency and IaC analysis)
SCA_FILENAMES = {
    "requirements.txt", "requirements-dev.txt", "Pipfile", "Pipfile.lock",
    "package.json", "package-lock.json", "yarn.lock",
    "go.mod", "go.sum",
    "pom.xml", "build.gradle",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".terraform", "main.tf",
}


def route_and_run(inp: OrchestratorInput) -> list[NormalizedFinding]:
    """
    Decide which files go to which tools based on file type,
    then run the appropriate tools.

    PR environment:  Semgrep + Gitleaks + Trivy  (fast, static)
    Staging:         all of the above + ZAP       (adds live DAST)
    """
    # Separate files by type
    existing_files = [f for f in inp.files if os.path.exists(f)]

    code_files = [
        f for f in existing_files
        if os.path.splitext(f)[1].lower() in CODE_EXTENSIONS
    ]
    sca_files = [
        f for f in existing_files
        if os.path.basename(f) in SCA_FILENAMES
    ]
    # Gitleaks scans everything — secrets can be in any file type
    all_files = existing_files

    print(f"[router] {len(code_files)} code files → Semgrep")
    print(f"[router] {len(all_files)} files → Gitleaks")
    print(f"[router] {len(sca_files)} SCA/IaC files → Trivy")

    findings: list[NormalizedFinding] = []

    # Always run static tools (both PR and staging)
    findings += semgrep.run(code_files)
    findings += gitleaks.run(all_files)
    findings += trivy.run(sca_files)

    # DAST only in staging (live endpoint required)
    if inp.environment == "staging" and inp.live_endpoint:
        print(f"[router] Staging environment → ZAP against {inp.live_endpoint}")
        findings += zap.run(inp.live_endpoint)
    else:
        print(f"[router] PR environment → ZAP skipped")

    print(f"[router] Total raw findings: {len(findings)}")
    return findings