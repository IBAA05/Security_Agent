# 🛡️ ARGUS Security Agent (v1.0.1)

**Argus** is an advanced AI-native security specialist agent designed to perform multi-tool semantic vulnerability analysis. It goes beyond simple regex matches by using **DeepSeek LLM reasoning** to validate findings, eliminate false positives, and identify complex attack chains.

---

## 📑 Table of Contents
1.  [Overview](#-overview)
2.  [Features](#-features)
3.  [Installation](#-installation)
    -   [Prerequisites](#prerequisites)
    -   [Step-by-Step Setup](#step-by-step-setup)
4.  [Scanning Modes (PR vs. Nightly)](#-scanning-modes-pr-vs-nightly)
5.  [Data Formats](#-data-formats)
    -   [YAML Input Format](#yaml-input-format)
    -   [Tool Result Format](#tool-result-format)
    -   [Final JSON Report](#final-json-report)
6.  [AI & Memory Storage](#-ai--memory-storage)

---

## 🌎 Overview
The **Argus Security Agent** acts as a specialist in an **Agent-to-Agent (A2A)** ecosystem. It receives requests from an Orchestrator containing new code changes, relevant symbols, and the context of the blast radius.

Instead of just reporting raw tool output, Argus coordinates multiple security engines (Semgrep, Gitleaks, Trivy, ZAP), scores their findings against a **historical memory**, and then uses **AI Reflexion loops** to provide high-quality, actionable remediation advice.

---

## ✨ Features
*   🔍 **Semantic Analysis:** Uses LLM to read the *code surrounding* a finding to verify its validity.
*   📜 **Policy Enforcement:** Automatically checks findings against custom company security policies.
*   🧠 **Historical Memory:** Remembers recurring findings and human verdicts to reduce noise in future scans.
*   🔄 **A2A Support:** Fully integrated with the A2A SDK for autonomous task execution.
*   🛡️ **Multi-Tool Orchestration:** Unified management of SAST, SCA, Secrets, and DAST.

---

## ⚙️ Installation

### Prerequisites
Before installing the agent, ensure your system meets the requirements:
*   **OS:** Ubuntu 22.04+ (Preferred) or macOS.
*   **Python:** 3.11+ (Side-by-side install recommended for Ubuntu).
*   **Tools (Required in PATH):**
    *   **Semgrep:** `pip install semgrep`
    *   **Gitleaks:** [Installation Guide](https://github.com/gitleaks/gitleaks)
    *   **Trivy:** [Installation Guide](https://github.com/aquasecurity/trivy)
    *   **ZAP (for Staging):** [Installation Guide](https://www.zaproxy.org/)

### Step-by-Step Setup
```bash
# 1. Clone the repository
git clone https://github.com/IBAA05/Security_Agent.git
cd Security_Agent

# 2. Setup Virtual Environment (Safe for Ubuntu 3.12+)
python3.12 -m venv venv
source venv/bin/activate

# 3. Install Python Dependencies
pip install -r requirements.txt

# 4. Configure Environment
cp .env.example .env
# Edit .env and add your DEEPSEEK_API_KEY and ZAP_HOST
```

---

## 🚀 Scanning Modes (PR vs. Nightly)

Argus adjusts its intensity based on the **environment** flag:

| Mode | Environment Flag | Tools Used | Speed | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **PR Scan** | `pr` | Semgrep, Gitleaks, Trivy | FAST | Block vulnerable code before merge. |
| **Nightly/Staging**| `staging` | Above + **OWASP ZAP** | SLOW | Detect live runtime flaws (DAST) on deployment. |

---

## 📊 Data Formats

### A2A Protocol Input Format (JSON)
Argus follows the **A2A/1.0** formal communication protocol. The Orchestrator sends a rich context message including the knowledge graph and active problem set:

```json
{
  "protocol": "A2A/1.0",
  "metadata": {
    "message_id": "msg_987654321",
    "correlation_id": "job_ref_argus_001",
    "timestamp": "2026-02-24T14:30:00Z",
    "sender": "argus-librarian-service",
    "version": "1.2.0"
  },
  "routing_instructions": {
    "priority": "HIGH",
    "target_specialist": "Security_Reviewer",
    "ttl_seconds": 3600
  },
  "payload": {
    "intent": "REFACTOR_AUTH_PIPELINE",
    "knowledge_graph": {
      "nodes": [
        {
          "id": "A",
          "file": "auth_service.py",
          "role": "PRIMARY_SOURCE",
          "symbols_changed": ["verify_jwt"],
          "logic_delta": "Changed algorithm from HS256 to RS256."
        },
        {
          "id": "B",
          "file": "config_loader.py",
          "role": "DEPENDENCY",
          "impact": "Now requires public_key path in environment variables.",
          "status": "AFFECTED_BUT_NOT_MODIFIED"
        }
      ]
    },
    "dehydrated_content": {
      "high_signal_code": [
        {
          "file": "auth_service.py",
          "snippet": "def verify_jwt(token):\n    # logic changes here..."
        }
      ],
      "policy_constraints": [
        "Security Standard v4: All RSA keys must be 4096-bit."
      ]
    },
    "active_problem_set": [
      {
        "type": "LOGIC_INCONSISTENCY",
        "location": "config_loader.py:45",
        "problem": "Loader expects HMAC secret; new logic expects RSA Public Key.",
        "remediation_hint": "Update ConfigLoader to support .pem file loading."
      }
    ]
  }
}
```

### Tool Result Format (Normalized Bundle)
Before sending data to the LLM, Argus aggregates and normalizes findings from all active tools into a single bundle. Every tool (SAST, Secrets, SCA, DAST) must output this schema:

```json
[
  {
    "tool": "gitleaks",
    "rule_id": "generic-api-key",
    "title": "Hardcoded secret: Generic API Key",
    "severity": "HIGH",
    "file_path": "auth_service.py",
    "line_start": 12,
    "evidence": "Match at line 12 — secret redacted",
    "owasp_category": "A07",
    "cwe": "CWE-798"
  },
  {
    "tool": "semgrep",
    "rule_id": "python.jwt.security.audit.jwt-decode-without-verify",
    "title": "JWT Decode without Verification",
    "severity": "HIGH",
    "file_path": "auth_service.py",
    "line_start": 35,
    "evidence": "jwt.decode(token, options={'verify_signature': False})",
    "owasp_category": "A07",
    "cwe": "CWE-287"
  },
  {
    "tool": "trivy",
    "rule_id": "CVE-2023-36478",
    "title": "Jetty: HTTP/2 DoS vulnerability",
    "severity": "MEDIUM",
    "file_path": "requirements.txt",
    "evidence": "jetty-server 9.4.51.v20230217 → fix: 9.4.52.v20230823",
    "owasp_category": "A06",
    "cwe": "CWE-400"
  },
  {
    "tool": "zap",
    "rule_id": "zap-40012",
    "title": "Reflected Cross-Site Scripting (XSS)",
    "severity": "HIGH",
    "file_path": null,
    "evidence": "<script>alert(1)</script>",
    "owasp_category": "A03",
    "cwe": "CWE-79",
    "description": "ZAP found an XSS vulnerability on the live staging endpoint."
  }
]
```

### Final JSON Report
The final output sent back to the Orchestrator/User:
```json
{
  "scan_id": "scan-99",
  "summary": "Detected 1 critical SQL injection. Remediation required.",
  "overall_risk": "CRITICAL",
  "findings": [
    {
      "rule_id": "semgrep-sqli",
      "severity": "CRITICAL",
      "base_confidence": 0.75,
      "final_confidence": 0.95,
      "is_false_positive": false,
      "reasoning": "Confirmed: user-controlled input flows directly into sqlite3 execute call at line 42.",
      "remediation": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))"
    }
  ],
  "confirmed_active_problems": ["LOGIC_INCONSISTENCY_42"]
}
```

---

## 🧠 AI & Memory Storage
Argus maintains a **`memory/history.json`** file.
1.  **File Context:** Tracks which files attract the most vulnerabilities.
2.  **Human Verdicts:** If a user marks a finding as a FALSE POSITIVE in the dashboard, Argus learns and suppresses that finding in the next scan.
3.  **Reflexion:** High-priority scans trigger a second LLM pass where the agent critiques its own draft for improved accuracy.

---

## 🤝 Human-in-the-Loop (HITL) & Expert Feedback
Argus is designed to learn from security experts. It uses two primary feedback loops:

### 1. The Expert Pattern Injection loop
Experts can add high-signal rules and custom security requirements to **`expert_patterns.txt`**.
*   This file is **dynamically injected** into the LLM's **System Prompt**.
*   The LLM uses these expert instructions to prioritize specific vulnerabilities (e.g., "Always flag RSA keys smaller than 4096-bit").

### 2. Historical Verdict Influence
When a security expert reviews a scan result:
*   **Confirmed Findings:** Boost the `base_confidence` of similar future findings in that same file by **+25%**.
*   **False Positives:** Create a permanent penalty (**-40%**) for that specific rule/file combination.
*   The LLM is explicitly informed of these historical human verdicts in the **User Message**, allowing it to say: *"I am marking this as a False Positive because a human expert previously dismissed this specific rule in this file."*

---

