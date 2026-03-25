# memory/store.py
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from schemas import LLMOutput, LLMFinding, Severity

MEMORY_PATH = Path("memory/history.json")


def _load() -> dict:
    if not MEMORY_PATH.exists():
        return {"files": {}, "findings": {}}
    with open(MEMORY_PATH, encoding="utf-8") as f:
        return json.load(f)


def _save(data: dict) -> None:
    MEMORY_PATH.parent.mkdir(exist_ok=True)
    with open(MEMORY_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def update_after_scan(result: LLMOutput, scanned_files: list[str]) -> None:
    """
    Called after every scan. Updates file-level and finding-level memory.
    This is how the agent learns over time.
    """
    data = _load()
    now = datetime.now(timezone.utc).isoformat()

    confirmed = [f for f in result.findings if not f.is_false_positive]
    false_positives = [f for f in result.findings if f.is_false_positive]

    for fpath in scanned_files:
        # ── File-level memory ──────────────────────────────────────────────
        if fpath not in data["files"]:
            data["files"][fpath] = {
                "scan_count": 0,
                "confirmed_findings_total": 0,
                "false_positive_total": 0,
                "last_scan": None,
                "last_risk_level": "CLEAN",
                "recurring_rule_ids": [],
                "priority_score": 0.0,
            }

        rec = data["files"][fpath]
        rec["scan_count"] += 1
        rec["last_scan"] = now
        rec["last_risk_level"] = result.overall_risk

        file_confirmed = [
            f for f in confirmed
            if f.file_path == fpath or not f.file_path
        ]
        file_fps = [
            f for f in false_positives
            if f.file_path == fpath or not f.file_path
        ]

        rec["confirmed_findings_total"] += len(file_confirmed)
        rec["false_positive_total"] += len(file_fps)

        # Track which rule_ids keep appearing in this file
        for f in file_confirmed:
            if f.rule_id not in rec["recurring_rule_ids"]:
                rec["recurring_rule_ids"].append(f.rule_id)

        # Priority score — how much attention this file deserves
        # Formula: weighted combination of finding history + recency + severity
        severity_weight = {
            "CRITICAL": 1.0, "HIGH": 0.8,
            "MEDIUM": 0.5, "LOW": 0.2, "CLEAN": 0.0
        }
        risk_w = severity_weight.get(result.overall_risk, 0.0)
        finding_rate = min(rec["confirmed_findings_total"] / max(rec["scan_count"], 1), 1.0)
        fp_penalty = rec["false_positive_total"] / max(rec["scan_count"], 1) * 0.3
        rec["priority_score"] = round(
            (risk_w * 0.5) + (finding_rate * 0.4) - fp_penalty, 3
        )

        # ── Finding-level memory ───────────────────────────────────────────
        for f in file_confirmed + file_fps:
            fkey = f"{fpath}:{f.rule_id}"
            if fkey not in data["findings"]:
                data["findings"][fkey] = {
                    "first_seen": now,
                    "times_seen": 0,
                    "was_false_positive_count": 0,
                    "confirmed_count": 0,
                    "confidence_history": [],
                    "human_verdict": None,
                    "added_to_patterns": False,
                }

            frec = data["findings"][fkey]
            frec["times_seen"] += 1
            frec["confidence_history"].append(f.final_confidence)

            # Keep only last 10 confidence values
            frec["confidence_history"] = frec["confidence_history"][-10:]

            if f.is_false_positive:
                frec["was_false_positive_count"] += 1
            else:
                frec["confirmed_count"] += 1

    _save(data)
    print(f"[memory] Updated history for {len(scanned_files)} files")


def get_file_context(file_paths: list[str]) -> dict:
    """
    Called BEFORE a scan. Returns memory context for the files
    being scanned so the LLM and scorer can use it.
    """
    data = _load()
    context = {}

    for fpath in file_paths:
        file_rec = data["files"].get(fpath, {})

        # Find all known findings for this file
        known_findings = {
            k.split(":", 1)[1]: v
            for k, v in data["findings"].items()
            if k.startswith(f"{fpath}:")
        }

        context[fpath] = {
            "priority_score": file_rec.get("priority_score", 0.0),
            "scan_count": file_rec.get("scan_count", 0),
            "last_risk_level": file_rec.get("last_risk_level", "UNKNOWN"),
            "recurring_rule_ids": file_rec.get("recurring_rule_ids", []),
            "known_findings": known_findings,
        }

    return context


def record_human_verdict(
        file_path: str,
        rule_id: str,
        verdict: str,  # "confirmed" or "false_positive"
        add_to_patterns: bool = False
) -> None:
    """
    Called when a human reviews a finding and makes a decision.
    This is the Level 2 HITL feedback — it directly improves future scans.
    """
    data = _load()
    fkey = f"{file_path}:{rule_id}"

    if fkey in data["findings"]:
        data["findings"][fkey]["human_verdict"] = verdict
        data["findings"][fkey]["added_to_patterns"] = add_to_patterns
        _save(data)
        print(f"[memory] Human verdict recorded: {fkey} → {verdict}")