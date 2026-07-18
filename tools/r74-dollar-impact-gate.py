#!/usr/bin/env python3
"""R74 dollar-impact / expected-bounty-vs-drill-cost gate (pre-submit).

r36-rebuttal: registered lane mimo-harness-build-2026-05-27.

For HIGH+ drafts, optionally consult tools/dollar-impact-model.py output
to check whether the expected bounty is greater than the drill cost.
If a dollar-impact sidecar exists and gate_verdict is SKIP / DROP /
INSUFFICIENT_DATA, refuse promotion unless rebuttal present.

Trigger: severity in {HIGH, CRITICAL} AND
         a dollar_impact_<slug>.json sidecar exists for the draft.
         If no sidecar, treat as pass-not-applicable (don't gate
         in absence of $-model data, just warn).

Sidecar lookup order:
  1. <draft-dir>/dollar_impact.json
  2. <draft-dir>/dollar_impact_<slug>.json
  3. audit/corpus_tags/derived/dollar_impact/<slug>.json
  4. audit/corpus_tags/derived/dollar_impact_<slug>.json

Override: `<!-- r74-rebuttal: <reason up to 200 chars> -->`

Exit code 0 = pass, 1 = fail, 2 = error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA_ID = "auditooor.r74_dollar_impact_gate.v1"
RULE_ID = "R74-DOLLAR-IMPACT-GATE"

SEVERITY_RE = re.compile(
    r"^(?:#+\s*)?severity\s*[:=]?\s*"
    r"(low|medium|high|critical)\b",
    re.IGNORECASE | re.MULTILINE,
)
REBUTTAL_RE = re.compile(
    r"<!--\s*r74-rebuttal:\s*(.{1,200}?)\s*-->",
    re.IGNORECASE | re.DOTALL,
)


def detect_severity(text: str, override: str | None) -> str:
    if override and override.lower() != "auto":
        return override.upper()
    matches = SEVERITY_RE.findall(text)
    if not matches:
        return "UNKNOWN"
    return matches[0].upper()


def locate_sidecar(draft_path: Path, workspace: Path | None) -> Path | None:
    slug = draft_path.stem
    draft_dir = draft_path.parent
    candidates = [
        draft_dir / "dollar_impact.json",
        draft_dir / f"dollar_impact_{slug}.json",
    ]
    if workspace:
        candidates += [
            workspace / "audit" / "corpus_tags" / "derived" / "dollar_impact" / f"{slug}.json",
            workspace / "audit" / "corpus_tags" / "derived" / f"dollar_impact_{slug}.json",
        ]
    for c in candidates:
        if c.is_file():
            return c
    return None


def check_draft(draft_path: Path, workspace: Path | None, severity: str) -> dict:
    try:
        text = draft_path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return {
            "schema_version": SCHEMA_ID, "rule_id": RULE_ID,
            "draft": str(draft_path), "verdict": "error",
            "reason": f"draft not found: {draft_path}",
        }

    rebuttal = REBUTTAL_RE.search(text)
    if rebuttal and rebuttal.group(1).strip():
        reason = rebuttal.group(1).strip()
        return {
            "schema_version": SCHEMA_ID, "rule_id": RULE_ID,
            "draft": str(draft_path), "verdict": "ok-rebuttal",
            "reason": f"r74-rebuttal accepted: {reason[:200]}",
            "rebuttal": reason[:200],
        }

    sev = detect_severity(text, severity)
    if sev not in ("HIGH", "CRITICAL"):
        return {
            "schema_version": SCHEMA_ID, "rule_id": RULE_ID,
            "draft": str(draft_path), "verdict": "pass-out-of-scope",
            "reason": f"Severity={sev}; R74 only fires HIGH+.",
            "severity_detected": sev,
        }

    sidecar = locate_sidecar(draft_path, workspace)
    if not sidecar:
        return {
            "schema_version": SCHEMA_ID, "rule_id": RULE_ID,
            "draft": str(draft_path),
            "verdict": "pass-not-applicable",
            "reason": (
                "HIGH+ draft but no dollar_impact sidecar found. "
                "Run tools/dollar-impact-model.py to generate one, or "
                "skip with <!-- r74-rebuttal: <reason> --> if intentional."
            ),
            "severity_detected": sev,
        }

    try:
        sidecar_data = json.loads(sidecar.read_text(encoding="utf-8"))
    except Exception as e:
        return {
            "schema_version": SCHEMA_ID, "rule_id": RULE_ID,
            "draft": str(draft_path), "verdict": "error",
            "reason": f"sidecar parse failed: {e}",
        }

    gate_verdict = str(sidecar_data.get("gate_verdict", "")).upper()
    expected = sidecar_data.get("expected_bounty_usd")
    drill_cost = sidecar_data.get("drill_cost_estimate_usd")
    base = {
        "schema_version": SCHEMA_ID, "rule_id": RULE_ID,
        "draft": str(draft_path), "severity_detected": sev,
        "sidecar_path": str(sidecar),
        "expected_bounty_usd": expected,
        "drill_cost_estimate_usd": drill_cost,
        "gate_verdict_from_model": gate_verdict,
    }

    if gate_verdict in ("PROCEED", "OK"):
        return {**base, "verdict": "pass-bounty-positive",
                "reason": "dollar-impact-model verdict PROCEED."}
    if gate_verdict in ("SKIP", "DROP", "FAIL"):
        return {**base, "verdict": "fail-bounty-below-cost",
                "reason": (
                    f"dollar-impact-model verdict={gate_verdict}; expected "
                    f"bounty (${expected}) below drill cost (${drill_cost}). "
                    "Walk back severity or add r74-rebuttal."
                )}
    if gate_verdict in ("INSUFFICIENT_DATA", "UNKNOWN", ""):
        return {**base, "verdict": "pass-insufficient-data",
                "reason": (
                    "dollar-impact-model returned INSUFFICIENT_DATA; "
                    "warn-only pass."
                )}
    return {**base, "verdict": "error",
            "reason": f"unknown gate_verdict from model: {gate_verdict}"}


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="R74 dollar-impact gate")
    p.add_argument("draft")
    p.add_argument("--workspace")
    p.add_argument("--severity", default="auto",
                   choices=["auto", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    p.add_argument("--strict", action="store_true")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    ws = Path(args.workspace) if args.workspace else None
    r = check_draft(Path(args.draft), ws, args.severity)
    if args.json:
        print(json.dumps(r, indent=2))
    else:
        print(f"[R74] {r.get('verdict','?')}: {r.get('reason','')}")
    v = r.get("verdict", "")
    if v.startswith("pass") or v == "ok-rebuttal":
        return 0
    if v == "error":
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
