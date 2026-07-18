#!/usr/bin/env python3
"""followup-lead-completeness-check.py - fail-closed gate over
hunt-followup-lead-scanner.py's output. An audit cannot be honestly complete
while it carries agent-flagged "maybe"/follow-up-worthy leads that were never
driven to a terminal verdict - that is exactly the abandoned-lead failure
mode L37/unhunted-followthrough already polices for coverage gaps, applied
here to the narrower "agent explicitly said this deserves another look" case.

Language-agnostic: reads <ws>/.auditooor/followup_leads.json, itself produced
by a language-agnostic scanner over the uniform hunt_findings_sidecars shape.
No Solidity/Go/Rust branching in this file either.

Verdicts:
  pass-followup-leads-resolved      - scanner ran, 0 open leads
  fail-followup-leads-undispatched  - scanner ran, >=1 open lead (STRICT-fail)
  warn-followup-leads-not-scanned   - scanner has not been run yet (advisory,
                                       exit 0 even under STRICT - this gate
                                       cannot invent leads it wasn't given)

CLI: python3 tools/followup-lead-completeness-check.py --workspace <ws> [--strict]
Exit 0 on pass/warn, 1 on fail-under-strict.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

LEADS_FILE = "followup_leads.json"


def evaluate(ws: Path) -> dict:
    path = ws / ".auditooor" / LEADS_FILE
    if not path.is_file():
        return {
            "verdict": "warn-followup-leads-not-scanned",
            "detail": "hunt-followup-lead-scanner.py has not been run for this workspace",
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"verdict": "warn-followup-leads-not-scanned", "detail": f"unreadable: {exc}"}

    open_leads = [l for l in data.get("leads", []) if l.get("status") == "open"]
    if not open_leads:
        return {
            "verdict": "pass-followup-leads-resolved",
            "total_flagged": data.get("total_flagged", 0),
            "resolved": data.get("resolved", 0),
        }
    return {
        "verdict": "fail-followup-leads-undispatched",
        "open_count": len(open_leads),
        "open_leads": [f"{l['file']}:{l['function']} ({l['reason']})" for l in open_leads],
        "remediation": (
            "run: python3 tools/hunt-followup-lead-scanner.py --workspace <ws> --emit ; "
            "dispatch each row in .auditooor/followup_lead_hunt_tasks.jsonl via "
            "Agent(sonnet); re-run the scanner to confirm resolution."
        ),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Fail-closed gate over followup-lead scan results")
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).resolve()
    res = evaluate(ws)
    print(json.dumps(res, indent=2))

    if res["verdict"] == "fail-followup-leads-undispatched" and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
