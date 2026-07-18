#!/usr/bin/env python3
"""R72 fix-semantic-reach-spreader check (pre-submit gate).

r36-rebuttal: registered lane mimo-harness-build-2026-05-27.

For any draft that contains an L30 missing-guard / L30-style claim
(asymmetric path pair, missing modifier, missing access-control on
sibling call site), require the draft to cite output from
tools/fix-semantic-reach-spreader.py for the named guard.

Trigger phrases (case-insensitive):
  - "missing guard" / "missing modifier" / "missing access control"
  - "asymmetric path" / "asymmetric pair"
  - "L30" / "rule 30"
  - "Enumerated Call Sites" (the R30/L30 enumeration section heading)

Required citation (any one):
  - `tools/fix-semantic-reach-spreader.py` referenced verbatim
  - `audit/corpus_tags/derived/fix_reach_audit/...` path cited
  - `auditooor.fix_reach_audit.v1` schema id cited

Override: `<!-- r72-rebuttal: <reason up to 200 chars> -->`

Exit code 0 = pass, 1 = fail, 2 = error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA_ID = "auditooor.r72_fix_reach_check.v1"
RULE_ID = "R72-FIX-REACH-SPREADER-CHECK"

TRIGGER_RE = re.compile(
    r"(missing\s+guard|missing\s+modifier|missing\s+access[- ]control|"
    r"asymmetric\s+(path|pair)|\bL30\b|\brule\s+30\b|"
    r"Enumerated\s+Call\s+Sites)",
    re.IGNORECASE,
)
CITATION_RE = re.compile(
    r"(tools/fix-semantic-reach-spreader\.py|"
    r"audit/corpus_tags/derived/fix_reach_audit/|"
    r"auditooor\.fix_reach_audit\.v1)",
    re.IGNORECASE,
)
REBUTTAL_RE = re.compile(
    r"<!--\s*r72-rebuttal:\s*(.{1,200}?)\s*-->",
    re.IGNORECASE | re.DOTALL,
)


def check_draft(draft_path: Path) -> dict:
    """Run the R72 gate against a single draft."""
    try:
        text = draft_path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return {
            "schema_version": SCHEMA_ID,
            "rule_id": RULE_ID,
            "draft": str(draft_path),
            "verdict": "error",
            "reason": f"draft not found: {draft_path}",
        }

    rebuttal_match = REBUTTAL_RE.search(text)
    rebuttal_reason = rebuttal_match.group(1).strip() if rebuttal_match else None
    if rebuttal_reason:
        return {
            "schema_version": SCHEMA_ID,
            "rule_id": RULE_ID,
            "draft": str(draft_path),
            "verdict": "ok-rebuttal",
            "reason": f"r72-rebuttal accepted: {rebuttal_reason[:200]}",
            "rebuttal": rebuttal_reason[:200],
        }

    trigger_matches = TRIGGER_RE.findall(text)
    if not trigger_matches:
        return {
            "schema_version": SCHEMA_ID,
            "rule_id": RULE_ID,
            "draft": str(draft_path),
            "verdict": "pass-not-applicable",
            "reason": "No L30 missing-guard trigger phrases in draft.",
        }

    citation_matches = CITATION_RE.findall(text)
    if citation_matches:
        return {
            "schema_version": SCHEMA_ID,
            "rule_id": RULE_ID,
            "draft": str(draft_path),
            "verdict": "pass-cited",
            "reason": (
                f"Draft contains {len(trigger_matches)} L30 trigger(s) and "
                f"{len(citation_matches)} fix-semantic-reach-spreader citation(s)."
            ),
            "evidence": {
                "trigger_count": len(trigger_matches),
                "citation_count": len(citation_matches),
            },
        }

    return {
        "schema_version": SCHEMA_ID,
        "rule_id": RULE_ID,
        "draft": str(draft_path),
        "verdict": "fail-missing-citation",
        "reason": (
            f"Draft contains {len(trigger_matches)} L30 missing-guard trigger(s) "
            "but does not cite tools/fix-semantic-reach-spreader.py output. "
            "Either run the spreader and cite its output, or add "
            "<!-- r72-rebuttal: <reason> --> with a bounded explanation."
        ),
        "evidence": {"trigger_count": len(trigger_matches), "citation_count": 0},
    }


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="R72 fix-semantic-reach-spreader gate")
    p.add_argument("draft", help="Path to draft.md")
    p.add_argument("--workspace", help="Workspace root (unused; future use)")
    p.add_argument("--strict", action="store_true",
                   help="Treat pass-not-applicable as ok (always 0).")
    p.add_argument("--json", action="store_true", help="Output strict JSON to stdout.")
    args = p.parse_args(argv)

    result = check_draft(Path(args.draft))
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        verdict = result.get("verdict", "?")
        reason = result.get("reason", "")
        print(f"[R72] {verdict}: {reason}")

    v = result.get("verdict", "")
    if v in ("pass-not-applicable", "pass-cited", "ok-rebuttal"):
        return 0
    if v == "error":
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
