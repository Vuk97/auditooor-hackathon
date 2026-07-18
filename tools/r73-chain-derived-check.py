#!/usr/bin/env python3
"""R73 chain-derived-finding check (pre-submit gate).

r36-rebuttal: registered lane mimo-harness-build-2026-05-27.

For any draft that contains a chain-derived / compositional-attack claim,
require the draft to cite output from tools/chain-synthesizer-hunt-time.py
(or a vault_hackerman_chain_candidates record id) showing the composition
proof sketch.

Trigger phrases:
  - "chain", "chained attack", "compound attack", "multi-step"
  - "composition", "compositional"
  - "chain_with", "chain_candidate"
  - section heading "Attack Chain" / "Exploit Chain" / "Composition Path"

Required citation (any one):
  - `tools/chain-synthesizer-hunt-time.py` referenced
  - `audit/corpus_tags/derived/chain_candidates*` path cited
  - `vault_hackerman_chain_candidates` or `vault_chained_attack_plan_context`
  - schema id `auditooor.chain_synthesized.v1`

Override: `<!-- r73-rebuttal: <reason up to 200 chars> -->`

Exit code 0 = pass, 1 = fail, 2 = error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA_ID = "auditooor.r73_chain_derived_check.v1"
RULE_ID = "R73-CHAIN-DERIVED-CHECK"

TRIGGER_RE = re.compile(
    r"(\bchained?\s+attack\b|\bcompound\s+attack\b|\bmulti[- ]step\b|"
    r"\bcomposition(al)?\b|chain_with|chain_candidate|"
    r"#+\s*(Attack|Exploit)\s+Chain|#+\s*Composition\s+Path)",
    re.IGNORECASE,
)
CITATION_RE = re.compile(
    r"(tools/chain-synthesizer-hunt-time\.py|"
    r"audit/corpus_tags/derived/chain_candidates|"
    r"vault_hackerman_chain_candidates|"
    r"vault_chained_attack_plan_context|"
    r"auditooor\.chain_synthesized\.v1)",
    re.IGNORECASE,
)
REBUTTAL_RE = re.compile(
    r"<!--\s*r73-rebuttal:\s*(.{1,200}?)\s*-->",
    re.IGNORECASE | re.DOTALL,
)


def check_draft(draft_path: Path) -> dict:
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
            "reason": f"r73-rebuttal accepted: {reason[:200]}",
            "rebuttal": reason[:200],
        }

    triggers = TRIGGER_RE.findall(text)
    if not triggers:
        return {
            "schema_version": SCHEMA_ID, "rule_id": RULE_ID,
            "draft": str(draft_path), "verdict": "pass-not-chain-derived",
            "reason": "No chain-derived trigger phrases in draft.",
        }

    cites = CITATION_RE.findall(text)
    if cites:
        return {
            "schema_version": SCHEMA_ID, "rule_id": RULE_ID,
            "draft": str(draft_path), "verdict": "pass-cited",
            "reason": (
                f"Draft contains {len(triggers)} chain-derived trigger(s) "
                f"and {len(cites)} chain-synthesizer citation(s)."
            ),
            "evidence": {"trigger_count": len(triggers),
                         "citation_count": len(cites)},
        }

    return {
        "schema_version": SCHEMA_ID, "rule_id": RULE_ID,
        "draft": str(draft_path), "verdict": "fail-missing-citation",
        "reason": (
            f"Draft contains {len(triggers)} chain-derived trigger(s) "
            "but does not cite tools/chain-synthesizer-hunt-time.py "
            "composition-proof-sketch. Run the synthesizer and cite its "
            "output, or add <!-- r73-rebuttal: <reason> -->."
        ),
        "evidence": {"trigger_count": len(triggers), "citation_count": 0},
    }


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="R73 chain-derived gate")
    p.add_argument("draft")
    p.add_argument("--workspace")
    p.add_argument("--strict", action="store_true")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    r = check_draft(Path(args.draft))
    if args.json:
        print(json.dumps(r, indent=2))
    else:
        print(f"[R73] {r.get('verdict','?')}: {r.get('reason','')}")
    v = r.get("verdict", "")
    if v in ("pass-not-chain-derived", "pass-cited", "ok-rebuttal"):
        return 0
    if v == "error":
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
