#!/usr/bin/env python3
# <!-- r36-rebuttal: lane-RULE-INVENTORY-PARITY registered in .auditooor/agent_pathspec.json -->
"""r-rule-inventory-parity-check.py - assert the rule-inventory tracks every wired gate.

Background
----------
``reference/r_rules_inventory.jsonl`` is the doc-of-record a consumer reads to
answer "what does this toolkit ENFORCE?". The 2026-05-29 self-audit
(``docs/CAPABILITY_VS_ENFORCEMENT_2026-05-29.md`` DELTA-1) found it was missing
~20 rule-family gates that ``tools/pre-submit-check.sh`` actually wires as hard
checks (R59-R76, several GAP rules). A truncated inventory silently
under-reports the enforcement surface by ~33%.

This check closes that drift mechanically: it parses every
``# Check #N: <RULEID>-...`` header from ``pre-submit-check.sh``, keeps the
R/L/GAP rule-family ones, and asserts each has a matching ``rule_id`` row in
``r_rules_inventory.jsonl``. It is deterministic, stdlib-only, offline-safe,
and NEVER modifies anything - it reads the two artifacts and compares.

Verdict vocabulary
------------------
- ``pass-inventory-complete``  every wired rule-family check has an inventory row.
- ``fail-inventory-missing-rows``  one or more wired checks have no inventory row.
- ``error``  could not read an input.

Usage
-----
    python3 tools/r-rule-inventory-parity-check.py [--json]
    python3 tools/r-rule-inventory-parity-check.py \
        --pre-submit tools/pre-submit-check.sh \
        --inventory reference/r_rules_inventory.jsonl [--json]

Exit codes: 0 pass, 1 fail (missing rows), 2 error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

_HDR = re.compile(r"#\s*Check\s*#(\d+):\s*([A-Za-z0-9_\-]+)")
_RULE_FAMILY = re.compile(r"^(R|L|GAP)[0-9]")


def _rule_id_from_check_name(check_name: str) -> str | None:
    """Map a check-name token (e.g. 'R76-HALLUCINATION-GUARD',
    'GAP37B-SALVAGE-NEGATION-VERDICT', 'R18/R19/L32') to its primary rule_id."""
    head = check_name.split("/")[0]
    m = re.match(r"^((?:R|L|GAP)[0-9A-Z]*?[0-9][0-9A-Z]*)", head)
    if not m:
        return None
    rid = m.group(1)
    return rid if _RULE_FAMILY.match(rid) else None


def parse_wired_rules(pre_submit: Path) -> dict[str, str]:
    """Return {rule_id: 'N'} for every wired rule-family Check header."""
    wired: dict[str, str] = {}
    text = pre_submit.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        m = _HDR.search(line)
        if not m:
            continue
        num, check_name = m.group(1), m.group(2)
        rid = _rule_id_from_check_name(check_name)
        if rid:
            wired.setdefault(rid, num)
    return wired


def parse_inventory_ids(inventory: Path) -> set[str]:
    ids: set[str] = set()
    for raw in inventory.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError:
            continue
        rid = row.get("rule_id")
        if isinstance(rid, str) and rid:
            ids.add(rid)
    return ids


def evaluate(pre_submit: Path, inventory: Path) -> dict:
    if not pre_submit.is_file():
        return {"verdict": "error", "reason": f"pre-submit not found: {pre_submit}"}
    if not inventory.is_file():
        return {"verdict": "error", "reason": f"inventory not found: {inventory}"}

    wired = parse_wired_rules(pre_submit)
    inv = parse_inventory_ids(inventory)
    missing = sorted(
        (rid for rid in wired if rid not in inv),
        key=lambda r: (r[0], int(re.sub(r"\D", "", r) or "0")),
    )
    result = {
        "schema": "auditooor.r_rule_inventory_parity.v1",
        "wired_rule_family_checks": len(wired),
        "inventory_rows": len(inv),
        "missing_from_inventory": [
            {"rule_id": rid, "check_number": wired[rid]} for rid in missing
        ],
    }
    if missing:
        result["verdict"] = "fail-inventory-missing-rows"
    else:
        result["verdict"] = "pass-inventory-complete"
    return result


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pre-submit", default=str(root / "tools" / "pre-submit-check.sh"))
    ap.add_argument("--inventory", default=str(root / "reference" / "r_rules_inventory.jsonl"))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    res = evaluate(Path(args.pre_submit), Path(args.inventory))
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        v = res.get("verdict")
        if v == "pass-inventory-complete":
            print(
                f"[r-rule-inventory-parity] PASS: all {res['wired_rule_family_checks']} "
                f"wired rule-family checks have an inventory row ({res['inventory_rows']} rows)."
            )
        elif v == "fail-inventory-missing-rows":
            miss = ", ".join(f"{m['rule_id']}(#{m['check_number']})" for m in res["missing_from_inventory"])
            print(f"[r-rule-inventory-parity] FAIL: {len(res['missing_from_inventory'])} wired checks missing from inventory: {miss}")
        else:
            print(f"[r-rule-inventory-parity] ERROR: {res.get('reason')}", file=sys.stderr)

    if res.get("verdict") == "pass-inventory-complete":
        return 0
    if res.get("verdict") == "fail-inventory-missing-rows":
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
