#!/usr/bin/env python3
"""invariant-obligation-coverage.py - tie the audit's OWN per-function obligations
to invariant coverage: every value-moving function's derived invariant obligation
MUST be discharged by a mutation-verified invariant OR a cited disposition.

THE IDEA (operator 2026-07-07): the pipeline already DISCOVERS, per in-scope
function, what could go wrong - .auditooor/per_fn_hacker_questions.jsonl carries
1000s of per-fn questions each tagged with a question_class (sum-preserved,
unguarded-transfer/mint/burn, rubric-targeted, impact-methodology, ...) that maps
onto the 10 invariant categories. That per-item discovery is FREE (already run);
what was missing was CONVERTING it into an invariant-coverage REQUIREMENT. Instead
of a static family taxonomy (the ceiling) or an expensive fresh agent run, DERIVE
each value-moving function's required invariant categories from its own obligations
and require each be TESTED (a mutation-verified enumerated category for that asset)
or DISPOSITIONED (non-economic / cited). "All invariants held" is then falsifiable:
an untested, undispositioned obligation is an OPEN gap, not a vacuous pass.

Sources (all already produced by the audit - no new discovery):
  - .auditooor/per_fn_hacker_questions.jsonl   (per-fn question_class obligations)
  - .auditooor/value_moving_functions.json     (which functions move value)
  - .auditooor/completeness_matrix.json        (per-asset ENUMERATED invariant categories)
  - .auditooor/non_economic_dispositions.json  (cited non-economic dispositions)

question_class -> invariant category (only the CONCRETE, value-relevant classes force a
requirement; generic rubric-targeted/impact-methodology are advisory context, not a
category demand, so the gate never fabricates an unsatisfiable obligation).

ADVISORY-FIRST + NEVER-RETRO-RED: WARN by default; hard-fail only under
AUDITOOOR_INVARIANT_OBLIGATION_STRICT. Fails OPEN (WARN-pass) when any source
artifact is absent (tooling/early-audit), never on missing data.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

# Only the CONCRETE per-fn question classes that name a value-moving property map to
# a required category. rubric-targeted / impact-methodology are generic (the specific
# category depends on the rubric row), so they are advisory context, not a demand.
_QCLASS_TO_CATEGORY = {
    "sum-preserved": "conservation",
    "unguarded-transfer": "custody",
    "unguarded-transferfrom": "custody",
    "unguarded-safetransfer": "custody",
    "unguarded-safetransferfrom": "custody",
    "unguarded-mint": "conservation",
    "unguarded-burn": "conservation",
    "unguarded-low_level_call": "atomicity",
    "unguarded-call": "atomicity",
    "unguarded-delegatecall": "authorization",
}


def _load_jsonl(p: Path) -> list:
    out = []
    if not p.is_file():
        return out
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def _stem(path: str) -> str:
    return Path(str(path).split(":")[0]).name.replace(".sol", "").lower()


def _value_moving_stems(ws: Path) -> dict:
    """asset-stem -> the FLOOR invariant category its value-moving surface demands.
    A real token transfer (transfer_hit) is CUSTODY + value conservation; a pure
    ledger write (config-mapping) is conservation of the accounting it writes. This
    floor makes the obligation non-vacuous even when the per-fn question generator
    did not populate question_class (nuva/morpho: all None) - the value-moving
    classifier alone proves the asset needs a conservation invariant tested."""
    out: dict[str, set] = {}
    p = ws / ".auditooor" / "value_moving_functions.json"
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return out
    for f in (d.get("functions") or []):
        stem = _stem(f.get("file", ""))
        if not stem:
            continue
        if f.get("transfer_hit"):
            out.setdefault(stem, set()).update({"conservation", "custody"})
        elif f.get("ledger_write_hit"):
            out.setdefault(stem, set()).add("conservation")
    return out


def _enumerated_categories_by_asset(ws: Path) -> dict:
    """asset-stem -> set of ENUMERATED (mutation-verified) invariant categories,
    from the completeness matrix's per-asset invariant_enumeration."""
    out: dict[str, set] = {}
    p = ws / ".auditooor" / "completeness_matrix.json"
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return out
    rows = d.get("asset_rows") or d.get("assets") or d.get("invariant_rows") or []
    for r in rows:
        stem = _stem(str(r.get("asset_id") or r.get("asset") or ""))
        inv = r.get("invariant_enumeration") or {}
        cats = {c for c, v in inv.items()
                if isinstance(v, dict) and v.get("status") in ("enumerated", "enumerated-comprehension-only")}
        if stem:
            out.setdefault(stem, set()).update(cats)
    return out


def _dispositioned_stems(ws: Path) -> set:
    out = set()
    p = ws / ".auditooor" / "non_economic_dispositions.json"
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return out
    for r in (d.get("dispositions") or []):
        cp = r.get("cut_path") or r.get("repo") or ""
        out.add(_stem(cp))
    return out


def check(ws: Path) -> dict:
    ws = ws.expanduser().resolve()
    vm = _value_moving_stems(ws)  # asset-stem -> floor categories
    if not vm:
        return {"verdict": "pass-no-obligations", "strict": False,
                "reason": "no value-moving functions (source absent / no value-moving surface) - WARN-pass",
                "obligations": 0, "covered": 0, "open": []}
    questions = _load_jsonl(ws / ".auditooor" / "per_fn_hacker_questions.jsonl")
    enum = _enumerated_categories_by_asset(ws)
    disp = _dispositioned_stems(ws)

    # per value-moving asset-stem: REQUIRED categories = the value-moving FLOOR
    # (conservation/custody from the classifier - non-vacuous on every ws even when
    # question_class is unpopulated) ENRICHED with the per-fn question_class
    # obligations the hunt produced (sum-preserved/unguarded-* -> concrete category).
    required: dict[str, set] = {stem: set(cats) for stem, cats in vm.items()}
    for q in questions:
        stem = _stem(str(q.get("file", "")))
        if stem not in vm:
            continue
        cat = _QCLASS_TO_CATEGORY.get(str(q.get("question_class", "")).strip().lower())
        if cat:
            required.setdefault(stem, set()).add(cat)

    open_obligations = []
    covered = 0
    total = 0
    for stem, cats in sorted(required.items()):
        for cat in sorted(cats):
            total += 1
            if cat in enum.get(stem, set()):
                covered += 1
            elif stem in disp:
                covered += 1  # dispositioned asset discharges its obligations
            else:
                open_obligations.append({"asset": stem, "required_category": cat,
                                         "why": "derived from this function's per-fn question_class obligation; "
                                                "no mutation-verified enumerated invariant of this category and no disposition"})

    strict = (os.environ.get("AUDITOOOR_INVARIANT_OBLIGATION_STRICT", "").strip().lower()
              not in ("", "0", "false", "no"))
    if not open_obligations:
        verdict = "pass-obligations-covered"
    elif strict:
        verdict = "fail-invariant-obligation-uncovered"
    else:
        verdict = "warn-invariant-obligation-uncovered"
    return {"verdict": verdict, "strict": strict, "obligations": total,
            "covered": covered, "open_count": len(open_obligations),
            "value_moving_assets": len(required), "open": open_obligations}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    r = check(a.workspace)
    if a.json:
        print(json.dumps(r, indent=2))
    else:
        print(f"invariant-obligation-coverage: {r['verdict']} "
              f"({r['covered']}/{r['obligations']} obligations covered; "
              f"{r.get('open_count', 0)} open across {r.get('value_moving_assets', 0)} value-moving assets)")
        for o in r.get("open", [])[:20]:
            print(f"  <-- {o['asset']} needs a {o['required_category']} invariant (tested or dispositioned)")
    return 1 if r["verdict"].startswith("fail-") else 0


if __name__ == "__main__":
    raise SystemExit(main())
