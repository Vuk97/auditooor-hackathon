#!/usr/bin/env python3
"""program-rules-check.py - enforce a bug-bounty program's own PoC / scope rules on a
paste-ready finding BEFORE it is filed.

Generic + workspace-driven: reads <ws>/.auditooor/program_rules.json (absent -> N/A pass).
Programs frequently publish hard PoC/scope constraints the generic pipeline does not know
about (Strata 2026-07-07: "a PoC must seed BOTH tranches with >=10 assets; findings whose
impact depends on a tranche base NAV at/near ONE_ASSET are closed as invalid"). A finding
was drafted to High and nearly filed while its impact PROVABLY required Junior real NAV to
floor at 0 (< ONE_ASSET) - exactly the excluded condition. This gate makes such a finding
fail up front instead of after filing.

Checks (each program_rules.json key is optional):
  invalid_impact_conditions : [phrases]
      FAIL if a normalized phrase appears in the draft's impact/summary text (the finding's
      impact depends on a program-excluded condition).
  poc_seeding : {min_assets_per_entity, floor_value_wei, entities}
      WARN if the finding's PoC seeds a declared entity (tranche) at/below the floor or below
      min_assets * floor - i.e. inits at the accounting floor rather than a deployable state.
  ineligible_if_disclosed : {enforced}
      advisory reminder only (disclosure adjudication is done by the dedup gates); surfaced so
      the operator sees the eligibility rule.

ADVISORY-FIRST: verdict is warn/fail but the caller (pre-submit) decides enforcement; a
`program-rules-rebuttal` marker in the draft clears a specific check with an operator note.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip().lower()


def _load_rules(ws: Path) -> dict | None:
    p = ws / ".auditooor" / "program_rules.json"
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None


def _draft_impact_text(md: str) -> str:
    """Concatenate the impact-bearing sections (Summary / Impact / attack / impact-contract)
    so an excluded-condition phrase is caught where it is load-bearing, not in a dedup aside."""
    out = []
    keep = False
    for line in md.splitlines():
        h = re.match(r"^#{1,4}\s+(.*)$", line)
        if h:
            title = h.group(1).lower()
            keep = any(k in title for k in
                       ("summary", "impact", "attack", "root cause", "what the poc"))
            continue
        if keep:
            out.append(line)
    # also the impact-contract yaml block + the severity line, always
    out.append(md)  # fallback: whole doc (phrases are specific enough)
    return _norm(" ".join(out))


def _poc_files(finding_dir: Path) -> list[Path]:
    return [p for p in finding_dir.rglob("*.sol") if p.is_file()] + \
           [p for p in finding_dir.rglob("*.t.sol") if p.is_file()]


def check(ws: Path, draft: Path) -> dict:
    rules = _load_rules(ws)
    if rules is None:
        return {"verdict": "n/a", "reason": "no .auditooor/program_rules.json", "checks": []}
    md = draft.read_text(encoding="utf-8", errors="replace") if draft.is_file() else ""
    has_rebuttal = "program-rules-rebuttal" in md
    checks = []

    # 1. invalid impact conditions (FAIL)
    bad = rules.get("invalid_impact_conditions") or []
    impact_txt = _draft_impact_text(md)
    hit = [p for p in bad if _norm(p) and _norm(p) in impact_txt]
    checks.append({
        "check": "invalid-impact-condition",
        "status": "pass" if not hit else ("rebutted" if has_rebuttal else "fail"),
        "detail": {"matched": hit},
    })

    # 2. poc seeding floor (WARN)
    seed = rules.get("poc_seeding") or {}
    floor = int(seed.get("floor_value_wei") or 0)
    minx = int(seed.get("min_assets_per_entity") or 0)
    seed_status, seed_detail = "n/a", {}
    if floor and minx:
        threshold = floor * minx
        below = []
        for pf in _poc_files(draft.parent):
            txt = pf.read_text(encoding="utf-8", errors="replace")
            # seed literals near a deposit/seed call: N e18 / bare wei ints
            for m in re.finditer(r"\b(\d+)\s*e18\b", txt):
                val = int(m.group(1)) * floor
                if 0 < val < threshold:
                    below.append(f"{pf.name}: {m.group(0)} (< {minx} assets)")
            # a bare `ONE_ASSET`/`1e18` used as a deposit/seed amount
            if re.search(r"(deposit|seed|mint|init)\w*\([^)]*\bONE_ASSET\b", txt, re.I):
                below.append(f"{pf.name}: seeds an entity at ONE_ASSET")
        seed_status = "pass" if not below else ("rebutted" if has_rebuttal else "warn")
        seed_detail = {"threshold_wei": str(threshold), "below": sorted(set(below))[:8]}
    checks.append({"check": "poc-seeding-floor", "status": seed_status, "detail": seed_detail})

    # 3. PoC-requirements COMPLIANCE ATTESTATION (WARN) - the load-bearing check.
    # A syntactic gate cannot detect a SEMANTIC rule violation (Strata: the finding seeded
    # both tranches at 100e18 (compliant) yet its impact math PROVABLY required Junior real
    # NAV -> 0 (< ONE_ASSET); no regex catches that). So instead of detecting the violation,
    # REQUIRE the draft to affirmatively ADDRESS each program PoC rule - force the author to
    # confront it. A High+ finding that never states it seeds >= the floor AND that its impact
    # does not depend on the excluded floor condition is flagged for review (the finding that
    # slipped through never contained such an affirmation - it could not honestly write one).
    if seed:
        floor_const = str(seed.get("floor_constant") or "").lower()
        minx_a = seed.get("min_assets_per_entity")
        low = _norm(md)
        seed_affirmed = any(t in low for t in (
            "poc requirement", "poc-requirement", "deployable state",
            f">= {minx_a} asset" if minx_a else "\x00",
            f"{minx_a} assets each" if minx_a else "\x00",
            "seeds both tranches", "both tranches with", "seeded with"))
        floor_affirmed = (not floor_const) or (
            floor_const in low and any(
                neg in low for neg in ("does not depend", "not depend on",
                                       "independent of", "not near", "well above",
                                       "no dependence on")))
        missing = []
        if not seed_affirmed:
            missing.append("no affirmation the PoC seeds each entity >= the floor")
        if not floor_affirmed:
            missing.append(f"no affirmation the impact does NOT depend on {floor_const or 'the floor'}")
        checks.append({
            "check": "poc-requirements-attested",
            "status": "pass" if not missing else ("rebutted" if has_rebuttal else "warn"),
            "detail": {"missing": missing},
        })

    # 4. disclosure eligibility reminder (advisory)
    elig = rules.get("ineligible_if_disclosed") or {}
    if elig.get("enforced"):
        checks.append({
            "check": "disclosure-eligibility",
            "status": "advisory",
            "detail": {"note": elig.get("note", ""), "audits": elig.get("audits", [])},
        })

    fails = [c for c in checks if c["status"] == "fail"]
    warns = [c for c in checks if c["status"] == "warn"]
    verdict = "fail" if fails else ("warn" if warns else "pass")
    return {"verdict": verdict, "program": rules.get("program"), "checks": checks,
            "draft": str(draft)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument("--draft", required=True, type=Path)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true",
                    help="return rc=1 on a warn too (default: rc=1 only on fail)")
    a = ap.parse_args(argv)
    r = check(a.workspace, a.draft)
    if a.json:
        print(json.dumps(r, indent=2))
    else:
        print(f"program-rules-check: {r['verdict']} ({r.get('program','?')})")
        for c in r["checks"]:
            print(f"  [{c['status']:8}] {c['check']}: {json.dumps(c['detail'])[:160]}")
    if r["verdict"] == "fail":
        return 1
    if r["verdict"] == "warn" and a.strict:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
