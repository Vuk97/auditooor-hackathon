#!/usr/bin/env python3
"""program-intake-check.py - validate that a workspace has INGESTED a bounty program's
own rules into machine-readable, enforced artifacts, so dedup / scope / PoC-requirement
decisions are grounded in the program's actual constraints instead of guessed.

Motivated 2026-07-07 (Strata): the program published hard PoC requirements (>=10-asset
tranche seeding; ONE_ASSET-impact-dependent findings closed as invalid) and an eligibility
rule (ANY disclosed vuln - fixed OR not - is ineligible; 6 prior audits), plus per-finding
"is it still live at the current pin" nuance. None of that was captured as a first-class
artifact, so findings were drafted that violated it and dedup was ad hoc.

This is the INTAKE MANUAL-STEP gate (advisory-first): it reports what a workspace still
needs so the operator/agent can fill it, and later runs can hard-enforce presence.

Required intake artifacts (each optional key checked independently):
  <ws>/.auditooor/program_rules.json
      poc_seeding {min_assets_per_entity, floor_constant, floor_value_wei, entities}
      invalid_impact_conditions : [phrases]  (program-excluded impact conditions)
      eligibility {disclosed_unpatched_eligible: bool}  (PER-PROGRAM - Strata=false)
      prior_audits : [ {auditor, date, url|link} ]  (the completed audits)
      scope_globs / oos_globs (optional; SCOPE.md remains the authority)
  <ws>/prior_audits/known_issues.jsonl
      one row per DISCLOSED prior finding: {id, title, severity, file, disclosed_in,
      status(disclosed|resolved), fix_verified_at_pin: true|false|unknown, dedup_class}
      -> `fix_verified_at_pin` is the "is the exploit still LIVE" flag; `unknown` means the
      fix presence at HEAD has not been checked yet (a hunt lead: verify it).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def _load_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _load_jsonl(p: Path) -> list[dict]:
    rows = []
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    pass
    except OSError:
        pass
    return rows


def check(ws: Path) -> dict:
    items = []
    rules_p = ws / ".auditooor" / "program_rules.json"
    ki_p = ws / "prior_audits" / "known_issues.jsonl"

    rules = _load_json(rules_p) if rules_p.is_file() else None
    if rules is None:
        items.append({"artifact": "program_rules.json", "status": "MISSING",
                      "need": "author PoC requirements + eligibility + prior_audits list"})
    else:
        seed = rules.get("poc_seeding") or {}
        items.append({"artifact": "program_rules.poc_seeding",
                      "status": "ok" if seed.get("min_assets_per_entity") else "incomplete",
                      "need": "min_assets_per_entity + floor_constant/value"})
        # eligibility + prior-audits may live in an `eligibility` OR legacy
        # `ineligible_if_disclosed` block; merge both so key placement never false-reds.
        elig = {**(rules.get("ineligible_if_disclosed") or {}),
                **(rules.get("eligibility") or {})}
        has_elig = ("disclosed_unpatched_eligible" in elig) or elig.get("enforced")
        items.append({"artifact": "program_rules.eligibility",
                      "status": "ok" if has_elig else "incomplete",
                      "need": "eligibility.disclosed_unpatched_eligible (per-program: is a "
                              "disclosed-but-UNPATCHED bug eligible? Strata=false)"})
        items.append({"artifact": "program_rules.invalid_impact_conditions",
                      "status": "ok" if rules.get("invalid_impact_conditions") else "advisory",
                      "need": "program-excluded impact conditions (e.g. ONE_ASSET dependence)"})
        audits = rules.get("prior_audits") or elig.get("audits")
        items.append({"artifact": "program_rules.prior_audits",
                      "status": "ok" if audits else "incomplete",
                      "need": "list the completed audits (auditor + date + link)"})

    ki = _load_jsonl(ki_p) if ki_p.is_file() else None
    if not ki:
        items.append({"artifact": "prior_audits/known_issues.jsonl", "status": "MISSING",
                      "need": "one row per disclosed prior finding with fix_verified_at_pin "
                              "(the is-it-still-LIVE flag) + dedup_class"})
    else:
        n = len(ki)
        unknown = sum(1 for r in ki if str(r.get("fix_verified_at_pin")).lower() == "unknown")
        no_flag = sum(1 for r in ki if "fix_verified_at_pin" not in r)
        items.append({"artifact": "prior_audits/known_issues.jsonl",
                      "status": "ok" if (unknown + no_flag) == 0 else "has-unverified",
                      "need": (f"{unknown+no_flag}/{n} disclosed issue(s) have UNKNOWN/missing "
                               f"fix-status at pin - verify each (live-vs-fixed) before dedup")
                              if (unknown + no_flag) else f"{n} issues, all fix-status-verified"})

    missing = [i for i in items if i["status"] in ("MISSING", "incomplete")]
    unverified = [i for i in items if i["status"] == "has-unverified"]
    verdict = ("fail-intake-incomplete" if missing else
               "warn-unverified-known-issues" if unverified else "pass-intake-complete")
    return {"workspace": str(ws), "verdict": verdict, "items": items,
            "missing": [i["artifact"] for i in missing]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true", help="rc=1 on warn too")
    a = ap.parse_args(argv)
    r = check(a.workspace)
    if a.json:
        print(json.dumps(r, indent=2))
    else:
        print(f"program-intake-check: {r['verdict']}")
        for i in r["items"]:
            print(f"  [{i['status']:14}] {i['artifact']}: {i['need']}")
    if r["verdict"] == "fail-intake-incomplete":
        return 1
    if r["verdict"] == "warn-unverified-known-issues" and a.strict:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
