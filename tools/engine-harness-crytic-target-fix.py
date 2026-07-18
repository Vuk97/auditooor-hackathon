#!/usr/bin/env python3
"""engine-harness-crytic-target-fix.py - make authored Solidity engine harnesses
crytic-compilable so medusa/echidna actually run (Step 2 genuine coverage).

Generic gap this closes: evm-engine-harness-author.py emits medusa.json with
compilation.platformConfig.target="." and an empty echidna cryticArgs. But
crytic-compile (used by BOTH medusa and echidna) builds a "." foundry target as
`forge build --build-info --skip ./test/**`, which SKIPS the harness's fuzzable
property contract (it lives in test/<Name>_FuzzProps.sol). Result: no
out/build-info for the property contract -> "out/build-info is not a directory"
-> medusa rc=6 / echidna rc=1 -> ALL engines error -> DEEP_AUDIT_HOLLOW. The
README (#505) already mandates the fix: target MUST be the specific property
FILE, not ".". This tool backfills existing harnesses to that contract.

Per harness <ws>/poc-tests/*-engine-harness/:
  - medusa.json: set compilation.platformConfig.target to test/<targetContract>.sol
    (or src/<targetContract>.sol) when it is currently "." and the file exists.
  - echidna.yaml: ensure cryticArgs includes --foundry-compile-all (so echidna's
    crytic-compile does not skip test/ either).

Idempotent + honest: only rewrites a target that is "." to a resolvable file; if
the property file cannot be found, it is LEFT UNCHANGED and reported as skipped
(never points the target at a nonexistent file).
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from pathlib import Path


def _resolve_target_file(harness: Path, contract: str) -> str | None:
    """Return the harness-relative path to the .sol file declaring `contract`,
    preferring test/ then src/. None if not found."""
    for sub in ("test", "src"):
        cand = harness / sub / f"{contract}.sol"
        if cand.is_file():
            return f"{sub}/{contract}.sol"
    # fallback: grep for `contract <Name>` under test/ then src/
    for sub in ("test", "src"):
        d = harness / sub
        if not d.is_dir():
            continue
        for p in sorted(d.rglob("*.sol")):
            try:
                if f"contract {contract}" in p.read_text(encoding="utf-8", errors="ignore"):
                    return str(p.relative_to(harness))
            except OSError:
                continue
    return None


def fix_medusa(harness: Path) -> dict:
    mj = harness / "medusa.json"
    if not mj.is_file():
        return {"medusa": "absent"}
    try:
        d = json.loads(mj.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"medusa": "unparseable"}
    pc = d.get("compilation", {}).get("platformConfig", {})
    cur = pc.get("target")
    if cur != ".":
        return {"medusa": f"already-targeted:{cur}"}
    tcs = d.get("fuzzing", {}).get("targetContracts") or []
    contract = tcs[0] if tcs else ""
    if not contract:
        return {"medusa": "no-targetContract"}
    rel = _resolve_target_file(harness, contract)
    if not rel:
        return {"medusa": f"target-file-not-found:{contract}"}
    pc["target"] = rel
    d["compilation"]["platformConfig"] = pc
    mj.write_text(json.dumps(d, indent=2) + "\n", encoding="utf-8")
    return {"medusa": f"fixed:.->{rel}"}


def fix_echidna(harness: Path) -> dict:
    ey = harness / "echidna.yaml"
    if not ey.is_file():
        return {"echidna": "absent"}
    txt = ey.read_text(encoding="utf-8")
    if "--foundry-compile-all" in txt:
        return {"echidna": "already-has-compile-all"}
    lines = txt.splitlines()
    out = []
    replaced = False
    for ln in lines:
        if ln.strip().startswith("cryticArgs:") and not replaced:
            out.append('cryticArgs: ["--foundry-compile-all"]')
            replaced = True
        else:
            out.append(ln)
    if not replaced:
        out.append('cryticArgs: ["--foundry-compile-all"]')
    ey.write_text("\n".join(out) + "\n", encoding="utf-8")
    return {"echidna": "added-foundry-compile-all"}


def run(ws: Path) -> dict:
    harness_dirs = sorted(
        Path(p) for p in glob.glob(str(ws / "poc-tests" / "*-engine-harness"))
        if Path(p).is_dir()
    )
    results = []
    fixed_medusa = fixed_echidna = 0
    for h in harness_dirs:
        r = {"harness": h.name}
        r.update(fix_medusa(h))
        r.update(fix_echidna(h))
        if str(r.get("medusa", "")).startswith("fixed:"):
            fixed_medusa += 1
        if r.get("echidna") == "added-foundry-compile-all":
            fixed_echidna += 1
        results.append(r)
    return {
        "workspace": str(ws),
        "harnesses": len(harness_dirs),
        "medusa_targets_fixed": fixed_medusa,
        "echidna_compile_all_added": fixed_echidna,
        "results": results,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Fix engine-harness crytic-compile targets.")
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    ws = Path(args.workspace).expanduser().resolve()
    if not ws.is_dir():
        print(f"[engine-harness-crytic-target-fix] ERR workspace not found: {ws}", file=sys.stderr)
        return 2
    res = run(ws)
    print(f"[engine-harness-crytic-target-fix] {ws.name}: "
          f"{res['medusa_targets_fixed']}/{res['harnesses']} medusa targets fixed, "
          f"{res['echidna_compile_all_added']} echidna compile-all added")
    if args.json:
        print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
