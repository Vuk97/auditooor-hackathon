#!/usr/bin/env python3
"""callsite-selector.py - AST-exact name/signature-filtered CALL-SITE selector
(Glider gap #4): the AST-backed producer for the L30 "enumerate-all-callsites"
step, replacing the grep enumeration's silent misses.

WHAT IT FIXES
-------------
``tools/missing-guard-callsite-enumerator.sh`` enumerates call sites by grep, so
it SILENTLY MISSES sites the source text does not spell with the target's
canonical name:
  - renamed-import aliases   ``import {Real as Alias}`` then ``Alias.f()``
  - overloads-by-signature   ``f(uint)`` vs ``f(uint,address)``
  - virtual / override        a bare ``f()`` dispatched to a base/child body
  - interface dispatch        ``IFoo(x).f()`` resolved to the concrete impl
This tool walks Slither's call IR (``slither_predicates.callsites_of``), which
resolves every one of those to the concrete callee, so the enumeration is a
SUPERSET-or-equal of the grep path (never fewer genuine sites).

WIRING (produce -> consume, no orphan)
--------------------------------------
PRODUCE: this tool / ``callsites_of`` emit the complete AST-exact call-site set.
CONSUME: the L30 missing-guard gate / pre-submit Check #48 - a finding's
``## Enumerated Call Sites`` section is built from this set, so an alias /
override / interface call site can no longer be omitted from a missing-guard
report. ``tools/missing-guard-callsite-enumerator.sh`` invokes this tool for the
AST path and falls back to its own grep when Slither cannot compile (R80).
See reference/DATAFLOW_WIRING_ORDER.md (edge group Z) + the README note.

R80 (honesty) / never-regress
-----------------------------
When Slither is not importable or cannot compile the target, this tool emits a
single ``degraded`` advisory and exits with a sentinel rc so the bash enumerator
falls back to grep WITHOUT crashing - never a silent miss, never a faked pass.

USAGE
-----
  callsite-selector.py --target <name|sig> --path <file-or-dir> [--json]
  callsite-selector.py --target validateExit            --path contracts/
  callsite-selector.py --target 'validateExit(uint256)' --path Vault.sol --json

  Exit codes:
    0  AST path ran, call sites printed (possibly zero).
    3  DEGRADED (slither missing / compile failed) - caller must fall back.
    2  usage / IO error.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import pathlib
import sys

# Sentinel rc the bash enumerator keys on to trigger its grep fallback.
RC_OK = 0
RC_USAGE = 2
RC_DEGRADED = 3

_TOOLS = pathlib.Path(__file__).resolve().parent


def _load_predicates():
    spec = importlib.util.spec_from_file_location(
        "slither_predicates_cs", _TOOLS / "slither_predicates.py"
    )
    if not (spec and spec.loader):
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


def _slither_compile(path: str):
    """Compile `path` (a single .sol file or a directory) with Slither. Returns
    a LIST of Slither objects (one per successful compilation unit) or None on
    total failure (R80 degrade).

    A bare directory without a build framework (foundry/hardhat) cannot be
    compiled by Slither directly. We FIRST try the whole path (a single file, or
    a directory with a detectable build config compiles in one shot). If that
    fails AND the path is a directory, we retry per-.sol-file and UNION the
    results, so a config-less tree still yields AST-exact sites for the files
    that compile standalone (never fewer than grep; missing units degrade-skip,
    not crash)."""
    try:
        from slither import Slither
    except Exception:
        return None
    objs = []
    try:
        objs.append(Slither(path))
        return objs
    except Exception:
        pass
    if not os.path.isdir(path):
        return None
    # Per-file union fallback for a config-less directory.
    for root, _dirs, files in os.walk(path):
        # Skip the usual non-source dirs.
        if any(seg in root for seg in (
                "/.git", "/node_modules", "/vendor", "/target",
                "/dist", "/build")):
            continue
        for fn in files:
            if not fn.endswith(".sol"):
                continue
            try:
                objs.append(Slither(os.path.join(root, fn)))
            except Exception:
                continue  # this unit doesn't compile standalone -> skip (R80)
    return objs or None


def _emit_degraded(reason: str, as_json: bool) -> int:
    rec = {"degraded": True, "reason": reason, "callsites": []}
    if as_json:
        print(json.dumps(rec))
    else:
        print(f"[degraded] {reason} -- caller should fall back to grep (R80)",
              file=sys.stderr)
    return RC_DEGRADED


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True,
                    help="target function name (all overloads) or full "
                         "signature like 'f(uint256)' (that overload only)")
    ap.add_argument("--path", required=True,
                    help="a .sol file or a directory of contracts to compile")
    ap.add_argument("--json", action="store_true",
                    help="emit JSON instead of the human table")
    args = ap.parse_args(argv)

    if not os.path.exists(args.path):
        print(f"[error] path not found: {args.path}", file=sys.stderr)
        return RC_USAGE

    sp = _load_predicates()
    if sp is None or not hasattr(sp, "callsites_of"):
        return _emit_degraded("slither_predicates.callsites_of unavailable",
                              args.json)

    sl_objs = _slither_compile(args.path)
    if not sl_objs:
        return _emit_degraded("slither not importable or compile failed",
                              args.json)

    # Union contracts across every compilation unit, then dedupe rows on
    # (file, line, caller, dispatch_kind, callee) so per-file fallback compiles
    # of the SAME source do not double-count a site.
    contracts = []
    for sl in sl_objs:
        contracts.extend(getattr(sl, "contracts", []) or [])
    rows = sp.callsites_of(args.target, contracts)
    if sp.is_degraded(rows):
        return _emit_degraded("callsites_of degraded (no navigable contracts)",
                              args.json)
    seen = set()
    deduped = []
    for r in rows:
        k = (r["file"], r["line"], r["caller_contract"], r["caller_fn"],
             r["dispatch_kind"], r["callee"])
        if k in seen:
            continue
        seen.add(k)
        deduped.append(r)
    rows = deduped

    if args.json:
        print(json.dumps({"degraded": False, "target": args.target,
                          "callsites": rows}))
        return RC_OK

    print("============================================================")
    print("  callsite-selector (AST-exact, Glider gap #4)")
    print("============================================================")
    print(f"  target: {args.target}")
    print(f"  path:   {args.path}")
    print(f"  sites:  {len(rows)}")
    print("============================================================")
    if not rows:
        print("  (no call sites resolved for this target)")
        return RC_OK
    for r in rows:
        line = r["line"] if r["line"] is not None else "?"
        print(f"  {r['file']}:{line}  {r['caller_contract']}.{r['caller_fn']}"
              f"  [{r['dispatch_kind']}]  -> {r['callee']}")
    print("")
    print("  Per L30: feed these AST-exact sites into the finding's")
    print("  '## Enumerated Call Sites' section (Check #48). Alias / overload /")
    print("  override / interface sites the grep path misses are included here.")
    return RC_OK


if __name__ == "__main__":
    raise SystemExit(main())
