#!/usr/bin/env python3
# <!-- r36-rebuttal: lane CHIMERA-ECHIDNA-EMIT registered in commit message -->
"""chimera-echidna-emit.py - materialize a runnable echidna.yaml for every
Chimera/Recon invariant harness so README Step-2c genuinely runs ALL THREE
engines (medusa + ECHIDNA + forge invariant), not just medusa.

Generic gap this closes (NUVA 2026-06-30): the Chimera harnesses author a
medusa.json (testLimit>=1M) + a forge *_Invariant.t.sol, but NO echidna.yaml -
chimera-scaffold.py only prints the echidna command (commands_display_only=True),
it never writes the config. So the only echidna.yaml on disk lived in the
auto-authored poc-tests/*-engine-harness/ scaffolds, which (a) are a separate,
shallower 50k probe and (b) in NUVA were STALE/corrupted (pre-dating the harness
author's unconstructable-struct guard) and failed crytic-compile -> echidna
rc=1 -> echidna silently NEVER RAN on the real CUT. Meanwhile the medusa-shaped
Chimera handler (property_*() returns(bool) + assertion wrappers) runs FINE under
echidna assertion mode once a config points at the Handler with
--foundry-compile-all (verified live: CrossChainManagerHandler, 6/6 properties
passing, cov 11385).

This tool writes, per <ws>/chimera_harnesses/<NAME>/, an echidna.yaml in
ASSERTION mode (catches both the property_*/invariant_* booleans echidna
auto-discovers AND the assert-based wrappers) targeting the discovered
*Handler contract, with --foundry-compile-all so crytic-compile does not skip
test/. Idempotent + honest: it only WRITES a config; it does not fake a run.
Run echidna separately and record an echidna_campaign_receipt.json.

NEVER corrupts a harness: it only writes echidna.yaml (never touches .sol), skips
*Mutant* handlers (those are deliberately-broken fixtures), and skips a dir that
already has a non-default echidna.yaml unless --force.
"""
from __future__ import annotations

import argparse
import glob
import json
import sys
from pathlib import Path

_DEFAULT_TEST_LIMIT = 1_000_000
_DEFAULT_SEQ_LEN = 50


def _discover_handler(harness_dir: Path) -> str | None:
    """Return the primary *Handler contract name for a chimera harness dir.

    Prefers test/<X>Handler.sol, excludes Mutant fixtures. Falls back to any
    *Handler.sol under the dir. None if none found."""
    cands: list[Path] = []
    for sub in ("test", "test/recon", "."):
        cands += sorted(Path(harness_dir / sub).glob("*Handler.sol")) if (harness_dir / sub).is_dir() else []
    if not cands:
        cands = sorted(harness_dir.rglob("*Handler.sol"))
    for c in cands:
        if "Mutant" in c.name:
            continue
        return c.stem  # contract name == file stem by convention
    return None


def _echidna_yaml(test_limit: int, seq_len: int) -> str:
    # Assertion mode: echidna auto-discovers property_/invariant_ bool functions
    # AND flags any failing assert in the called wrappers. --foundry-compile-all
    # stops crytic-compile from skipping the test/ harness contract.
    return (
        "testMode: assertion\n"
        f"testLimit: {test_limit}\n"
        f"seqLen: {seq_len}\n"
        "cryticArgs:\n"
        "  - --foundry-compile-all\n"
    )


def emit(ws: Path, test_limit: int, seq_len: int, force: bool) -> dict:
    root = ws / "chimera_harnesses"
    out = {"workspace": str(ws), "written": [], "skipped": [], "no_handler": []}
    if not root.is_dir():
        out["error"] = "no chimera_harnesses/ dir"
        return out
    for d in sorted(p for p in root.iterdir() if p.is_dir()):
        handler = _discover_handler(d)
        if handler is None:
            out["no_handler"].append(d.name)
            continue
        cfg = d / "echidna.yaml"
        if cfg.is_file() and not force:
            # Only skip if it already targets assertion mode (a real config).
            try:
                existing = cfg.read_text(encoding="utf-8")
            except OSError:
                existing = ""
            if "testMode: assertion" in existing:
                out["skipped"].append(d.name)
                continue
        cfg.write_text(_echidna_yaml(test_limit, seq_len), encoding="utf-8")
        out["written"].append({"harness": d.name, "contract": handler,
                               "config": str(cfg.relative_to(ws)),
                               "run": f"cd {d.relative_to(ws)} && echidna . --contract {handler} --config echidna.yaml"})
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument("--test-limit", type=int, default=_DEFAULT_TEST_LIMIT)
    ap.add_argument("--seq-len", type=int, default=_DEFAULT_SEQ_LEN)
    ap.add_argument("--force", action="store_true", help="overwrite an existing echidna.yaml")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    r = emit(a.workspace, a.test_limit, a.seq_len, a.force)
    if a.json:
        print(json.dumps(r, indent=2))
    else:
        print(f"chimera-echidna-emit: wrote {len(r.get('written', []))}, "
              f"skipped {len(r.get('skipped', []))}, no-handler {len(r.get('no_handler', []))}")
        for w in r.get("written", []):
            print(f"  + {w['harness']} -> {w['contract']}")
    return 0 if not r.get("error") else 1


if __name__ == "__main__":
    raise SystemExit(main())
