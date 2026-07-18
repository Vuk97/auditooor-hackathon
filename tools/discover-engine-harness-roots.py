#!/usr/bin/env python3
"""Discover engine-harness ROOTS for the solidity deep-engine all-harnesses loop.

WHY (SSV loop 2026-06-23): the all-harnesses discovery only globbed
`poc-tests/*-engine-harness/` (dirs with foundry.toml/hardhat.config). A workspace
whose coverage-guided harnesses live in the CANONICAL echidna/medusa layout -
`<foundry-root>/test/echidna/*Echidna.sol` + `echidna*.yaml` (+ corpus/) and/or a
`medusa.json` - was therefore invisible: roots-file empty ->
available_engine_harness_count=0 -> invariant_denominator_status=partial ->
`live-engines` / `engines-not-run-for-language` FALSE-RED even though a real, ran
suite exists (SSV: 24 harnesses, fuzzed >=500k). Same blind spot made
invariant-fuzz-completeness vacuously pass.

This tool generalises root discovery across the common layouts:
  1. poc-tests/*-engine-harness/   (the original; foundry.toml or hardhat.config.*)
  2. echidna suite roots           (a foundry root with test/echidna/*Echidna.sol
                                     or echidna*.yaml, OR property_/echidna_ props)
  3. medusa suite roots            (a foundry root with medusa.json)
The ROOT emitted is the FOUNDRY PROJECT ROOT (the dir holding foundry.toml), since
that is the cwd the deep-engine runner builds/executes from. Deduplicated, sorted.

Generic: --workspace only; prunes node_modules/lib/out/cache/prior_audits. Used by
the audit-deep-solidity-all-harnesses target (replaces the inline find) and is
safe to reuse anywhere a list of runnable engine-harness roots is needed.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

_PRUNE = {".git", "node_modules", "lib", "out", "cache", "artifacts", "broadcast",
          "prior_audits", "reference", "submissions", "agent_outputs", ".auditooor"}


def _pruned(p: Path) -> bool:
    return any(seg in _PRUNE for seg in p.parts)


def _foundry_roots(ws: Path) -> list[Path]:
    roots = []
    for ft in ws.rglob("foundry.toml"):
        if _pruned(ft.relative_to(ws)) if ft != ws else False:
            continue
        if _pruned(ft.parent.relative_to(ws)):
            continue
        roots.append(ft.parent)
    return roots


def discover(ws: Path) -> list[str]:
    found: set[Path] = set()

    # (1) poc-tests/*-engine-harness/ - the original layout.
    poc = ws / "poc-tests"
    if poc.is_dir():
        for d in sorted(poc.iterdir()):
            if not d.is_dir() or not d.name.endswith("-engine-harness"):
                continue
            if (d / "foundry.toml").is_file() or any(d.glob("hardhat.config.*")):
                found.add(d.resolve())

    # (2)+(3) echidna/medusa suite roots = the FOUNDRY ROOT that owns them.
    for root in _foundry_roots(ws):
        is_engine_root = False
        # echidna: a test/echidna dir (or any echidna dir) with a harness or config
        for ed in list(root.rglob("echidna")):
            try:
                if _pruned(ed.relative_to(root)):
                    continue
            except ValueError:
                continue
            if not ed.is_dir():
                continue
            if any(ed.glob("*Echidna.sol")) or any(ed.glob("echidna*.yaml")) \
               or any(ed.glob("*.yaml")) and any(ed.glob("*.sol")):
                is_engine_root = True
                break
        # medusa: a medusa.json anywhere under the root
        if not is_engine_root:
            for mj in root.rglob("medusa.json"):
                try:
                    if _pruned(mj.relative_to(root)):
                        continue
                except ValueError:
                    continue
                is_engine_root = True
                break
        if is_engine_root:
            found.add(root.resolve())

    return sorted(str(p) for p in found)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--out", default=None, help="write roots (one per line) here")
    args = ap.parse_args(argv)
    ws = Path(args.workspace).resolve()
    roots = discover(ws)
    text = "\n".join(roots) + ("\n" if roots else "")
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
