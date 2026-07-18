#!/usr/bin/env python3
"""scope-allowlist-prune.py - prune the authoritative in-scope manifest
(.auditooor/inscope_units.jsonl) to the SCOPE.md ENUMERATED in-scope allowlist.

DEPRECATED (2026-06-30, capability-wiring audit Theme-A): the same allowlist
filter is now applied NATIVELY inside the manifest emitter
(workspace-coverage-heatmap.py `_scope_md_allowlist_filter`, wired into
`write_inscope_manifest` at f51c35c546) AND into `_source_file_records`
(94a93c9003), so `make audit` produces an already-pruned manifest with no
separate step. This standalone tool remains only as a manual safety-net for a
manifest written by an OLD emitter; the canonical pipeline does not call it. Do
not add it to the runbook - prefer re-running `make audit` (the emitter prunes).

Generic gap this closes (Strata 2026-06-30): the intake/scan over-collects -
it walks every production .sol under the cloned repo into inscope_units.jsonl,
which scope_exclusion.is_in_scope then treats as MANIFEST-AUTHORITATIVE. When the
program's SCOPE.md enumerates an EXPLICIT in-scope target list ("exactly these 13
targets, nothing else"), the over-collected manifest leaks OOS files (Strata:
Strategy.sol=149 units, DiscreteAccounting, lens/, swap/, oz/) into the worklist +
the coverage denominator, wasting hunt budget and producing a wrong/insolvable
coverage gate.

This tool re-derives the allowlist from SCOPE.md (via scope-md-parser, which honors
numbered + bulleted in-scope target lists) and DROPS every manifest row whose file
matches NO enumerated in-scope token. SAFE + idempotent + allowlist-gated:
  - runs ONLY when SCOPE.md declares a non-empty enumerated allowlist (in_scope_paths);
    a whole-repo scope doc (no enumerated paths) is left untouched (no false pruning).
  - never ADDS rows; only removes out-of-allowlist rows.
  - writes a one-time .bak of the original manifest the first time it prunes.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

_THIS = Path(__file__).resolve().parent


def _load_scope_parser():
    spec = importlib.util.spec_from_file_location(
        "scope_md_parser", str(_THIS / "scope-md-parser.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules["scope_md_parser"] = m
    spec.loader.exec_module(m)
    return m


def prune(workspace: Path, *, dry_run: bool = False) -> dict:
    smp = _load_scope_parser()
    scope_md = workspace / "SCOPE.md"
    manifest = workspace / ".auditooor" / "inscope_units.jsonl"
    out = {"workspace": str(workspace), "pruned": 0, "kept": 0,
           "allowlist_tokens": 0, "verdict": "noop"}
    if not scope_md.is_file() or not manifest.is_file():
        out["verdict"] = "noop-missing-scope-or-manifest"
        return out
    mf = smp.parse_scope_md(scope_md)
    if not mf.in_scope_paths:
        # No enumerated allowlist -> whole-repo scope; do NOT prune (fail-safe).
        out["verdict"] = "noop-no-allowlist"
        return out
    out["allowlist_tokens"] = len(mf.in_scope_paths)
    rows = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    kept, dropped = [], []
    for r in rows:
        rel = str(r.get("file") or r.get("path") or r.get("rel") or "")
        in_scope, _reason = smp.is_path_in_scope(rel, mf)
        (kept if in_scope else dropped).append(r)
    out["kept"], out["pruned"] = len(kept), len(dropped)
    out["dropped_files"] = sorted({str(r.get("file") or "").split("/contracts/")[-1]
                                   for r in dropped})[:25]
    if dropped and not dry_run:
        bak = manifest.with_suffix(".jsonl.preprune.bak")
        if not bak.exists():
            bak.write_text(manifest.read_text(encoding="utf-8"), encoding="utf-8")
        manifest.write_text(
            "".join(json.dumps(r) + "\n" for r in kept), encoding="utf-8")
        out["verdict"] = "pruned"
        out["backup"] = str(bak)
    elif dropped:
        out["verdict"] = "would-prune"
    else:
        out["verdict"] = "noop-already-clean"
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    r = prune(a.workspace, dry_run=a.dry_run)
    if a.json:
        print(json.dumps(r, indent=2))
    else:
        print(f"scope-allowlist-prune: {r['verdict']} "
              f"(kept {r['kept']}, pruned {r['pruned']}, allowlist {r['allowlist_tokens']} tokens)")
        for f in r.get("dropped_files", [])[:15]:
            print(f"  - dropped OOS: {f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
