#!/usr/bin/env python3
"""Print distinct IN-SCOPE source-file paths from a workspace's authoritative
scope manifest (``.auditooor/inscope_units.jsonl``).

Generic + language-agnostic. Per-file/per-contract stages (e.g. the EVM
engine-harness author, per-contract harness scaffolding) historically enumerated
contracts with a raw ``find`` that hard-codes a few exclude globs
(test/mock/lib/...) but does NOT honor the program's ``scope.json``
``out_of_scope`` clauses. On a polyglot monorepo that silently authored harnesses
for out-of-scope modules (e.g. Hyperlane's ``contracts/avs`` AVS contracts that
are OOS per scope.json), wasting compute and polluting the harness/coverage set.

This helper drives those stages off the SAME scope authority the coverage gates
use (inscope_units.jsonl is produced scope-filtered, so OOS dirs are already
dropped). Prints one path per line, sorted, deduped. Non-absolute manifest paths
are resolved against the workspace. Exits non-zero (and prints nothing to stdout)
when no manifest / no matching files exist, so a caller can fall back to its
legacy enumeration without being starved.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def inscope_files(workspace: Path, ext: str = "") -> list[Path]:
    manifest = workspace / ".auditooor" / "inscope_units.jsonl"
    if not manifest.is_file():
        return []
    files: set[str] = set()
    try:
        text = manifest.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            row = json.loads(ln)
        except Exception:
            continue
        if not isinstance(row, dict):
            continue
        f = str(row.get("file") or "").strip()
        if not f:
            continue
        if ext and not f.endswith(ext):
            continue
        files.add(f)
    out: list[Path] = []
    for f in sorted(files):
        p = Path(f)
        if not p.is_absolute():
            p = workspace / f
        out.append(p)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("workspace")
    ap.add_argument("--ext", default="",
                    help="only files ending with this extension, e.g. .sol")
    ap.add_argument("--exists-only", action="store_true",
                    help="only print paths that exist on disk")
    args = ap.parse_args(argv)
    ws = Path(args.workspace).expanduser().resolve()
    if not ws.is_dir():
        sys.stderr.write(f"workspace not a directory: {ws}\n")
        return 2
    files = inscope_files(ws, args.ext)
    if args.exists_only:
        files = [p for p in files if p.exists()]
    if not files:
        sys.stderr.write(
            f"no in-scope files (manifest .auditooor/inscope_units.jsonl absent "
            f"or no {args.ext or 'matching'} entries) for {ws}\n")
        return 1
    for p in files:
        print(str(p))
    return 0


if __name__ == "__main__":
    sys.exit(main())
