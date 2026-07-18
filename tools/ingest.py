#!/usr/bin/env python3
"""ingest.py — single-entry dispatcher for pattern generation.

Replaces having to remember which of ~8 `*-to-specs` / `mine-*` scripts to call
for each corpus type. This script normalizes the flow:

    sources/            (raw inputs)
      ├─ solodit JSON corpus file       → mine-solodit.py   → YAML stubs
      ├─ audit PDF / text file          → mine-audit-to-patterns.py
      ├─ glider query dir               → glider-to-specs.py
      ├─ defihacklabs PoC dir           → defihacklabs-to-specs.py
      ├─ git-fix-diff corpus            → mine-diffs-to-patterns.py
      └─ audit-text (raw .md)           → audit-text-to-specs.py
                        ↓
            reference/patterns.dsl/    (always the target)
                        ↓
            tools/pattern-compile.py    (always the compile step)
                        ↓
            detectors/wave17/           (Solidity detectors)
            detectors/rust_wave1/       (Rust detectors, hand-written)

Usage:
    # Mine a Solodit corpus JSON file
    ingest.py solodit /tmp/solodit-cycle99.json
      → routes to `mine-solodit.py --input <file> --out-dir reference/patterns.dsl/`

    # Mine an audit PDF
    ingest.py audit ./path/to/audit.pdf

    # Mine Glider queries dir
    ingest.py glider external/glider-query-db/queries/

    # Mine DeFiHackLabs PoC dir
    ingest.py defihacklabs ./defihacklabs/src/

    # Mine raw audit text (markdown)
    ingest.py audit-text ./some-audit.md

    # Mine git-fix-diff corpus
    ingest.py diffs ./diff-corpus/

Run with `--dry-run` to print the underlying command without executing.
Run with `--list` to enumerate supported source types.

NOTE: This dispatcher PRESERVES the per-generator scripts. It does not replace
them; it just provides one stable entrypoint so users don't need to remember
which generator maps to which source type. Deprecation of any generator should
be tracked via `docs/TOOLS_INVENTORY.md` + `docs/archive/DEPRECATED.md`.
"""
from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

REPO = Path(__file__).resolve().parent.parent
TOOLS = REPO / "tools"
DEFAULT_OUT_DIR = REPO / "reference" / "patterns.dsl"


@dataclass
class Route:
    name: str
    primary_script: str     # path relative to repo root
    help_text: str
    arg_builder: Callable[[Path, Path], list[str]]


def solodit_args(input_path: Path, out_dir: Path) -> list[str]:
    return [
        str(TOOLS / "mine-solodit.py"),
        "--input", str(input_path),
        "--out-dir", str(out_dir),
    ]


def audit_pdf_args(input_path: Path, out_dir: Path) -> list[str]:
    # mine-audit-to-patterns.py takes an input file; output dir is flagged
    return [
        str(TOOLS / "mine-audit-to-patterns.py"),
        "--input", str(input_path),
        "--out-dir", str(out_dir),
    ]


def glider_args(input_path: Path, out_dir: Path) -> list[str]:
    # glider-to-specs.py sniffs the queries dir and emits YAML specs
    return [
        str(TOOLS / "glider-to-specs.py"),
        "--queries-dir", str(input_path),
        "--out-dir", str(out_dir),
    ]


def defihacklabs_args(input_path: Path, out_dir: Path) -> list[str]:
    return [
        str(TOOLS / "defihacklabs-to-specs.py"),
        "--src-dir", str(input_path),
        "--out-dir", str(out_dir),
    ]


def audit_text_args(input_path: Path, out_dir: Path) -> list[str]:
    return [
        str(TOOLS / "audit-text-to-specs.py"),
        "--input", str(input_path),
        "--out-dir", str(out_dir),
    ]


def diffs_args(input_path: Path, out_dir: Path) -> list[str]:
    return [
        str(TOOLS / "mine-diffs-to-patterns.py"),
        "--corpus-dir", str(input_path),
        "--out-dir", str(out_dir),
    ]


ROUTES: dict[str, Route] = {
    "solodit":       Route("solodit", "tools/mine-solodit.py",
                           "Solodit findings JSON → draft YAML stubs",
                           solodit_args),
    "audit":         Route("audit", "tools/mine-audit-to-patterns.py",
                           "Audit PDF / text → pattern candidates",
                           audit_pdf_args),
    "glider":        Route("glider", "tools/glider-to-specs.py",
                           "Hexens Glider query dir → YAML specs",
                           glider_args),
    "defihacklabs":  Route("defihacklabs", "tools/defihacklabs-to-specs.py",
                           "DeFiHackLabs PoC dir → YAML specs",
                           defihacklabs_args),
    "audit-text":    Route("audit-text", "tools/audit-text-to-specs.py",
                           "Raw audit markdown → YAML specs",
                           audit_text_args),
    "diffs":         Route("diffs", "tools/mine-diffs-to-patterns.py",
                           "Git fix-diff corpus → pattern candidates",
                           diffs_args),
}


def list_sources() -> int:
    print("Supported source types for `ingest.py`:\n")
    width = max(len(k) for k in ROUTES)
    for key, route in ROUTES.items():
        print(f"  {key:<{width}}  →  {route.primary_script}")
        print(f"  {'':{width}}     {route.help_text}")
        print()
    print(f"Default output dir: {DEFAULT_OUT_DIR.relative_to(REPO)}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Unified dispatcher for pattern-generation pipelines.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("source_type", nargs="?", default=None,
                    help="One of: " + ", ".join(ROUTES.keys()))
    ap.add_argument("input_path", nargs="?", default=None,
                    help="Path to the input file/dir")
    ap.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR),
                    help="Output dir (default: reference/patterns.dsl/)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Print command without executing")
    ap.add_argument("--list", action="store_true",
                    help="List supported source types and exit")
    args = ap.parse_args()

    if args.list or args.source_type is None:
        return list_sources()

    if args.source_type not in ROUTES:
        print(f"[err] Unknown source_type: {args.source_type}", file=sys.stderr)
        print(f"      Valid: {', '.join(ROUTES.keys())}", file=sys.stderr)
        return 2

    if args.input_path is None:
        print(f"[err] Missing input_path for `{args.source_type}`", file=sys.stderr)
        return 2

    input_path = Path(args.input_path).resolve()
    out_dir = Path(args.out_dir).resolve()

    if not input_path.exists():
        print(f"[err] Input does not exist: {input_path}", file=sys.stderr)
        return 2

    out_dir.mkdir(parents=True, exist_ok=True)

    route = ROUTES[args.source_type]
    cmd = [sys.executable] + route.arg_builder(input_path, out_dir)

    print(f"[ingest] route={route.name} script={route.primary_script}")
    print(f"[ingest] cmd: {' '.join(shlex.quote(c) for c in cmd)}")

    if args.dry_run:
        print("[ingest] --dry-run: not executing")
        return 0

    return subprocess.call(cmd)


if __name__ == "__main__":
    sys.exit(main())
