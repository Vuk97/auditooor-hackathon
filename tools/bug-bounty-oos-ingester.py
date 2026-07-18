#!/usr/bin/env python3
"""M1-4a wrapper for BUG_BOUNTY.md OOS catalog ingestion.

This is intentionally thin. CAP-92 already shipped the parser and matcher in
``tools/bug_bounty_oos_index.py``. This wrapper provides the AGI-plan surface:

- a hyphenated CLI entrypoint
- warn-grade SUCCESS_WARN when no BUG_BOUNTY.md catalog exists
- optional quiet mode for Makefile wiring
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


SUCCESS = "SUCCESS"
SUCCESS_WARN = "SUCCESS_WARN"
FAIL = "FAIL"


def _load_helper() -> Any:
    here = Path(__file__).resolve().parent
    helper_path = here / "bug_bounty_oos_index.py"
    spec = importlib.util.spec_from_file_location("bug_bounty_oos_index", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"helper unavailable: {helper_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ingest_workspace(workspace: Path, output_path: Path | None = None) -> dict[str, Any]:
    helper = _load_helper()
    workspace = workspace.resolve()
    index = helper.build_and_write_index(workspace, output_path)
    source_paths = list(index.get("source_paths") or [])
    if source_paths:
        status = SUCCESS
        state = "indexed"
        message = f"indexed {len(source_paths)} BUG_BOUNTY.md source file(s)"
    else:
        status = SUCCESS_WARN
        state = "missing-bug-bounty-md"
        message = "no BUG_BOUNTY.md catalog found; wrote empty index"
    return {
        "status": status,
        "state": state,
        "message": message,
        "workspace": str(workspace),
        "index_path": str(index.get("index_path") or ""),
        "source_paths": source_paths,
        "row_count": int(index.get("row_count") or 0),
        "index_hash": str(index.get("index_hash") or ""),
        "index_schema": str(index.get("schema") or ""),
        "index": index,
    }


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ingest BUG_BOUNTY.md OOS catalogs")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--output", default=None)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    workspace = Path(args.workspace).resolve()
    output = Path(args.output).resolve() if args.output else None

    if not workspace.is_dir():
        message = f"{FAIL} workspace not found: {workspace}"
        if args.json:
            sys.stdout.write(json.dumps({"status": FAIL, "message": message}) + "\n")
        elif not args.quiet:
            sys.stdout.write(message + "\n")
        return 2

    result = ingest_workspace(workspace, output)
    if args.json:
        sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    elif not args.quiet:
        sys.stdout.write(
            f'{result["status"]} {result["message"]}; '
            f'rows={result["row_count"]} path={result["index_path"]}\n'
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
