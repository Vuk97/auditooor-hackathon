#!/usr/bin/env python3
"""Protocol-model synthesizer for auditooor toolkit.

Reads SCOPE.md and a workspace contract list, then synthesizes a
protocol-model JSON containing:
  actors, objects, state_machines, invariants, trust_boundaries, composition_paths.

Currently emits a skeleton structure with TODO stubs where the inner LLM
call would live.  All I/O (CLI, file reads, JSON output) is fully wired.

CLI:
  python3 tools/protocol-model-synthesizer.py --workspace <path> \\
      --output <path>
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_ID = "auditooor.protocol_model.v1"
CONTRACT_EXTENSIONS = {".sol", ".vy", ".rs", ".cairo"}
MAX_READ_BYTES = 256_000  # per file cap


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_scope(workspace: Path) -> str:
    """Return text of SCOPE.md or empty string."""
    p = workspace / "SCOPE.md"
    return p.read_text(encoding="utf-8", errors="replace") if p.is_file() else ""


def discover_contracts(workspace: Path) -> list[dict[str, str]]:
    """Walk workspace and return [{path, name, source}] for contract files."""
    contracts: list[dict[str, str]] = []
    for p in sorted(workspace.rglob("*")):
        if not p.is_file():
            continue
        if p.suffix.lower() not in CONTRACT_EXTENSIONS:
            continue
        if any(part.startswith(".") or part == "node_modules" for part in p.parts):
            continue
        try:
            src = p.read_text(encoding="utf-8", errors="replace")[:MAX_READ_BYTES]
        except OSError:
            continue
        contracts.append({
            "path": str(p.relative_to(workspace)),
            "name": p.stem,
            "source": src,
        })
    return contracts


# ---------------------------------------------------------------------------
# LLM placeholder
# ---------------------------------------------------------------------------

def _llm_synthesize(scope: str, contracts: list[dict[str, str]]) -> dict[str, Any]:
    """Call inner LLM to produce the protocol model.

    TODO: Replace this stub with a real LLM invocation (e.g. via subprocess
    calling a local model, or an HTTP call to an inference endpoint).
    For now we return a minimal skeleton so the rest of the pipeline is testable.
    """
    actor_names: set[str] = set()
    for c in contracts:
        # Naive extraction: look for "actor" or "role" in variable names
        for m in re.finditer(r"\b(?:actor|role|user|admin|owner)[A-Za-z0-9_]*", c["source"], re.I):
            actor_names.add(m.group().lower())

    return {
        "actors": sorted(actor_names) if actor_names else ["TODO"],
        "objects": [c["name"] for c in contracts] or ["TODO"],
        "state_machines": ["TODO"],
        "invariants": ["TODO"],
        "trust_boundaries": ["TODO"],
        "composition_paths": ["TODO"],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Synthesize a protocol-model JSON from workspace sources."
    )
    ap.add_argument(
        "--workspace",
        type=Path,
        required=True,
        help="Root of the protocol workspace (must contain contract files).",
    )
    ap.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write JSON report to this path (default: stdout).",
    )
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    workspace: Path = args.workspace.resolve()
    if not workspace.is_dir():
        print(f"error: workspace not found: {workspace}", file=sys.stderr)
        return 1

    scope = read_scope(workspace)
    contracts = discover_contracts(workspace)
    if not contracts:
        print("warning: no contract files discovered", file=sys.stderr)

    model = _llm_synthesize(scope, contracts)

    report: dict[str, Any] = {
        "schema": SCHEMA_ID,
        "generated_at": utc_now(),
        "workspace": str(workspace),
        "scope_excerpt": scope[:500] if scope else "",
        "contract_count": len(contracts),
        "model": model,
    }

    blob = json.dumps(report, indent=2, ensure_ascii=False) + "\n"

    if args.output is not None:
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(blob, encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot write output: {exc}", file=sys.stderr)
            return 2
    else:
        sys.stdout.write(blob)

    return 0


if __name__ == "__main__":
    sys.exit(main())
