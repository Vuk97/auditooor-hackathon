#!/usr/bin/env python3
"""Emit pinned, parser-backed Oscript syntax substrate records.

This is deliberately not a semantic engine.  It invokes the existing ocore
Nearley parser adapter and emits only AST-backed/syntactic source evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.oscript_ast_substrate.v1"
BACKEND = "ocore-nearley-ast"
EVIDENCE_TIER = "ast-backed/syntactic"


def _load_parser_adapter() -> Any:
    path = Path(__file__).with_name("oscript-ast-dataflow.py")
    spec = importlib.util.spec_from_file_location("_oscript_ast_dataflow", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load Oscript parser adapter")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _source_files(workspace: Path, source: Path | None) -> list[Path]:
    if source is not None:
        resolved = source.expanduser().resolve()
        try:
            resolved.relative_to(workspace)
        except ValueError as exc:
            raise ValueError("source is outside workspace") from exc
        return [resolved]
    return sorted(
        path for suffix in ("*.oscript", "*.aa") for path in workspace.rglob(suffix)
        if ".auditooor" not in path.parts and "node_modules" not in path.parts
    )


def _record(workspace: Path, source: Path, parsed: dict[str, Any]) -> dict[str, Any]:
    raw = source.read_bytes()
    rel = source.relative_to(workspace).as_posix()
    messages = parsed.get("messages")
    if not isinstance(messages, list):
        raise ValueError("parser output has no message list")
    return {
        "schema": SCHEMA,
        "record_type": "typed_source",
        "language": "oscript",
        "backend": BACKEND,
        "evidence_tier": EVIDENCE_TIER,
        "source": {"path": rel, "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)},
        "parser_execution": {"status": "passed", "backend": BACKEND, "message_count": len(messages)},
        "ast_summary": {
            "message_apps": sorted(str(row.get("app")) for row in messages if isinstance(row, dict) and row.get("app") is not None),
            "guarded_message_count": sum(1 for row in messages if isinstance(row, dict) and row.get("guard_ast") is not None),
        },
        "credit": {"compiler_backed": False, "semantic_engine": False, "depth": False, "fuzz": False},
    }


def run(workspace: Path, source: Path | None = None, ocore_root: Path | None = None) -> list[dict[str, Any]]:
    root = workspace.expanduser().resolve()
    if not root.is_dir():
        raise ValueError("workspace missing")
    adapter = _load_parser_adapter()
    parser_root = adapter._ocore_root(root, str(ocore_root) if ocore_root else None)
    node = adapter.shutil.which("node")
    if not node or parser_root is None:
        raise RuntimeError("ocore Nearley parser dependency unavailable")
    records = []
    for path in _source_files(root, source):
        records.append(_record(root, path, adapter.run_parser(node, parser_root, path)))
    if not records:
        raise ValueError("no Oscript sources found")
    return records


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--ocore-root", type=Path)
    args = parser.parse_args(argv)
    try:
        for record in run(args.workspace, args.source, args.ocore_root):
            print(json.dumps(record, sort_keys=True))
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
