#!/usr/bin/env python3
"""Validate docs/STAGE_REFERENCE.md against tools/engage.py.

This is intentionally narrow: it checks the canonical stage names and the
standalone rejection-learn entry. The stage descriptions can stay human-edited,
but the ordered stage list must match the orchestrator.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ENGAGE = REPO / "tools" / "engage.py"
DOC = REPO / "docs" / "STAGE_REFERENCE.md"


def _load_stage_table() -> list[str]:
    tree = ast.parse(ENGAGE.read_text())
    for node in tree.body:
        value = None
        if isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == "STAGE_TABLE":
                value = node.value
        elif isinstance(node, ast.Assign):
            if any(isinstance(t, ast.Name) and t.id == "STAGE_TABLE" for t in node.targets):
                value = node.value
        if value is not None:
            rows = ast.literal_eval(value)
            return [row[0] for row in rows]
    raise RuntimeError("STAGE_TABLE not found in tools/engage.py")


def _load_doc_rows() -> tuple[list[str], bool]:
    stages: list[str] = []
    standalone_ok = False
    row_re = re.compile(r"^\|\s*(?P<num>\d+|standalone)\s*\|\s*`(?P<stage>[^`]+)`\s*\|")
    for line in DOC.read_text().splitlines():
        m = row_re.match(line)
        if not m:
            continue
        stage = m.group("stage")
        if m.group("num") == "standalone":
            standalone_ok = stage == "rejection-learn"
        else:
            stages.append(stage)
    return stages, standalone_ok


def main() -> int:
    table = _load_stage_table()
    canonical = [s for s in table if s != "rejection-learn"]
    doc_stages, standalone_ok = _load_doc_rows()

    errors: list[str] = []
    if doc_stages != canonical:
        errors.append("docs/STAGE_REFERENCE.md canonical stage order differs from tools/engage.py")
        max_len = max(len(doc_stages), len(canonical))
        for i in range(max_len):
            expected = canonical[i] if i < len(canonical) else "<missing>"
            actual = doc_stages[i] if i < len(doc_stages) else "<missing>"
            if expected != actual:
                errors.append(f"  {i + 1:02d}: expected {expected!r}, found {actual!r}")
    if not standalone_ok:
        errors.append("docs/STAGE_REFERENCE.md must include standalone `rejection-learn` row")

    if errors:
        print("[stage-reference] FAIL")
        print("\n".join(errors))
        return 1
    print(f"[stage-reference] OK - {len(canonical)} canonical stages + rejection-learn standalone")
    return 0


if __name__ == "__main__":
    sys.exit(main())
