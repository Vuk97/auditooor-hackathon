#!/usr/bin/env python3
"""Control-plane state snapshot assembly.

This module composes existing read-only control helpers into one durable packet.
It only writes when callers explicitly pass an output path.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .candidates import discover_candidates, paste_ready_blockers
from .next_actions import rank_next_actions
from .runs import summarize_runs
from .status import collect_status


SCHEMA = "auditooor.control.state.v1"


def collect_state(workspace: str | Path) -> dict[str, Any]:
    """Return a v1 control-plane snapshot for ``workspace``."""

    ws = Path(workspace).expanduser().resolve()
    status = collect_status(ws)
    candidates = _candidate_rows(ws)
    runs = summarize_runs(ws)
    actions = rank_next_actions(ws, status, candidates, runs.get("rows", []))
    return {
        "schema": SCHEMA,
        "workspace": ws.as_posix(),
        "target_name": ws.name,
        "generated_at": status.get("generated_at"),
        "status": status,
        "candidates": candidates,
        "runs": runs,
        "next_actions": actions,
    }


def render_json(snapshot: dict[str, Any]) -> str:
    return json.dumps(snapshot, indent=2, sort_keys=True) + "\n"


def write_state(snapshot: dict[str, Any], out_path: str | Path) -> Path:
    """Write ``snapshot`` to ``out_path`` and return the resolved path."""

    path = Path(out_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_json(snapshot), encoding="utf-8")
    return path.resolve()


def _candidate_rows(workspace: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for candidate in discover_candidates(workspace):
        row = candidate.to_dict()
        row["paste_ready_blockers"] = paste_ready_blockers(candidate)
        rows.append(row)
    return rows


__all__ = ["SCHEMA", "collect_state", "render_json", "write_state"]
