#!/usr/bin/env python3
"""queue-staleness-report.py — scan all advisory queues, dump JSON.

Background
----------
P2-4 burn-down. ``audit-closeout-check.py`` already warns when an advisory
queue (PoC dispatch briefs, deep counterexamples, P1 fixture extraction
queues, unresolved execution manifests) accumulates without execution. This
tool is the standalone, machine-readable view of the same state, suitable
for CI dashboards, handoff summaries, and stale-queue audits.

The output is a JSON list of objects:

::

    [
      {
        "queue": "poc_task_brief",
        "count": 5,
        "oldest_age_days": 12.7,
        "oldest_id": "/abs/path/to/poc_task_briefs/001-cand.md",
        "owner": "poc-execution",
        "status": "WARN"
      },
      ...
    ]

Status classification reuses the same env-configurable thresholds as
``audit-closeout-check.py``:

* ``AUDITOOOR_QUEUE_WARN_DAYS`` — items older than this WARN (default 7)
* ``AUDITOOOR_QUEUE_FAIL_DAYS`` — items older than this FAIL (default 30)
* ``REQUIRE_NO_STALE_QUEUES=1`` — promote any WARN-aged item to FAIL

Discipline
----------
* Stdlib-only.
* Offline-safe — reads the workspace, never calls the network.
* Deterministic for a given workspace + thresholds + clock.

Usage
-----
::

    python3 tools/queue-staleness-report.py --workspace <ws>
    python3 tools/queue-staleness-report.py --workspace <ws> --pretty
    python3 tools/queue-staleness-report.py --workspace <ws> --strict

Exit codes
----------
0  no FAIL rows
1  at least one FAIL row (only when ``--strict``)
2  argument / I/O error
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_closeout_module():
    """Import ``tools/audit-closeout-check.py`` despite the hyphenated name.

    Reusing the existing helpers (``_queue_item_summary``,
    ``_per_queue_summaries``, etc.) keeps the staleness classification
    consistent across the closeout gate and this report.
    """
    tool_path = REPO_ROOT / "tools" / "audit-closeout-check.py"
    spec = importlib.util.spec_from_file_location("audit_closeout_check", tool_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load module at {tool_path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("audit_closeout_check", mod)
    spec.loader.exec_module(mod)
    return mod


CLOSEOUT = _load_closeout_module()


def _glob(root: Path, pattern: str) -> list[Path]:
    try:
        return sorted(root.glob(pattern))
    except OSError:
        return []


def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _deep_counterexample_owners(ws: Path) -> dict[str, str]:
    data = _read_json(ws / "deep_counterexamples" / "execution_queue.json")
    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        return {}
    out: dict[str, str] = {}
    for item in data["items"]:
        if not isinstance(item, dict):
            continue
        rec = item.get("record_path")
        owner = item.get("assigned_model")
        if isinstance(rec, str) and isinstance(owner, str) and owner:
            out[rec] = owner
    return out


def collect_queue_items(ws: Path, *, now: float | None = None) -> list[dict]:
    """Walk all known advisory queues and emit closeout-shaped item rows."""
    briefs = _glob(ws, "source_mining/**/poc_task_briefs/*.md")
    deep_records = [
        path
        for path in _glob(ws, "deep_counterexamples/*.deep_counterexample.v1.json")
        if path.name != "collection_manifest.json"
    ]
    manifests = _glob(ws, "poc_execution/**/execution_manifest.json")
    deep_owners = _deep_counterexample_owners(ws)

    p1_queue = ws / ".audit_logs" / "p1_fixture_extraction" / "extraction_queue.json"
    p1_manifest = ws / ".audit_logs" / "p1_fixture_extraction" / "execution_manifest.json"
    p1_queue_rows = _read_json(p1_queue) if p1_queue.exists() else None
    p1_queue_count = len(p1_queue_rows) if isinstance(p1_queue_rows, list) else 0

    items: list[dict] = []
    items.extend(
        CLOSEOUT._queue_item_summary("poc_task_brief", path, owner="poc-execution", now=now)
        for path in briefs
    )
    items.extend(
        CLOSEOUT._queue_item_summary(
            "deep_counterexample",
            path,
            owner=deep_owners.get(str(path), "deep-counterexample-replay"),
            now=now,
        )
        for path in deep_records
    )
    if p1_queue_count and not p1_manifest.exists():
        items.append(
            CLOSEOUT._queue_item_summary(
                "p1_extraction_queue",
                p1_queue,
                owner="p1-fixture-extraction",
                now=now,
            )
        )
    # Unresolved execution manifests are also a source of latent staleness:
    # a manifest stuck on ``needs_human`` or unparseable for weeks deserves a
    # WARN/FAIL the same way an unexecuted brief does.
    for path in manifests:
        data = _read_json(path)
        final = ""
        if isinstance(data, dict):
            final_val = data.get("final_result")
            if isinstance(final_val, str):
                final = final_val
        if final in {"", "needs_human", "unreadable"}:
            items.append(
                CLOSEOUT._queue_item_summary(
                    "unresolved_execution_manifest",
                    path,
                    owner="poc-execution",
                    now=now,
                )
            )
    return items


def build_report(ws: Path, *, now: float | None = None) -> list[dict]:
    items = collect_queue_items(ws, now=now)
    return CLOSEOUT._per_queue_summaries(items)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=(
            "Scan advisory queues (PoC briefs, deep counterexamples, P1 "
            "extraction queues, unresolved execution manifests) and emit a "
            "JSON staleness report."
        ),
    )
    p.add_argument(
        "--workspace",
        required=True,
        type=Path,
        help="Audit workspace root (the WS=... argument to `make audit`).",
    )
    p.add_argument(
        "--pretty",
        action="store_true",
        help="Indent JSON output for human reading (default: compact).",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 if any queue ends up with status=FAIL.",
    )
    args = p.parse_args(argv)

    ws = args.workspace.expanduser()
    if not ws.exists():
        print(
            f"[queue-staleness-report] error: workspace not found: {ws}",
            file=sys.stderr,
        )
        return 2
    if not ws.is_dir():
        print(
            f"[queue-staleness-report] error: workspace is not a directory: {ws}",
            file=sys.stderr,
        )
        return 2

    blocks = build_report(ws)
    if args.pretty:
        print(json.dumps(blocks, indent=2))
    else:
        print(json.dumps(blocks))

    if args.strict and any(b.get("status") == CLOSEOUT.FAIL for b in blocks):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
