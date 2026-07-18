#!/usr/bin/env python3
"""Update scanner worker claim registries without hand-editing JSON."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.scanner_worker_active_claims.v1"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _safe_text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _slug(value: Any) -> str:
    text = re.sub(r"[^a-z0-9]+", "_", _safe_text(value).lower()).strip("_")
    while "__" in text:
        text = text.replace("__", "_")
    return text


def _rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    value = payload.setdefault("active_claims", [])
    if not isinstance(value, list):
        raise ValueError("active_claims must be a list")
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("active_claims rows must be objects")
    return value


def load_registry(path: Path) -> dict[str, Any]:
    if path.is_file():
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"expected object JSON in {path}")
    else:
        payload = {}
    payload.setdefault("schema", SCHEMA)
    _rows(payload)
    return payload


def parse_activation(raw: str) -> tuple[str, str]:
    if "=" not in raw:
        raise argparse.ArgumentTypeError("activation must be AGENT_ID=ROW_ID")
    agent_id, row_id = raw.split("=", 1)
    agent_id = agent_id.strip()
    row_id = row_id.strip()
    if not agent_id or not row_id:
        raise argparse.ArgumentTypeError("activation must include both AGENT_ID and ROW_ID")
    return agent_id, row_id


def mark_completed(payload: dict[str, Any], row_ids: list[str], *, allow_missing: bool = False) -> list[str]:
    rows = _rows(payload)
    missing: list[str] = []
    by_row = {_slug(row.get("row_id")): row for row in rows if _slug(row.get("row_id"))}
    for row_id in row_ids:
        row = by_row.get(_slug(row_id))
        if row is None:
            missing.append(row_id)
            if allow_missing:
                rows.append({"agent_id": "", "row_id": row_id, "status": "completed"})
            continue
        row["status"] = "completed"
    return missing


def activate(payload: dict[str, Any], assignments: list[tuple[str, str]]) -> None:
    rows = _rows(payload)
    by_row = {_slug(row.get("row_id")): row for row in rows if _slug(row.get("row_id"))}
    for agent_id, row_id in assignments:
        row = by_row.get(_slug(row_id))
        if row is None:
            row = {"agent_id": agent_id, "row_id": row_id, "status": "active"}
            rows.append(row)
            by_row[_slug(row_id)] = row
            continue
        row["agent_id"] = agent_id
        row["row_id"] = row_id
        row["status"] = "active"


def summary(payload: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in _rows(payload):
        status = _safe_text(row.get("status")) or "active"
        counts[status] = counts.get(status, 0) + 1
    return dict(sorted(counts.items()))


def update_registry(
    payload: dict[str, Any],
    *,
    completed: list[str],
    activations: list[tuple[str, str]],
    updated_at: str,
    allow_missing_complete: bool = False,
) -> tuple[dict[str, Any], list[str]]:
    payload["updated_at"] = updated_at
    missing = mark_completed(payload, completed, allow_missing=allow_missing_complete)
    activate(payload, activations)
    payload["summary"] = summary(payload)
    return payload, missing


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claims", required=True, type=Path, help="claim registry JSON path")
    parser.add_argument("--complete", action="append", default=[], help="row_id to mark completed")
    parser.add_argument("--activate", action="append", default=[], type=parse_activation, help="AGENT_ID=ROW_ID")
    parser.add_argument("--updated-at", default="", help="override updated_at timestamp")
    parser.add_argument("--allow-missing-complete", action="store_true")
    parser.add_argument("--in-place", action="store_true", help="rewrite --claims in place")
    parser.add_argument("--output", type=Path, help="optional output path; defaults to stdout")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.in_place and args.output:
        raise SystemExit("--in-place and --output are mutually exclusive")
    try:
        payload = load_registry(args.claims)
        updated, missing = update_registry(
            payload,
            completed=[_safe_text(row_id) for row_id in args.complete if _safe_text(row_id)],
            activations=args.activate,
            updated_at=args.updated_at or utc_now(),
            allow_missing_complete=args.allow_missing_complete,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"scanner worker claims update failed: {exc}") from exc
    if missing and not args.allow_missing_complete:
        raise SystemExit(f"missing completed row(s): {', '.join(missing)}")
    if args.in_place:
        write_json(args.claims, updated)
    elif args.output:
        write_json(args.output, updated)
    else:
        print(json.dumps(updated, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
