#!/usr/bin/env python3
"""R71 lane-verdict-bus consultation pre-submit check.

Rule 71 requires drill, hunt, triage, and dispatch-derived lane drafts to
show that they consulted the lane verdict bus before proceeding. The check is
deliberately tolerant of final Section 15n wording: it accepts the canonical
"Lane-Verdict-Bus Consultation" header and close aliases used by the dispatch
brief composer.

Exit codes:
  0 - pass, out-of-scope, empty bus, or accepted rebuttal
  1 - R71 violation
  2 - input error
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.r71_lane_verdict_bus_consult.v1"
GATE = "R71-LANE-VERDICT-BUS-CONSULT"
REBUTTAL_MAX_CHARS = 200
BUS_REL = Path(".auditooor") / "lane_verdict_bus"
AGGREGATE_NAME = "aggregated.json"

REBUTTAL_RE = re.compile(
    r"<!--\s*r71-rebuttal\s*:\s*(.{1,300}?)\s*-->",
    re.IGNORECASE | re.DOTALL,
)
REBUTTAL_LINE_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?r71-rebuttal\s*:\s*(.{1,300}?)\s*$",
)

SECTION_HEADER_RE = re.compile(
    r"(?im)^\s*#{1,6}\s*(?:"
    r"(?:section\s+)?15n\b.*lane[- ]verdict[- ]bus|"
    r"lane[- ]verdict[- ]bus\s+consultation|"
    r"sibling\s+lane\s+verdicts"
    r")\b"
)

SNAPSHOT_TIMESTAMP_RE = re.compile(
    r"(?im)^\s*[-*]?\s*(?:snapshot\s+)?timestamp\s*:\s*\S+"
)
BUS_SNAPSHOT_PATH_RE = re.compile(
    r"(?im)^\s*[-*]?\s*bus\s+snapshot\s+path\s*:\s*(\S+)"
)

LANE_TYPE_RE = re.compile(
    r"(?im)^\s*(?:lane[_ -]?type|type)\s*[:=]\s*(drill|hunt|triage|dispatch|comp)\b"
)
LANE_TEXT_RE = re.compile(
    r"\b("
    r"drill\s+lane|hunt\s+lane|triage\s+lane|dispatch-derived|"
    r"worker\s+[A-Z0-9_.:-]+|lane[_ -]?id|ORIENT|REACH|"
    r"candidate[_ -]?id|attack[_ -]?class"
    r")\b",
    re.IGNORECASE,
)
LANE_PATH_RE = re.compile(
    r"(^|[/_.-])(drill|hunt|triage|dispatch|lane|worker|agent_outputs)([/_.-]|$)",
    re.IGNORECASE,
)


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _parse_rebuttal(text: str) -> str | None:
    match = REBUTTAL_RE.search(text) or REBUTTAL_LINE_RE.search(text)
    if not match:
        return None
    reason = " ".join(match.group(1).split())
    if not reason or len(reason) > REBUTTAL_MAX_CHARS:
        return None
    return reason


def _infer_workspace(draft: Path, workspace: Path | None) -> Path | None:
    if workspace is not None:
        return workspace.expanduser().resolve()
    try:
        start = draft.expanduser().resolve()
    except OSError:
        start = draft.expanduser()
    for parent in [start.parent, *start.parents]:
        if (parent / ".auditooor").exists():
            return parent
    return None


def _is_lane_document(text: str, draft: Path, lane_type: str | None) -> tuple[bool, list[str]]:
    hits: list[str] = []
    if lane_type and lane_type.lower() in {"drill", "hunt", "triage", "dispatch", "comp"}:
        hits.append(f"lane-type:{lane_type.lower()}")
    path_text = str(draft)
    if LANE_PATH_RE.search(path_text):
        hits.append("path-lane-token")
    lane_type_match = LANE_TYPE_RE.search(text)
    if lane_type_match:
        hits.append(f"body-lane-type:{lane_type_match.group(1).lower()}")
    text_match = LANE_TEXT_RE.search(text)
    if text_match:
        hits.append(f"body-token:{text_match.group(1)}")
    return bool(hits), hits


def _section_present(text: str) -> dict[str, Any]:
    header = SECTION_HEADER_RE.search(text)
    snapshot_path = BUS_SNAPSHOT_PATH_RE.search(text)
    has_snapshot_timestamp = bool(SNAPSHOT_TIMESTAMP_RE.search(text))
    bus_snapshot_path = snapshot_path.group(1) if snapshot_path else None
    return {
        "present": bool(header),
        "header": header.group(0).strip() if header else None,
        "has_snapshot_timestamp": has_snapshot_timestamp,
        "bus_snapshot_path": bus_snapshot_path,
        "complete": bool(header) and has_snapshot_timestamp and bool(bus_snapshot_path),
    }


def _read_jsonl_records(path: Path) -> tuple[int, str | None]:
    count = 0
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return 0, f"cannot read {path}: {exc}"
    for lineno, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            return 0, f"{path}:{lineno}: invalid JSONL record: {exc}"
        if not isinstance(row, dict):
            return 0, f"{path}:{lineno}: record must be an object"
        count += 1
    return count, None


def _bus_state(workspace: Path | None) -> dict[str, Any]:
    if workspace is None:
        return {
            "classification": "empty",
            "reason": "workspace not resolved; treating bus as absent",
            "snapshot_path": None,
            "record_count": 0,
            "malformed": None,
        }

    bus_dir = workspace / BUS_REL
    snapshot = bus_dir / AGGREGATE_NAME
    state: dict[str, Any] = {
        "classification": "empty",
        "reason": "bus directory missing",
        "snapshot_path": str(snapshot),
        "record_count": 0,
        "malformed": None,
    }
    if not bus_dir.exists():
        return state

    if snapshot.exists():
        try:
            data = json.loads(snapshot.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            state.update({
                "classification": "malformed",
                "reason": f"malformed aggregate snapshot: {exc}",
                "malformed": str(exc),
            })
            return state
        if not isinstance(data, dict):
            state.update({
                "classification": "malformed",
                "reason": "aggregate snapshot must be a JSON object",
                "malformed": "aggregate snapshot must be a JSON object",
            })
            return state
        record_count = data.get("record_count")
        if not isinstance(record_count, int):
            state.update({
                "classification": "malformed",
                "reason": "aggregate snapshot missing integer record_count",
                "malformed": "record_count missing or not integer",
            })
            return state
        state.update({
            "classification": "non-empty" if record_count > 0 else "empty",
            "reason": "aggregate snapshot loaded",
            "record_count": record_count,
            "bus_empty": bool(data.get("bus_empty", record_count == 0)),
            "snapshot_schema": data.get("schema_version"),
        })
        if record_count == 0 or data.get("bus_empty") is True:
            state["classification"] = "empty"
        return state

    jsonl_paths = sorted(path for path in bus_dir.glob("*.jsonl") if path.is_file())
    if not jsonl_paths:
        state["reason"] = "bus directory has no lane JSONL files"
        return state

    total = 0
    for path in jsonl_paths:
        count, error = _read_jsonl_records(path)
        if error:
            state.update({
                "classification": "malformed",
                "reason": error,
                "malformed": error,
            })
            return state
        total += count
    state.update({
        "classification": "non-empty" if total > 0 else "empty",
        "reason": "aggregate snapshot missing; counted lane JSONL records",
        "record_count": total,
        "jsonl_file_count": len(jsonl_paths),
    })
    return state


def check(
    draft: Path,
    *,
    workspace: Path | None = None,
    lane_type: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "gate": GATE,
        "draft": str(draft),
        "workspace": None,
        "verdict": "error",
        "reason": "",
        "evidence": {},
    }
    if not draft.exists():
        payload["reason"] = f"draft not found: {draft}"
        return payload

    text = _read_text(draft)
    resolved_workspace = _infer_workspace(draft, workspace)
    payload["workspace"] = str(resolved_workspace) if resolved_workspace else None

    rebuttal = _parse_rebuttal(text)
    if rebuttal:
        payload.update({
            "verdict": "ok-rebuttal",
            "reason": "r71-rebuttal accepted",
            "rebuttal": rebuttal,
        })
        return payload

    is_lane, lane_hits = _is_lane_document(text, draft, lane_type)
    section = _section_present(text)
    bus = _bus_state(resolved_workspace)
    payload["evidence"] = {
        "lane_document": is_lane,
        "lane_hits": lane_hits,
        "section": section,
        "bus": bus,
    }

    if not is_lane:
        payload.update({
            "verdict": "pass-out-of-scope",
            "reason": "draft does not look like a drill, hunt, triage, or dispatch lane",
        })
        return payload

    if section["complete"]:
        payload.update({
            "verdict": "pass-section-present",
            "reason": "Lane-Verdict-Bus Consultation section present",
        })
        return payload

    if section["present"]:
        missing_parts: list[str] = []
        if not section["bus_snapshot_path"]:
            missing_parts.append("bus snapshot path")
        if not section["has_snapshot_timestamp"]:
            missing_parts.append("snapshot timestamp")
        payload.update({
            "verdict": "fail-no-consult",
            "reason": (
                "Lane-Verdict-Bus Consultation section incomplete; missing "
                + " and ".join(missing_parts)
            ),
        })
        return payload

    if bus["classification"] == "empty":
        payload.update({
            "verdict": "pass-empty-bus",
            "reason": bus["reason"],
        })
        return payload

    if bus["classification"] == "malformed":
        payload.update({
            "verdict": "fail-malformed-bus-snapshot",
            "reason": bus["reason"],
        })
        return payload

    payload.update({
        "verdict": "fail-no-consult",
        "reason": (
            "lane draft has a non-empty lane verdict bus but no "
            "Lane-Verdict-Bus Consultation section"
        ),
    })
    return payload


def rc_for(payload: dict[str, Any]) -> int:
    verdict = str(payload.get("verdict") or "")
    if verdict == "error":
        return 2
    if verdict.startswith("fail-"):
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="R71 lane verdict bus consultation check")
    parser.add_argument("draft", help="Draft, brief, or lane result file to check")
    parser.add_argument("--workspace", help="Workspace root containing .auditooor/")
    parser.add_argument("--lane-type", choices=["drill", "hunt", "triage", "dispatch", "comp"])
    parser.add_argument("--strict", action="store_true", help="Accepted for interface parity")
    parser.add_argument("--json", action="store_true", help="Emit JSON payload")
    args = parser.parse_args(argv)

    payload = check(
        Path(args.draft).expanduser(),
        workspace=Path(args.workspace).expanduser() if args.workspace else None,
        lane_type=args.lane_type,
    )
    rc = rc_for(payload)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"{payload['verdict']}: {payload.get('reason', '')}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
