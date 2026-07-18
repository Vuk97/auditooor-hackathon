#!/usr/bin/env python3
"""Read-only workspace status collection for auditooorctl."""
from __future__ import annotations

import json
import importlib.util
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.control.status.v1"
STATUS_MISSING = "missing"
STATUS_READY = "ready"
STATUS_PRESENT = "present"
STATUS_STALE_UNKNOWN = "stale_unknown"
STATUS_BLOCKED_UNKNOWN = "blocked_unknown"
STATUS_EXECUTED_UNKNOWN = "executed_unknown"
_TASK_FINALIZATION_LEDGER = None

PLACEHOLDER_MARKERS = (
    "placeholder",
    "todo",
    "tbd",
    "fill me",
    "replace me",
    "coming soon",
)


@dataclass(frozen=True)
class FileCheck:
    path: str
    exists: bool
    kind: str
    status: str
    size_bytes: int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "exists": self.exists,
            "kind": self.kind,
            "status": self.status,
            "size_bytes": self.size_bytes,
        }


def _rel(path: Path, workspace: Path) -> str:
    try:
        return path.relative_to(workspace).as_posix()
    except ValueError:
        return path.as_posix()


def _read_text(path: Path, limit: int = 65536) -> str:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def _is_placeholder(path: Path) -> bool:
    text = _read_text(path).strip().lower()
    if not text:
        return True
    return any(marker in text for marker in PLACEHOLDER_MARKERS)


def _check_path(workspace: Path, relative_path: str, *, executed: bool = False) -> FileCheck:
    path = workspace / relative_path
    exists = path.exists()
    if not exists:
        return FileCheck(relative_path, False, "missing", STATUS_MISSING, None)
    kind = "directory" if path.is_dir() else "file"
    try:
        size = None if path.is_dir() else path.stat().st_size
    except OSError:
        size = None
    status = STATUS_EXECUTED_UNKNOWN if executed else STATUS_PRESENT
    return FileCheck(relative_path, True, kind, status, size)


def _markdown_file_status(workspace: Path, relative_path: str) -> dict[str, Any]:
    path = workspace / relative_path
    row = _check_path(workspace, relative_path).to_dict()
    if row["exists"] and path.is_file():
        row["placeholder_unknown"] = _is_placeholder(path)
    return row


def _readiness_from_files(workspace: Path, files: list[str], *, require_all: bool = False) -> dict[str, Any]:
    rows = [_markdown_file_status(workspace, rel) for rel in files]
    present = [row for row in rows if row["exists"]]
    usable = [row for row in present if not row.get("placeholder_unknown")]
    placeholder = [row for row in present if row.get("placeholder_unknown")]
    if require_all:
        missing = [row for row in rows if not row["exists"]]
        status = STATUS_READY if not missing and not placeholder else (
            STATUS_BLOCKED_UNKNOWN if present else STATUS_MISSING
        )
    else:
        status = STATUS_READY if usable else (
            STATUS_BLOCKED_UNKNOWN if present else STATUS_MISSING
        )
    return {
        "status": status,
        "files": rows,
        "present_count": len(present),
        "usable_count": len(usable),
    }


def _task_finalization_ledger_module() -> Any:
    global _TASK_FINALIZATION_LEDGER
    if _TASK_FINALIZATION_LEDGER is not None:
        return _TASK_FINALIZATION_LEDGER
    repo = Path(__file__).resolve().parents[2]
    path = repo / "tools" / "task-finalization-ledger.py"
    spec = importlib.util.spec_from_file_location("auditooor_task_finalization_ledger", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load task finalization ledger module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _TASK_FINALIZATION_LEDGER = module
    return module


def _task_finalization_ledger_status(workspace: Path) -> dict[str, Any]:
    relative_path = "reports/task_finalization.jsonl"
    path = workspace / relative_path
    row = _check_path(workspace, relative_path).to_dict()
    row.update({
        "row_count": 0,
        "status_counts": {},
        "latest_closed_at": None,
        "latest_task_id": None,
    })
    if not row["exists"]:
        return row
    if not path.is_file():
        row["status"] = STATUS_BLOCKED_UNKNOWN
        row["summary_error"] = "ledger path is not a file"
        return row
    try:
        ledger_module = _task_finalization_ledger_module()
        summary = ledger_module.summarize_ledger(path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        row["status"] = STATUS_BLOCKED_UNKNOWN
        row["row_count"] = 0
        row["status_counts"] = {}
        row["latest_closed_at"] = None
        row["latest_task_id"] = None
        row["summary_error"] = str(exc)
        return row
    row["row_count"] = summary["valid_rows"]
    row["total_rows"] = summary["total_rows"]
    row["invalid_row_count"] = summary["invalid_rows"]
    row["status_counts"] = summary["status_counts"]
    latest = summary.get("latest") or {}
    row["latest_closed_at"] = latest.get("closed_at")
    row["latest_task_id"] = latest.get("task_id")
    if summary["invalid_rows"]:
        row["status"] = STATUS_BLOCKED_UNKNOWN
        first_error = ""
        if summary.get("validation_errors"):
            item = summary["validation_errors"][0]
            first_error = f"; first: line {item['line']}: {'; '.join(item['errors'])}"
        row["summary_error"] = f"{summary['invalid_rows']} invalid task finalization row(s){first_error}"
    return row


def collect_status(workspace: str | Path) -> dict[str, Any]:
    ws = Path(workspace).expanduser().resolve()
    severity_files = [
        "SEVERITY.md",
        "SEVERITY_SMART_CONTRACTS.md",
        "SEVERITY_BLOCKCHAIN_DLT.md",
    ]
    artifacts = {
        "engage_report": _check_path(ws, "engage_report.md").to_dict(),
        "scan_report": _check_path(ws, "scan_report.md").to_dict(),
        "static_analysis_summary": _check_path(ws, "static-analysis-summary.md").to_dict(),
        "semantic_graph": _check_path(ws, ".auditooor/semantic_graph.json").to_dict(),
        "invariant_ledger": _check_path(ws, ".auditooor/invariant_ledger.json").to_dict(),
        "rust_scan_summary": _check_path(ws, "scanners/rust/SCAN_RUST_SUMMARY.json").to_dict(),
        "audit_deep_manifest": _check_path(
            ws, ".audit_logs/audit_deep_all_manifest.json", executed=True
        ).to_dict(),
        "task_finalization_ledger": _task_finalization_ledger_status(ws),
        "submissions": _check_path(ws, "submissions").to_dict(),
    }
    severity = _readiness_from_files(ws, severity_files)
    rubric = _readiness_from_files(ws, ["RUBRIC_COVERAGE.md"])
    if severity["status"] == STATUS_READY and rubric["status"] == STATUS_READY:
        severity_status = STATUS_READY
    elif severity["status"] == STATUS_MISSING and rubric["status"] == STATUS_MISSING:
        severity_status = STATUS_MISSING
    else:
        severity_status = STATUS_BLOCKED_UNKNOWN
    return {
        "schema": SCHEMA,
        "workspace": ws.as_posix(),
        "target_name": ws.name,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "readiness": {
            "scope": _readiness_from_files(ws, ["SCOPE.md"]),
            "severity": {
                "status": severity_status,
                "severity_files": severity["files"],
                "rubric_coverage": rubric["files"][0],
                "present_count": severity["present_count"] + rubric["present_count"],
                "usable_count": severity["usable_count"] + rubric["usable_count"],
            },
            "oos": _readiness_from_files(ws, ["OOS_CHECKLIST.md", "OOS_PASTED.md"]),
        },
        "artifacts": artifacts,
    }


def render_human(snapshot: dict[str, Any]) -> str:
    rows: list[tuple[str, str, str]] = [
        ("workspace", "present", snapshot["workspace"]),
        ("target", "present", snapshot["target_name"]),
    ]
    for name in ("scope", "severity", "oos"):
        rows.append((name, snapshot["readiness"][name]["status"], "readiness"))
    for name, info in snapshot["artifacts"].items():
        rows.append((name, info["status"], _artifact_detail(name, info)))

    name_w = max(len(row[0]) for row in rows + [("item", "", "")])
    status_w = max(len(row[1]) for row in rows + [("", "status", "")])
    lines = [
        f"{'item'.ljust(name_w)}  {'status'.ljust(status_w)}  detail",
        f"{'-' * name_w}  {'-' * status_w}  {'-' * 6}",
    ]
    lines.extend(f"{name.ljust(name_w)}  {status.ljust(status_w)}  {detail}" for name, status, detail in rows)
    return "\n".join(lines)


def _artifact_detail(name: str, info: dict[str, Any]) -> str:
    if name != "task_finalization_ledger":
        return str(info["path"])
    detail = str(info["path"])
    if info.get("summary_error"):
        return f"{detail} rows={info.get('row_count', 0)} error={info['summary_error']}"
    counts = info.get("status_counts") or {}
    count_text = " ".join(f"{status}={count}" for status, count in counts.items())
    latest = info.get("latest_closed_at") or "none"
    return f"{detail} rows={info.get('row_count', 0)} {count_text} latest={latest}".strip()


def render_json(snapshot: dict[str, Any]) -> str:
    return json.dumps(snapshot, indent=2, sort_keys=True) + "\n"
