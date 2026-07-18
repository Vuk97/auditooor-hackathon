#!/usr/bin/env python3
"""agent-cycle-log.py -- manual agent-cycle evidence log.

This tool provides a tiny append-only workspace log for agent cycling
evidence that currently lives only in chat. It does not hook into Codex
internals, dispatchers, or any background automation.

Artifact
--------
The primary artifact is ``<workspace>/.auditooor/agent_cycle_log.jsonl``.
Each row is a single JSON object with a lightweight schema:

  - ``schema``: ``auditooor.agent_cycle_log.v1``
  - ``ts``: UTC ISO timestamp
  - ``event``: one of ``spawn``, ``complete``, ``close``, ``verify``,
    ``no_artifact``
  - ``workspace``: absolute workspace path
  - ``agent``: optional agent label
  - ``task``: optional task label
  - ``note``: optional human note

The CLI supports two operations:

  append   Append one new row to the workspace JSONL log
  summary  Read the log and emit counts by event / agent / task

Summary mode is read-only and tolerates malformed rows by skipping them.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Callable


SCHEMA = "auditooor.agent_cycle_log.v1"
DEFAULT_EVENTS = ("spawn", "complete", "close", "verify", "no_artifact")
TERMINAL_EVENTS = {"complete", "close"}
NO_ARTIFACT_MARKER = "NO_ARTIFACT"
DEFAULT_LOG_REL = Path(".auditooor") / "agent_cycle_log.jsonl"
_PLACEHOLDER_VALUES = {"", "tbd", "todo", "n/a", "na", "none", "null", "-", "`tbd`", "`todo`"}
_CONTEXT_PACK_ID_RE = re.compile(r"^auditooor\.vault_context_pack\.v1:[^:\s]+:[0-9a-f]{16}$")


def _utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_iso(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        return dt.datetime.fromisoformat(candidate)
    except ValueError:
        return None


def _normalize_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        return text or None
    return str(value).strip() or None


def _is_non_empty_string_list(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(item, str) and item.strip() for item in value)


def _is_placeholder_text(value: Any) -> bool:
    if not isinstance(value, str):
        return True
    cleaned = value.strip().strip("`").strip()
    return cleaned.lower() in _PLACEHOLDER_VALUES


def _structured_evidence_present(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip()) and not _is_placeholder_text(value)
    if _is_non_empty_string_list(value):
        return any(not _is_placeholder_text(item) for item in value)
    if not isinstance(value, dict) or not value:
        return False
    for nested in value.values():
        if _structured_evidence_present(nested):
            return True
    return False


def _manifest_field_has_evidence(manifest: dict[str, Any], *field_names: str) -> bool:
    return any(_structured_evidence_present(manifest.get(field_name)) for field_name in field_names)


def _validate_mcp_memory_update_when_relevant(manifest: dict[str, Any]) -> None:
    value = manifest.get("mcp_memory_updated_when_relevant")
    if not isinstance(value, dict):
        raise ValueError("terminal events require mcp_memory_updated_when_relevant object in manifest")

    relevant = value.get("relevant")
    updated = value.get("updated")
    if not isinstance(relevant, bool):
        raise ValueError("terminal events require mcp_memory_updated_when_relevant.relevant boolean")
    if not relevant:
        return
    if updated is not True:
        raise ValueError("terminal events require MCP memory update when relevant")

    evidence_only = {
        key: nested
        for key, nested in value.items()
        if key not in {"relevant", "updated"}
    }
    if not _structured_evidence_present(evidence_only):
        raise ValueError("terminal events require MCP memory update evidence when relevant")


def _commands_from_manifest(manifest: dict[str, Any]) -> list[str]:
    commands: list[str] = []
    for key in ("tests_or_logs", "tests_or_logs_linked"):
        bucket = manifest.get(key)
        if not isinstance(bucket, dict):
            continue
        raw = bucket.get("commands")
        if isinstance(raw, list):
            for command in raw:
                if isinstance(command, str) and command.strip():
                    commands.append(command.strip())
    return commands


def _has_strict_memory_receipt_command(commands: list[str]) -> bool:
    for command in commands:
        lower = command.lower()
        if "python3 tools/memory-context-load.py" not in lower:
            continue
        if "--check" in lower and "--strict" in lower and "--require-proof" in lower:
            return True
    return False


def _has_structured_mcp_context_evidence(manifest: dict[str, Any]) -> bool:
    value = manifest.get("mcp_context_evidence")
    if not isinstance(value, dict):
        return False
    context_pack_id = value.get("context_pack_id")
    context_pack_hash = value.get("context_pack_hash")
    source_refs = value.get("source_refs")
    if not isinstance(context_pack_id, str) or _is_placeholder_text(context_pack_id):
        return False
    if not _CONTEXT_PACK_ID_RE.match(context_pack_id.strip()):
        return False
    if not isinstance(context_pack_hash, str) or _is_placeholder_text(context_pack_hash):
        return False
    if not isinstance(source_refs, list) or not source_refs:
        return False
    return any(isinstance(item, str) and not _is_placeholder_text(item) for item in source_refs)


def _validate_terminal_closeout_manifest(workspace_path: Path, manifest_path: Path) -> Path:
    resolved_manifest = manifest_path.expanduser()
    if not resolved_manifest.is_absolute():
        resolved_manifest = (workspace_path / resolved_manifest).resolve()
    if not resolved_manifest.is_file():
        raise ValueError(f"terminal events require --manifest and file must exist: {resolved_manifest}")

    try:
        payload = json.loads(resolved_manifest.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"terminal events require a valid manifest JSON ({resolved_manifest}:{exc.lineno}:{exc.colno})"
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError("terminal events require manifest root object")

    artifact_paths = payload.get("artifact_paths")
    if not isinstance(artifact_paths, list):
        artifact_paths = payload.get("changed_artifacts")
    has_artifacts = _is_non_empty_string_list(artifact_paths)
    no_artifact_reason = payload.get("no_artifact_reason")
    has_no_artifact_reason = (
        isinstance(no_artifact_reason, str)
        and no_artifact_reason.strip()
        and NO_ARTIFACT_MARKER in no_artifact_reason
    )
    if not has_artifacts and not has_no_artifact_reason:
        raise ValueError(
            "terminal events require artifact paths or explicit NO_ARTIFACT reason in manifest"
        )

    tests_evidence_ok = any(
        _structured_evidence_present(payload.get(field_name))
        for field_name in ("tests_or_logs", "tests_or_logs_linked")
    )
    if not tests_evidence_ok:
        raise ValueError("terminal events require tests/log references in manifest")

    if not _manifest_field_has_evidence(payload, "handoff_or_ledger_updated", "handoff_or_ledger_paths"):
        raise ValueError("terminal events require updated local ledger/handoff evidence in manifest")
    if not _manifest_field_has_evidence(payload, "agent_outputs_collected", "agent_output_paths"):
        raise ValueError("terminal events require agent output collection evidence in manifest")
    _validate_mcp_memory_update_when_relevant(payload)

    commands = _commands_from_manifest(payload)
    mcp_context_ok = _has_structured_mcp_context_evidence(payload) or _has_strict_memory_receipt_command(commands)
    if not mcp_context_ok:
        raise ValueError(
            "terminal events require MCP memory/context evidence in manifest "
            "(mcp_context_evidence or strict memory-context-load receipt command)"
        )
    return resolved_manifest.resolve()


def workspace_log_path(workspace: Path | str) -> Path:
    return Path(workspace).expanduser().resolve() / DEFAULT_LOG_REL


def _ensure_json_serializable(value: Any, *, field: str) -> Any:
    try:
        json.dumps(value)
    except TypeError as exc:
        raise ValueError(f"{field} must be JSON serializable") from exc
    return value


def build_event_row(
    *,
    workspace: Path | str,
    event: str,
    agent: str | None = None,
    task: str | None = None,
    note: str | None = None,
    details: Any = None,
    closeout_manifest: Path | str | None = None,
    now_fn: Callable[[], str] | None = None,
) -> dict[str, Any]:
    workspace_path = Path(workspace).expanduser().resolve()
    event_name = _normalize_text(event)
    if event_name is None:
        raise ValueError("event must be a non-empty string")
    event_name = event_name.lower()
    if event_name not in DEFAULT_EVENTS:
        raise ValueError(f"event must be one of: {', '.join(DEFAULT_EVENTS)}")
    closeout_manifest_path: Path | None = None
    if event_name in TERMINAL_EVENTS:
        if closeout_manifest is None:
            raise ValueError("event complete/close requires --manifest closeout proof")
        closeout_manifest_path = _validate_terminal_closeout_manifest(
            workspace_path,
            Path(closeout_manifest),
        )

    row: dict[str, Any] = {
        "schema": SCHEMA,
        "ts": (now_fn or _utcnow)(),
        "event": event_name,
        "workspace": str(workspace_path),
    }
    if closeout_manifest_path is not None:
        row["closeout_manifest"] = str(closeout_manifest_path)
    agent_text = _normalize_text(agent)
    if agent_text is not None:
        row["agent"] = agent_text
    task_text = _normalize_text(task)
    if task_text is not None:
        row["task"] = task_text
    note_text = _normalize_text(note)
    if note_text is not None:
        row["note"] = note_text
    if details is not None:
        row["details"] = _ensure_json_serializable(details, field="details")
    return row


def append_event(
    *,
    workspace: Path | str,
    event: str,
    agent: str | None = None,
    task: str | None = None,
    note: str | None = None,
    details: Any = None,
    closeout_manifest: Path | str | None = None,
    log_path: Path | None = None,
    now_fn: Callable[[], str] | None = None,
) -> dict[str, Any]:
    workspace_path = Path(workspace).expanduser().resolve()
    if not workspace_path.is_dir():
        raise ValueError(f"workspace not found: {workspace_path}")

    row = build_event_row(
        workspace=workspace_path,
        event=event,
        agent=agent,
        task=task,
        note=note,
        details=details,
        closeout_manifest=closeout_manifest,
        now_fn=now_fn,
    )
    path = log_path or workspace_log_path(workspace_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    return row


def read_rows(log_path: Path | str) -> tuple[list[dict[str, Any]], list[str]]:
    path = Path(log_path)
    if not path.is_file():
        return [], []

    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"{path}:{line_no}: invalid JSON: {exc.msg}")
            continue
        if not isinstance(value, dict):
            errors.append(f"{path}:{line_no}: line is not a JSON object")
            continue
        rows.append(value)
    return rows, errors


def summarize_log(log_path: Path | str) -> dict[str, Any]:
    rows, errors = read_rows(log_path)
    event_counts: Counter[str] = Counter()
    agent_counts: Counter[str] = Counter()
    task_counts: Counter[str] = Counter()
    latest_ts: dt.datetime | None = None
    latest_raw: str | None = None

    for row in rows:
        event = _normalize_text(row.get("event")) or "_unknown"
        agent = _normalize_text(row.get("agent")) or "_unknown"
        task = _normalize_text(row.get("task")) or "_unknown"
        event_counts[event] += 1
        agent_counts[agent] += 1
        task_counts[task] += 1

        ts = _parse_iso(row.get("ts") or row.get("timestamp") or row.get("updated_at"))
        if ts is None:
            continue
        if latest_ts is None or ts > latest_ts:
            latest_ts = ts
            latest_raw = row.get("ts") or row.get("timestamp") or row.get("updated_at")

    def as_sorted_map(counter: Counter[str]) -> dict[str, int]:
        return {key: counter[key] for key in sorted(counter)}

    return {
        "schema": SCHEMA,
        "log_path": str(Path(log_path)),
        "rows": len(rows),
        "malformed_rows": len(errors),
        "last_updated": latest_raw,
        "by_event": as_sorted_map(event_counts),
        "by_agent": as_sorted_map(agent_counts),
        "by_task": as_sorted_map(task_counts),
    }


def _format_text(summary: dict[str, Any]) -> str:
    lines = [
        f"rows: {summary['rows']}",
        f"malformed_rows: {summary['malformed_rows']}",
        f"last_updated: {summary['last_updated'] or 'null'}",
        "by_event:",
    ]
    for key, value in summary["by_event"].items():
        lines.append(f"  {key}: {value}")
    lines.append("by_agent:")
    for key, value in summary["by_agent"].items():
        lines.append(f"  {key}: {value}")
    lines.append("by_task:")
    for key, value in summary["by_task"].items():
        lines.append(f"  {key}: {value}")
    return "\n".join(lines)


def _cmd_append(args: argparse.Namespace) -> int:
    row = append_event(
        workspace=args.workspace,
        event=args.event,
        agent=args.agent,
        task=args.task,
        note=args.note,
        closeout_manifest=args.manifest,
    )
    print(json.dumps(row, indent=2, sort_keys=True))
    return 0


def _cmd_summary(args: argparse.Namespace) -> int:
    summary = summarize_log(workspace_log_path(args.workspace))
    if args.format == "text":
        print(_format_text(summary))
    else:
        print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    append = sub.add_parser("append", help="append one cycle event to the workspace JSONL log")
    append.add_argument("--workspace", required=True, type=Path, help="audit workspace path")
    append.add_argument("--event", required=True, help="event name: spawn, complete, close, verify, no_artifact")
    append.add_argument("--agent", help="agent label")
    append.add_argument("--task", help="task label")
    append.add_argument("--note", help="optional free-form note")
    append.add_argument(
        "--manifest",
        help=(
            "required for event=complete|close: finalization manifest path "
            "proving artifact/no-artifact, tests/log refs, and MCP context evidence"
        ),
    )
    append.set_defaults(func=_cmd_append)

    summary = sub.add_parser("summary", help="read the workspace log and emit counts")
    summary.add_argument("--workspace", required=True, type=Path, help="audit workspace path")
    summary.add_argument("--format", choices=("json", "text"), default="json", help="output format")
    summary.set_defaults(func=_cmd_summary)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ValueError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
