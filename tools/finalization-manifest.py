#!/usr/bin/env python3
"""Build/read a bounded canonical finalization manifest for loop closeout."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.finalization_manifest.v1"
VALIDATION_SCHEMA = "auditooor.finalization_manifest_validation.v1"
SCHEMA_VERSION = 1
NO_ARTIFACT_MARKER = "NO_ARTIFACT"
DEFAULT_RELATIVE_PATH = Path(".auditooor/finalization/current_manifest.json")
AGENT_CYCLE_LOG_RELATIVE_PATH = Path(".auditooor/agent_cycle_log.jsonl")
_PLACEHOLDER_VALUES = {"", "tbd", "todo", "n/a", "na", "none", "null", "-", "`tbd`", "`todo`"}
_CONTEXT_PACK_ID_RE = re.compile(r"^auditooor\.vault_context_pack\.v1:[^:\s]+:[0-9a-f]{16}$")


def _utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_non_empty_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_non_empty_string_list(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(_is_non_empty_text(item) for item in value)


def _is_placeholder_text(value: Any) -> bool:
    if not isinstance(value, str):
        return True
    cleaned = value.strip().strip("`").strip()
    return cleaned.lower() in _PLACEHOLDER_VALUES


def _parse_utc_iso(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip()
    if not text:
        return False
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _normalize_path(path_text: str, workspace: Path) -> str:
    candidate = Path(path_text.replace("\\", "/")).expanduser()
    if not candidate.is_absolute():
        candidate = workspace / candidate
    normalized = candidate.resolve(strict=False)
    try:
        return normalized.relative_to(workspace).as_posix()
    except ValueError:
        return normalized.as_posix()


def _normalize_path_list(raw_values: list[str], workspace: Path) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in raw_values:
        if not _is_non_empty_text(raw):
            continue
        normalized = _normalize_path(raw.strip(), workspace)
        if normalized in seen:
            continue
        seen.add(normalized)
        out.append(normalized)
    return out


def _has_strict_memory_receipt_command(commands: Any) -> bool:
    if not isinstance(commands, list):
        return False
    for command in commands:
        if not isinstance(command, str):
            continue
        lower = command.lower()
        if "python3 tools/memory-context-load.py" not in lower:
            continue
        if "--check" in lower and "--strict" in lower and "--require-proof" in lower:
            return True
    return False


def _has_structured_mcp_context_evidence(value: Any) -> bool:
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


def _atomic_write(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=str(path.parent),
        delete=False,
        prefix=path.name + ".",
        suffix=".tmp",
    )
    try:
        tmp.write(payload)
        tmp.flush()
        os.fsync(tmp.fileno())
    finally:
        tmp.close()
    os.replace(tmp.name, path)


def _parse_agent_cycle_log_summary(log_path: Path) -> dict[str, Any]:
    event_counts: Counter[str] = Counter()
    malformed_rows = 0
    event_count = 0
    last_updated_iso: str | None = None
    last_updated_dt: dt.datetime | None = None

    for raw_line in log_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            malformed_rows += 1
            continue
        if not isinstance(row, dict):
            malformed_rows += 1
            continue

        event_count += 1
        event_name = row.get("event")
        event_key = event_name.strip() if isinstance(event_name, str) and event_name.strip() else "_unknown"
        event_counts[event_key] += 1

        for ts_key in ("ts", "timestamp", "updated_at"):
            ts_raw = row.get(ts_key)
            if not isinstance(ts_raw, str):
                continue
            ts_text = ts_raw.strip()
            if not ts_text:
                continue
            ts_parse = ts_text[:-1] + "+00:00" if ts_text.endswith("Z") else ts_text
            try:
                parsed = dt.datetime.fromisoformat(ts_parse)
            except ValueError:
                continue
            if parsed.tzinfo is None:
                continue
            if last_updated_dt is None or parsed > last_updated_dt:
                last_updated_dt = parsed
                last_updated_iso = ts_text
            break

    return {
        "path": log_path.as_posix(),
        "event_count": event_count,
        "malformed_rows": malformed_rows,
        "counts_by_event": {key: event_counts[key] for key in sorted(event_counts)},
        "last_updated": last_updated_iso,
    }


def build_manifest(args: argparse.Namespace) -> tuple[dict[str, Any], Path]:
    workspace = Path(args.workspace).expanduser().resolve()
    output_path = (
        Path(args.output).expanduser().resolve()
        if args.output
        else (workspace / DEFAULT_RELATIVE_PATH).resolve()
    )
    artifact_paths = _normalize_path_list(args.artifact_path or [], workspace)
    handoff_paths = _normalize_path_list(args.handoff_or_ledger_path or [], workspace)
    agent_output_paths = _normalize_path_list(args.agent_output_path or [], workspace)
    test_log_paths = _normalize_path_list(args.test_log_path or [], workspace)
    mcp_paths = _normalize_path_list(args.mcp_evidence_path or [], workspace)
    task_update_paths = _normalize_path_list(args.task_update_path or [], workspace)
    test_commands = [item.strip() for item in (args.test_command or []) if _is_non_empty_text(item)]
    mcp_notes = [item.strip() for item in (args.mcp_note or []) if _is_non_empty_text(item)]
    source_refs = [item.strip() for item in (args.source_ref or []) if _is_non_empty_text(item)]
    context_pack_id = args.context_pack_id.strip() if _is_non_empty_text(args.context_pack_id) else None
    context_pack_hash = args.context_pack_hash.strip() if _is_non_empty_text(args.context_pack_hash) else None

    no_artifact_reason: str | None = None
    if _is_non_empty_text(args.no_artifact_reason):
        no_artifact_reason = args.no_artifact_reason.strip()
        if NO_ARTIFACT_MARKER not in no_artifact_reason:
            no_artifact_reason = f"{NO_ARTIFACT_MARKER}: {no_artifact_reason}"

    manifest: dict[str, Any] = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "workspace_path": str(workspace),
        "generated_at_utc": args.timestamp or _utc_now_iso(),
        "artifact_paths": artifact_paths,
        "handoff_or_ledger_paths": handoff_paths,
        "agent_output_paths": agent_output_paths,
        "tests_or_logs": {
            "commands": test_commands,
            "logs": test_log_paths,
        },
        "mcp_task_update_evidence": {
            "mcp_paths": mcp_paths,
            "task_update_paths": task_update_paths,
            "notes": mcp_notes,
        },
        # Compatibility aliases so the existing loop gate can consume this directly.
        "changed_artifacts": artifact_paths,
        "handoff_or_ledger_updated": {"paths": handoff_paths},
        "agent_outputs_collected": {"paths": agent_output_paths},
        "tests_or_logs_linked": {
            "commands": test_commands,
            "logs": test_log_paths,
        },
        "mcp_memory_updated_when_relevant": {
            "relevant": True,
            "updated": True,
            "paths": sorted(set(mcp_paths + task_update_paths)),
            "notes": mcp_notes,
        },
    }
    if context_pack_id or context_pack_hash:
        manifest["mcp_context_evidence"] = {
            "context_pack_id": context_pack_id or "TBD",
            "context_pack_hash": context_pack_hash or "TBD",
            "source_refs": source_refs,
        }
    if no_artifact_reason:
        manifest["no_artifact_reason"] = no_artifact_reason

    agent_cycle_log_path = workspace / AGENT_CYCLE_LOG_RELATIVE_PATH
    if agent_cycle_log_path.is_file():
        manifest["agent_cycle_log"] = _parse_agent_cycle_log_summary(agent_cycle_log_path)

    _atomic_write(output_path, json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest, output_path


def _load_manifest(path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, [f"unable to read manifest: {exc}"]
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, [f"manifest is not valid JSON: {exc.msg} at line {exc.lineno} column {exc.colno}"]
    if not isinstance(payload, dict):
        return None, ["manifest root must be a JSON object"]
    return payload, []


def validate_manifest(manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    if manifest.get("schema") != SCHEMA:
        errors.append(f"schema must be {SCHEMA}")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")
    if not _is_non_empty_text(manifest.get("workspace_path")):
        errors.append("workspace_path is required")
    if not _parse_utc_iso(manifest.get("generated_at_utc")):
        errors.append("generated_at_utc must be an ISO-8601 UTC timestamp")

    artifact_paths = manifest.get("artifact_paths")
    if not isinstance(artifact_paths, list):
        errors.append("artifact_paths must be a list")
    no_artifact_reason = manifest.get("no_artifact_reason")
    if no_artifact_reason is not None and not _is_non_empty_text(no_artifact_reason):
        errors.append("no_artifact_reason must be a non-empty string when present")
    if isinstance(artifact_paths, list):
        if artifact_paths and not _is_non_empty_string_list(artifact_paths):
            errors.append("artifact_paths must contain only non-empty strings")
        if not artifact_paths:
            if not _is_non_empty_text(no_artifact_reason):
                errors.append("artifact_paths requires entries unless no_artifact_reason is provided")
            elif NO_ARTIFACT_MARKER not in str(no_artifact_reason):
                errors.append(f"no_artifact_reason must include {NO_ARTIFACT_MARKER}")

    handoff = manifest.get("handoff_or_ledger_paths")
    if not _is_non_empty_string_list(handoff):
        errors.append("handoff_or_ledger_paths must be a non-empty string list")

    agent = manifest.get("agent_output_paths")
    if not _is_non_empty_string_list(agent):
        errors.append("agent_output_paths must be a non-empty string list")

    tests_or_logs = manifest.get("tests_or_logs")
    if not isinstance(tests_or_logs, dict):
        errors.append("tests_or_logs must be an object")
    else:
        commands = tests_or_logs.get("commands")
        logs = tests_or_logs.get("logs")
        has_commands = _is_non_empty_string_list(commands)
        has_logs = _is_non_empty_string_list(logs)
        if commands is not None and not (isinstance(commands, list) and all(_is_non_empty_text(v) for v in commands)):
            errors.append("tests_or_logs.commands must be a string list when present")
        if logs is not None and not (isinstance(logs, list) and all(_is_non_empty_text(v) for v in logs)):
            errors.append("tests_or_logs.logs must be a string list when present")
        if not has_commands and not has_logs:
            errors.append("tests_or_logs must include non-empty commands or logs")

    mcp_task_update = manifest.get("mcp_task_update_evidence")
    if not isinstance(mcp_task_update, dict):
        errors.append("mcp_task_update_evidence must be an object")
    else:
        buckets = []
        for key in ("mcp_paths", "task_update_paths", "notes"):
            value = mcp_task_update.get(key)
            if value is not None and not (isinstance(value, list) and all(_is_non_empty_text(v) for v in value)):
                errors.append(f"mcp_task_update_evidence.{key} must be a string list when present")
            if _is_non_empty_string_list(value):
                buckets.append(key)
        if not buckets:
            errors.append("mcp_task_update_evidence must include at least one non-empty evidence list")

    mcp_context_evidence = manifest.get("mcp_context_evidence")
    tests_or_logs_obj = manifest.get("tests_or_logs")
    commands = tests_or_logs_obj.get("commands") if isinstance(tests_or_logs_obj, dict) else None
    if mcp_context_evidence is not None and not _has_structured_mcp_context_evidence(mcp_context_evidence):
        errors.append(
            "mcp_context_evidence, when present, must include non-placeholder "
            "context_pack_id/context_pack_hash/source_refs"
        )
    elif mcp_context_evidence is None and not _has_strict_memory_receipt_command(commands):
        errors.append(
            "manifest must include mcp_context_evidence "
            "(context_pack_id/context_pack_hash/source_refs) or a strict "
            "python3 tools/memory-context-load.py --check --strict --require-proof command"
        )

    return errors


def _render_result(result: dict[str, Any], *, pretty: bool) -> None:
    if pretty:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(json.dumps(result, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)

    p_build = sub.add_parser("build", help="Build and write a canonical finalization manifest")
    p_build.add_argument("--workspace", required=True, help="Workspace root path")
    p_build.add_argument("--output", help="Manifest path (default: <workspace>/.auditooor/finalization/current_manifest.json)")
    p_build.add_argument("--artifact-path", action="append", default=[], help="Artifact path changed in this slice")
    p_build.add_argument("--handoff-or-ledger-path", action="append", default=[], help="Handoff/ledger path")
    p_build.add_argument("--agent-output-path", action="append", default=[], help="Agent output path")
    p_build.add_argument("--test-command", action="append", default=[], help="Verification command")
    p_build.add_argument("--test-log-path", action="append", default=[], help="Verification log path")
    p_build.add_argument("--mcp-evidence-path", action="append", default=[], help="MCP evidence path")
    p_build.add_argument("--task-update-path", action="append", default=[], help="Task update evidence path")
    p_build.add_argument("--mcp-note", action="append", default=[], help="MCP/task evidence note")
    p_build.add_argument("--context-pack-id", help="MCP context pack id (auditooor.vault_context_pack.v1:...)")
    p_build.add_argument("--context-pack-hash", help="MCP context pack hash")
    p_build.add_argument("--source-ref", action="append", default=[], help="MCP source ref evidence path/URI")
    p_build.add_argument("--no-artifact-reason", help=f"Reason with optional {NO_ARTIFACT_MARKER} marker")
    p_build.add_argument("--timestamp", help="Override generated_at_utc timestamp")
    p_build.add_argument("--json", action="store_true", help="Pretty JSON output")

    p_read = sub.add_parser("read", help="Read and validate an existing manifest")
    p_read.add_argument("--manifest", required=True, help="Path to a manifest JSON file")
    p_read.add_argument("--json", action="store_true", help="Pretty JSON output")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.mode == "build":
        manifest, path = build_manifest(args)
        errors = validate_manifest(manifest)
        status = "pass" if not errors else "fail"
        result = {
            "schema": VALIDATION_SCHEMA,
            "mode": "build",
            "status": status,
            "passed": not errors,
            "manifest_path": str(path),
            "errors": errors,
            "manifest": manifest,
        }
        _render_result(result, pretty=args.json)
        return 0 if not errors else 1

    manifest_path = Path(args.manifest).expanduser().resolve()
    manifest, load_errors = _load_manifest(manifest_path)
    if load_errors:
        result = {
            "schema": VALIDATION_SCHEMA,
            "mode": "read",
            "status": "malformed_input",
            "passed": False,
            "manifest_path": str(manifest_path),
            "errors": load_errors,
        }
        _render_result(result, pretty=args.json)
        return 2

    errors = validate_manifest(manifest)
    status = "pass" if not errors else "fail"
    result = {
        "schema": VALIDATION_SCHEMA,
        "mode": "read",
        "status": status,
        "passed": not errors,
        "manifest_path": str(manifest_path),
        "errors": errors,
        "manifest": manifest,
    }
    _render_result(result, pretty=args.json)
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
