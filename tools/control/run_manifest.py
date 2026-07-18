"""Normalized run-manifest adapter for future auditooorctl execution records.

This module does not execute commands.  It only converts a planned command and
optional completed-process metadata into the auditooor control run-manifest
shape that later command runners can persist after execution.
"""
from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any, Mapping, Sequence

from tools.control.runner import command_hash


SCHEMA = "auditooor.control.run_manifest.v1"

STATUS_PLANNED = "planned"
STATUS_SUCCEEDED = "succeeded"
STATUS_FAILED = "failed"
STATUS_BLOCKED = "blocked"


def build_run_manifest(
    command: str | Sequence[str],
    *,
    cwd: str | Path,
    workspace: str | Path,
    completed: Any | None = None,
    started_at: str | None = None,
    finished_at: str | None = None,
    status: str | None = None,
    exit_code: int | None = None,
    stdout_path: str | Path | None = None,
    stderr_path: str | Path | None = None,
    artifacts: Sequence[str | Path | Mapping[str, Any]] | None = None,
    proof_counted: bool | None = None,
    blocked_reasons: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Return a normalized run manifest without running the command.

    ``completed`` may be a ``subprocess.CompletedProcess``-like object or a
    mapping. Explicit keyword arguments override values found on ``completed``.
    """

    argv = _normalize_argv(command)
    command_text = _command_text(command, argv)
    run_cwd = _path_text(cwd)
    ws = _path_text(workspace)
    meta = _completed_mapping(completed)
    normalized_exit_code = _first_int(exit_code, meta.get("exit_code"), meta.get("returncode"))
    normalized_status = _normalize_status(
        _first_text(status, meta.get("status")),
        exit_code=normalized_exit_code,
        has_completed=completed is not None,
        blocked_reasons=_list_text(blocked_reasons or meta.get("blocked_reasons") or meta.get("blockers")),
    )
    normalized_blockers = _normalize_blocked_reasons(blocked_reasons, meta)
    normalized_proof_counted = meta.get("proof_counted") is True if proof_counted is None else proof_counted

    manifest = {
        "schema": SCHEMA,
        "command_hash": command_hash(command_text, cwd=run_cwd, workspace=ws),
        "argv": argv,
        "cwd": run_cwd,
        "workspace": ws,
        "started_at": _first_text(started_at, meta.get("started_at")),
        "finished_at": _first_text(finished_at, meta.get("finished_at")),
        "status": normalized_status,
        "exit_code": normalized_exit_code,
        "stdout_path": _optional_path_text(stdout_path, meta.get("stdout_path")),
        "stderr_path": _optional_path_text(stderr_path, meta.get("stderr_path")),
        "artifacts": _normalize_artifacts(artifacts if artifacts is not None else meta.get("artifacts")),
        "proof_counted": bool(normalized_proof_counted),
        "blocked_reasons": normalized_blockers,
    }
    if manifest["status"] == STATUS_PLANNED:
        manifest["finished_at"] = None
        manifest["exit_code"] = None
    if manifest["status"] == STATUS_BLOCKED and not manifest["blocked_reasons"]:
        manifest["blocked_reasons"] = ["blocked_without_reason"]
    return manifest


def write_run_manifest(path: str | Path, manifest: Mapping[str, Any]) -> None:
    """Persist a normalized run manifest as deterministic JSON."""

    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(dict(manifest), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _normalize_argv(command: str | Sequence[str]) -> list[str]:
    if isinstance(command, str):
        try:
            return shlex.split(command)
        except ValueError:
            return []
    return [str(part) for part in command]


def _command_text(command: str | Sequence[str], argv: Sequence[str]) -> str:
    if isinstance(command, str):
        return " ".join(command.strip().split())
    return " ".join(shlex.quote(part) for part in argv)


def _completed_mapping(completed: Any | None) -> dict[str, Any]:
    if completed is None:
        return {}
    if isinstance(completed, Mapping):
        return dict(completed)
    names = (
        "args",
        "returncode",
        "exit_code",
        "started_at",
        "finished_at",
        "status",
        "stdout_path",
        "stderr_path",
        "artifacts",
        "proof_counted",
        "blocked_reasons",
        "blockers",
    )
    return {name: getattr(completed, name) for name in names if hasattr(completed, name)}


def _normalize_status(
    value: str | None,
    *,
    exit_code: int | None,
    has_completed: bool,
    blocked_reasons: list[str],
) -> str:
    normalized = (value or "").strip().lower().replace("-", "_")
    if normalized in {"success", "succeeded", "passed", "pass", "ok", "done"}:
        return STATUS_SUCCEEDED
    if normalized in {"fail", "failed", "failure", "error"}:
        return STATUS_FAILED
    if normalized in {"blocked", "blocked_path", "invalid"}:
        return STATUS_BLOCKED
    if normalized in {"planned", "dry_run", "dryrun"}:
        return STATUS_PLANNED
    if blocked_reasons:
        return STATUS_BLOCKED
    if exit_code is not None:
        return STATUS_SUCCEEDED if exit_code == 0 else STATUS_FAILED
    return STATUS_PLANNED if not has_completed else STATUS_FAILED


def _normalize_blocked_reasons(blocked_reasons: Sequence[str] | None, meta: Mapping[str, Any]) -> list[str]:
    raw = blocked_reasons
    if raw is None:
        raw = meta.get("blocked_reasons") or meta.get("blockers") or []
    return sorted(set(_list_text(raw)))


def _normalize_artifacts(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, (str, Path)):
        return [_path_text(raw)]
    artifacts: list[str] = []
    for item in raw:
        if isinstance(item, Mapping):
            path = item.get("path") or item.get("artifact_path") or item.get("file")
            if path:
                artifacts.append(_path_text(path))
        else:
            artifacts.append(_path_text(item))
    return sorted(dict.fromkeys(artifacts))


def _list_text(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, (str, Path)):
        text = str(raw).strip()
        return [text] if text else []
    return [str(item).strip() for item in raw if str(item).strip()]


def _first_text(*values: Any) -> str | None:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def _first_int(*values: Any) -> int | None:
    for value in values:
        if value is None:
            continue
        if isinstance(value, bool):
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return None


def _optional_path_text(*values: Any) -> str | None:
    text = _first_text(*values)
    if text is None:
        return None
    return _path_text(text)


def _path_text(path: Any) -> str:
    return str(Path(str(path)).expanduser())
