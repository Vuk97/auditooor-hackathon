"""Safe dry-run execution planning for control-plane next actions.

The runner module deliberately does not execute commands.  It converts ranked
next-action rows into replayable dry-run manifests with enough metadata for an
operator or later worker to inspect, approve, and run the command elsewhere.
"""
from __future__ import annotations

import hashlib
import json
import shlex
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "auditooor.control.execution_plan.v1"

CLASS_SAFE_LOCAL = "safe-local"
CLASS_PROOF_RECORDING = "proof-recording"
CLASS_NEEDS_OPERATOR = "needs-operator"
CLASS_BLOCKED = "blocked"

PROOF_RECORDING_TOKENS = {
    "poc-execution-record",
    "deep-counterexample-record",
    "deep-counterexample-collect",
    "source-proof-record.py",
    "live-check-runner.py",
    "live-state-checker.py",
    "submission-packager.py",
    "pre-submit-check.sh",
    "per-finding-oos-check.py",
    "claim-precondition-check.py",
}

OPERATOR_TOKENS = {
    "operator-oos-import.py",
    "record-submission",
    "record-outcome",
    "submit.sh",
    "ledger-sync.sh",
}


def command_hash(command: str, *, cwd: str | Path | None = None, workspace: str | Path | None = None) -> str:
    """Return a stable SHA-256 hash for a command in its replay context."""

    payload = {
        "command": _normalize_command_text(command),
        "cwd": _path_text(cwd),
        "workspace": _path_text(workspace),
        "argv": _split_command(command),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def plan_command(
    command: str,
    *,
    workspace: str | Path,
    cwd: str | Path | None = None,
    action: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Classify one command and return a dry-run command plan row."""

    ws = Path(workspace).expanduser()
    run_cwd = Path(cwd).expanduser() if cwd is not None else Path.cwd()
    argv = _split_command(command)
    blockers = _blocked_reasons(argv, command)
    command_class = _classify(argv, command, blockers)
    row: dict[str, Any] = {
        "command": _normalize_command_text(command),
        "argv": argv,
        "command_hash": command_hash(command, cwd=run_cwd, workspace=ws),
        "classification": command_class,
        "dry_run": True,
        "would_execute": False,
        "workspace": str(ws),
        "cwd": str(run_cwd),
        "blockers": blockers,
    }
    if action:
        row["action"] = _action_summary(action)
    return row


def build_execution_plan(
    workspace: str | Path,
    actions: Iterable[dict[str, Any]],
    *,
    cwd: str | Path | None = None,
) -> dict[str, Any]:
    """Build a replayable dry-run manifest for next-action command rows."""

    rows = [
        plan_command(str(action.get("command") or ""), workspace=workspace, cwd=cwd, action=action)
        for action in actions
        if str(action.get("command") or "").strip()
    ]
    counts: dict[str, int] = {
        CLASS_SAFE_LOCAL: 0,
        CLASS_PROOF_RECORDING: 0,
        CLASS_NEEDS_OPERATOR: 0,
        CLASS_BLOCKED: 0,
    }
    for row in rows:
        counts[str(row["classification"])] = counts.get(str(row["classification"]), 0) + 1

    return {
        "schema": SCHEMA,
        "dry_run": True,
        "would_execute": False,
        "workspace": str(Path(workspace).expanduser()),
        "cwd": str(Path(cwd).expanduser() if cwd is not None else Path.cwd()),
        "command_count": len(rows),
        "counts_by_classification": counts,
        "commands": rows,
    }


def write_execution_plan(
    path: str | Path,
    workspace: str | Path,
    actions: Iterable[dict[str, Any]],
    *,
    cwd: str | Path | None = None,
) -> dict[str, Any]:
    """Write a dry-run manifest and return the payload that was written."""

    payload = build_execution_plan(workspace, actions, cwd=cwd)
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def _classify(argv: list[str], command: str, blockers: list[str]) -> str:
    if blockers:
        return CLASS_BLOCKED
    if _contains_token(argv, OPERATOR_TOKENS):
        return CLASS_NEEDS_OPERATOR
    if _contains_token(argv, PROOF_RECORDING_TOKENS):
        return CLASS_PROOF_RECORDING
    if _make_target(argv) in {
        "record-submission",
        "record-outcome",
    }:
        return CLASS_NEEDS_OPERATOR
    if _make_target(argv) in {
        "poc-execution-record",
        "deep-counterexample-record",
        "deep-counterexample-collect",
    }:
        return CLASS_PROOF_RECORDING
    if "operator" in command.lower() and "import" in command.lower():
        return CLASS_NEEDS_OPERATOR
    return CLASS_SAFE_LOCAL


def _blocked_reasons(argv: list[str], command: str) -> list[str]:
    reasons: list[str] = []
    first = _first_executable(argv)
    lowered = [part.lower() for part in argv]
    text = command.lower()

    if first == "git":
        sub = _git_subcommand(lowered)
        if sub == "push":
            reasons.append("git_push_blocked")
            if _has_force_flag(lowered):
                reasons.append("git_force_push_blocked")
        if sub == "merge":
            reasons.append("git_merge_blocked")
        if sub == "reset" and "--hard" in lowered:
            reasons.append("destructive_git_cleanup_blocked")
        if sub == "clean":
            reasons.append("destructive_git_cleanup_blocked")
        if sub in {"checkout", "restore"} and _looks_like_destructive_checkout(lowered):
            reasons.append("destructive_git_cleanup_blocked")

    if first == "gh":
        sub = _gh_subcommand(lowered)
        if sub in {"workflow", "run", "actions"}:
            reasons.append("github_actions_blocked")
        if sub == "pr":
            reasons.append("github_pr_blocked")

    if first in {"act", "gh-actions"}:
        reasons.append("github_actions_blocked")

    if "github actions" in text or "gh workflow" in text or "gh run" in text:
        reasons.append("github_actions_blocked")
    if "force-push" in text or "force push" in text:
        reasons.append("git_force_push_blocked")
    return sorted(set(reasons))


def _split_command(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return []


def _normalize_command_text(command: str) -> str:
    return " ".join(str(command).strip().split())


def _path_text(path: str | Path | None) -> str:
    if path is None:
        return ""
    return str(Path(path).expanduser())


def _contains_token(argv: list[str], needles: set[str]) -> bool:
    parts = {Path(part).name for part in argv}
    parts.update(argv)
    return bool(parts & needles)


def _make_target(argv: list[str]) -> str:
    if len(argv) >= 2 and Path(argv[0]).name == "make":
        return argv[1]
    return ""


def _first_executable(argv: list[str]) -> str:
    if not argv:
        return ""
    return Path(argv[0]).name.lower()


def _git_subcommand(lowered: list[str]) -> str:
    if not lowered or Path(lowered[0]).name != "git":
        return ""
    for token in lowered[1:]:
        if token.startswith("-"):
            continue
        return token
    return ""


def _gh_subcommand(lowered: list[str]) -> str:
    if not lowered or Path(lowered[0]).name != "gh":
        return ""
    for token in lowered[1:]:
        if token.startswith("-"):
            continue
        return token
    return ""


def _has_force_flag(lowered: list[str]) -> bool:
    return any(token in {"-f", "--force", "--force-with-lease"} for token in lowered)


def _looks_like_destructive_checkout(lowered: list[str]) -> bool:
    if "--" in lowered:
        return True
    return any(token in {"-f", "--force", "--staged", "--worktree"} for token in lowered)


def _action_summary(action: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for key in ("priority", "reason", "artifact", "stop_condition", "proof_boundary"):
        if key in action:
            summary[key] = action[key]
    return summary
