#!/usr/bin/env python3
"""Phase-C/Phase-D execution wrapper for Cosmos production-harness readiness.

This tool is execution plumbing only. It gates command execution on:

1) Phase-A planner verdict == ``ready``
2) Phase-B tasks report no blocking gaps and include the runtime compile task
3) Optional Phase-D runtime-marker guard when ``--require-runtime-markers`` is set

When preflight passes, it runs only an explicit ``go test ...`` command and
captures command/cwd/exit/stdout/stderr paths in a durable JSON record.

The optional runtime-marker guard checks that the command transcript contains
machine-readable app-chain observations. It is a realism guard for production
harness work; it still does not claim runtime proof or HIGH+/submission
readiness.

Exit codes:
  0 - command executed and passed
  1 - blocked by preflight gate or command executed and failed
  2 - input/validation error
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.cosmos_production_harness_exec.v1"
TOOL = "cosmos-production-harness-exec"
REPO = Path(__file__).resolve().parent.parent
PLANNER_PATH = REPO / "tools" / "cosmos-production-harness-plan.py"
TASKS_PATH = REPO / "tools" / "cosmos-production-harness-tasks.py"
RUNTIME_TASK_ID = "cosmos-phase-b-runtime-01-compile"
RUNTIME_EVENT_SCHEMA = "auditooor.cosmos_production_harness_runtime_event.v1"
RUNTIME_EVENT_PREFIX = "AUDITOOOR_COSMOS_HARNESS_EVENT "

sys.path.insert(0, str(REPO / "tools"))
try:
    from go_toolchain_env import apply_go_toolchain as _apply_go_toolchain
except Exception:  # pragma: no cover - helper must be a sibling in tools/
    def _apply_go_toolchain(env, cwd, **_kw):  # type: ignore
        return ""
BASE_RUNTIME_EVENTS = ("app_profile", "block_execution", "restart_check", "impact_assertion")
NETWORK_RUNTIME_EVENT = "network_profile"
PERSISTENT_DB_BACKENDS = {"goleveldb", "leveldb", "pebbledb"}
PROOF_BOUNDARY = (
    "Phase-C execution plumbing only. This record captures command execution "
    "state and logs. It is not runtime proof, exploit proof, or HIGH+/submission evidence."
)
RUNTIME_GUARD_BOUNDARY = (
    "Phase-D runtime-marker guard only. Passing markers mean the transcript "
    "contains required self-reported production-harness observations; this is "
    "not independent runtime proof, exploit proof, or HIGH+/submission evidence."
)


def _load_module(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load module from {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_optional(path: Path) -> str:
    return _sha256_file(path) if path.is_file() else ""


def _slug(value: str) -> str:
    out = []
    for ch in value.strip().lower():
        if ch.isalnum() or ch in "._-":
            out.append(ch)
        else:
            out.append("-")
    return "".join(out).strip("-") or "candidate"


def _git_head(path: Path) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except OSError:
        return ""
    return proc.stdout.strip() if proc.returncode == 0 else ""


def _resolve_inside_workspace(path: Path, workspace: Path, field: str) -> Path:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise ValueError(f"{field} must be inside workspace: {resolved}") from exc
    return resolved


def _extract_claim_text(claim_file: Path | None, claim_text: str) -> str:
    combined = claim_text or ""
    if claim_file is None:
        return combined
    if not claim_file.is_file():
        raise ValueError(f"claim-file not found: {claim_file}")
    combined += "\n" + claim_file.read_text(encoding="utf-8", errors="replace")
    return combined


def _validate_go_test_command(command: str, cwd: Path, workspace: Path) -> list[str]:
    if not command.strip():
        raise ValueError("--command is required")
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError as exc:
        raise ValueError(f"invalid command quoting: {exc}") from exc
    if len(tokens) < 2 or tokens[0] != "go" or tokens[1] != "test":
        raise ValueError("command must be an explicit 'go test ...' invocation")
    for token in tokens[2:]:
        if token.startswith("/"):
            raise ValueError("absolute path arguments are not allowed in command")
        if token.startswith("../") or "/../" in token:
            raise ValueError("command path arguments must not escape workspace")
    try:
        cwd.relative_to(workspace)
    except ValueError as exc:
        raise ValueError(f"cwd must be inside workspace: {cwd}") from exc
    return tokens


def _truthy(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "1", "ok", "pass", "passed"}
    if isinstance(value, int):
        return value != 0
    return False


def _nonempty(value: Any) -> bool:
    return value is not None and str(value).strip() != ""


def _normalized_token(value: Any) -> str:
    return "".join(ch for ch in str(value or "").strip().lower() if ch.isalnum())


def _normalized_db_backend(value: Any) -> str:
    return _normalized_token(value).replace("cosmosdb", "")


def _parse_runtime_events(log_paths: list[Path]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    events: list[dict[str, Any]] = []
    parse_errors: list[dict[str, Any]] = []
    for log_path in log_paths:
        if not log_path.is_file():
            continue
        try:
            lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            parse_errors.append({"path": str(log_path), "line": 0, "error": str(exc)})
            continue
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped.startswith(RUNTIME_EVENT_PREFIX):
                continue
            raw = stripped[len(RUNTIME_EVENT_PREFIX) :].strip()
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError as exc:
                parse_errors.append({"path": str(log_path), "line": line_no, "error": f"invalid JSON marker: {exc}"})
                continue
            if not isinstance(parsed, dict):
                parse_errors.append({"path": str(log_path), "line": line_no, "error": "marker JSON must be an object"})
                continue
            parsed["_source_log"] = str(log_path)
            parsed["_source_line"] = line_no
            events.append(parsed)
    return events, parse_errors


def _marker_summary(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "event": str(event.get("event", "")),
        "source_log": str(event.get("_source_log", "")),
        "line": int(event.get("_source_line", 0) or 0),
    }


def _validate_runtime_event(event: dict[str, Any], target_app_chain: str) -> list[str]:
    event_name = str(event.get("event", ""))
    reasons: list[str] = []
    if event.get("schema") != RUNTIME_EVENT_SCHEMA:
        reasons.append(f"schema must be {RUNTIME_EVENT_SCHEMA}")

    if event_name == "app_profile":
        if not _nonempty(event.get("app_chain")):
            reasons.append("app_chain is required")
        if target_app_chain and _normalized_token(target_app_chain) not in _normalized_token(event.get("app_chain")):
            reasons.append(f"app_chain must identify target {target_app_chain}")
        backend = _normalized_db_backend(event.get("db_backend"))
        if backend not in PERSISTENT_DB_BACKENDS:
            reasons.append("db_backend must be GoLevelDB or PebbleDB")
        if not _nonempty(event.get("data_dir")):
            reasons.append("data_dir is required")
        if event.get("private_state_injection") is not False:
            reasons.append("private_state_injection must be false")
    elif event_name == "block_execution":
        if not _nonempty(event.get("height")):
            reasons.append("height is required")
        if not _truthy(event.get("finalize_block")):
            reasons.append("finalize_block must be true")
        if not _truthy(event.get("commit")):
            reasons.append("commit must be true")
        if not (_nonempty(event.get("app_hash")) or _nonempty(event.get("app_hash_after"))):
            reasons.append("app_hash or app_hash_after is required")
    elif event_name == "restart_check":
        if not _truthy(event.get("restarted")):
            reasons.append("restarted must be true")
        if not _truthy(event.get("same_data_dir")):
            reasons.append("same_data_dir must be true")
        if not (_nonempty(event.get("post_restart_assertion")) or _nonempty(event.get("assertion"))):
            reasons.append("post_restart_assertion or assertion is required")
    elif event_name == "impact_assertion":
        if not _nonempty(event.get("assertion")):
            reasons.append("assertion is required")
        if not _nonempty(event.get("observed")):
            reasons.append("observed is required")
    elif event_name == "network_profile":
        count = event.get("validator_count", event.get("validators"))
        try:
            validator_count = int(count)
        except (TypeError, ValueError):
            validator_count = 0
        if validator_count < 2:
            reasons.append("validator_count must be >= 2")
    else:
        reasons.append("unknown runtime event")
    return reasons


def _runtime_guard_skipped(required: bool, target_app_chain: str) -> dict[str, Any]:
    return {
        "required": required,
        "status": "skipped",
        "marker_prefix": RUNTIME_EVENT_PREFIX,
        "event_schema": RUNTIME_EVENT_SCHEMA,
        "target_app_chain": target_app_chain,
        "required_events": [],
        "events_seen": [],
        "missing_events": [],
        "invalid_events": [],
        "parse_errors": [],
        "events_path": "",
        "events_sha256": "",
        "advisory_boundary": RUNTIME_GUARD_BOUNDARY,
    }


def _evaluate_runtime_guard(
    *,
    required: bool,
    execution: dict[str, Any],
    out_dir: Path,
    network_claim: bool,
    target_app_chain: str,
) -> dict[str, Any]:
    if not required:
        return _runtime_guard_skipped(False, target_app_chain)

    required_events = list(BASE_RUNTIME_EVENTS)
    if network_claim:
        required_events.append(NETWORK_RUNTIME_EVENT)

    guard = _runtime_guard_skipped(True, target_app_chain)
    guard["required_events"] = required_events
    if not execution.get("attempted"):
        guard["status"] = "not_attempted"
        guard["missing_events"] = required_events
        return guard

    stdout_path = Path(str(execution.get("stdout_path") or ""))
    stderr_path = Path(str(execution.get("stderr_path") or ""))
    events, parse_errors = _parse_runtime_events([stdout_path, stderr_path])
    valid_by_event: dict[str, list[dict[str, Any]]] = {}
    invalid_events: list[dict[str, Any]] = []
    for event in events:
        reasons = _validate_runtime_event(event, target_app_chain)
        event_name = str(event.get("event", ""))
        if reasons:
            invalid_events.append({**_marker_summary(event), "reasons": reasons})
            continue
        valid_by_event.setdefault(event_name, []).append(event)

    missing = [name for name in required_events if not valid_by_event.get(name)]
    events_path = out_dir / "runtime_observation_events.json"
    events_payload = {
        "schema": "auditooor.cosmos_production_harness_runtime_events.v1",
        "marker_event_schema": RUNTIME_EVENT_SCHEMA,
        "marker_prefix": RUNTIME_EVENT_PREFIX,
        "required_events": required_events,
        "target_app_chain": target_app_chain,
        "events": events,
        "parse_errors": parse_errors,
        "invalid_events": invalid_events,
        "missing_events": missing,
        "advisory_boundary": RUNTIME_GUARD_BOUNDARY,
    }
    events_path.write_text(json.dumps(events_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    guard.update(
        {
            "status": "pass" if not missing and not invalid_events and not parse_errors else "fail",
            "events_seen": [_marker_summary(event) for event in events],
            "missing_events": missing,
            "invalid_events": invalid_events,
            "parse_errors": parse_errors,
            "events_path": str(events_path),
            "events_sha256": _sha256_optional(events_path),
        }
    )
    return guard


def _run_command(tokens: list[str], command: str, cwd: Path, out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = out_dir / "command.stdout.log"
    stderr_path = out_dir / "command.stderr.log"
    env = dict(os.environ)
    # Honor the workspace's pinned Go toolchain (go.work/go.mod) so a dep that only compiles
    # under it is not a silent build_failed on the host default (GOTOOLCHAIN suspected class).
    _apply_go_toolchain(env, cwd, log_prefix="cosmos-production-harness-exec")
    proc = subprocess.run(
        tokens,
        cwd=str(cwd),
        env=env,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout_path.write_text(proc.stdout, encoding="utf-8")
    stderr_path.write_text(proc.stderr, encoding="utf-8")
    return {
        "attempted": True,
        "status": "pass" if proc.returncode == 0 else "fail",
        "exit_code": proc.returncode,
        "command": command,
        "command_argv": tokens,
        "cwd": str(cwd),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }


def build_record(
    *,
    workspace: Path,
    poc_dir: Path,
    candidate_id: str,
    command: str,
    cwd: Path,
    claim_text: str,
    network_claim: bool,
    require_runtime_markers: bool = False,
    target_app_chain: str = "",
    out_json: Path | None,
) -> tuple[dict[str, Any], Path, int]:
    planner = _load_module(PLANNER_PATH, "cosmos_production_harness_plan")
    tasks_mod = _load_module(TASKS_PATH, "cosmos_production_harness_tasks")

    tokens = _validate_go_test_command(command, cwd, workspace)

    out_dir = workspace / "poc_execution" / _slug(candidate_id)
    manifest_path = out_json if out_json is not None else out_dir / "cosmos_production_harness_exec.json"
    manifest_path = manifest_path.expanduser().resolve()
    out_dir = manifest_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    plan = planner.build_plan(poc_dir, claim_text=claim_text, network_claim=network_claim)
    tasks = tasks_mod.build_tasks(plan)
    plan_path = out_dir / "phase_a_plan.json"
    tasks_path = out_dir / "phase_b_tasks.json"
    plan_path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tasks_path.write_text(json.dumps(tasks, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    next_runtime = tasks.get("next_runtime_tasks", [])
    runtime_task_ready = any(
        isinstance(item, dict) and item.get("task_id") == RUNTIME_TASK_ID
        for item in next_runtime
    )
    blocking_gap_count = int(((tasks.get("summary") or {}).get("blocking_gap_count")) or 0)
    phase_a_ready = plan.get("verdict") == "ready"
    phase_b_ready = blocking_gap_count == 0 and runtime_task_ready and tasks.get("source_plan_verdict") == "ready"
    execution_allowed = bool(phase_a_ready and phase_b_ready)
    effective_network_claim = bool((plan.get("claim_signals") or {}).get("network_claim")) if isinstance(plan.get("claim_signals"), dict) else bool(network_claim)

    execution = {
        "attempted": False,
        "status": "blocked_preflight",
        "exit_code": None,
        "command": command,
        "command_argv": tokens,
        "cwd": str(cwd),
        "stdout_path": "",
        "stderr_path": "",
    }
    exit_code = 1
    if execution_allowed:
        execution = _run_command(tokens, command, cwd, out_dir)
        exit_code = 0 if execution["status"] == "pass" else 1

    runtime_guard = _evaluate_runtime_guard(
        required=require_runtime_markers,
        execution=execution,
        out_dir=out_dir,
        network_claim=effective_network_claim,
        target_app_chain=target_app_chain,
    )
    if execution_allowed and execution["status"] == "pass" and runtime_guard["status"] == "fail":
        exit_code = 1

    payload = {
        "schema": SCHEMA,
        "tool": TOOL,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "workspace": str(workspace),
        "workspace_commit": _git_head(workspace),
        "poc_dir": str(poc_dir),
        "candidate_id": candidate_id,
        "runtime_proof_claimed": False,
        "submission_posture": "NOT_SUBMIT_READY",
        "advisory_boundary": PROOF_BOUNDARY,
        "preflight": {
            "phase_a_verdict": plan.get("verdict", ""),
            "phase_a_ready": phase_a_ready,
            "phase_b_source_plan_verdict": tasks.get("source_plan_verdict", ""),
            "phase_b_blocking_gap_count": blocking_gap_count,
            "phase_b_runtime_task_ready": runtime_task_ready,
            "execution_allowed": execution_allowed,
        },
        "runtime_observation_guard": runtime_guard,
        "planner_artifact": {
            "path": str(plan_path),
            "sha256": _sha256_file(plan_path),
            "source_schema": plan.get("schema", ""),
        },
        "phase_b_artifact": {
            "path": str(tasks_path),
            "sha256": _sha256_file(tasks_path),
            "source_schema": tasks.get("schema", ""),
        },
        "execution": execution,
    }
    return payload, manifest_path, exit_code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--poc-dir", required=True, type=Path)
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--claim-file", type=Path)
    parser.add_argument("--claim-text", default="")
    parser.add_argument("--network-claim", action="store_true")
    parser.add_argument(
        "--require-runtime-markers",
        action="store_true",
        help="Require structured AUDITOOOR_COSMOS_HARNESS_EVENT markers in go test stdout/stderr.",
    )
    parser.add_argument(
        "--target-app-chain",
        default="",
        help="Optional app-chain substring the app_profile runtime marker must identify, e.g. dydx.",
    )
    parser.add_argument("--command", required=True, help="Exact explicit go test command to execute.")
    parser.add_argument("--cwd", type=Path, help="Working directory for command execution. Defaults to --poc-dir.")
    parser.add_argument("--out-json", type=Path, help="Optional output record path.")
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    try:
        workspace = args.workspace.expanduser().resolve()
        if not workspace.is_dir():
            raise ValueError(f"workspace not found: {workspace}")

        poc_dir = _resolve_inside_workspace(args.poc_dir, workspace, "poc-dir")
        if not poc_dir.is_dir():
            raise ValueError(f"poc-dir not found: {poc_dir}")

        cwd_input = args.cwd if args.cwd is not None else args.poc_dir
        cwd = _resolve_inside_workspace(cwd_input, workspace, "cwd")
        if not cwd.is_dir():
            raise ValueError(f"cwd not found: {cwd}")

        claim_file = (
            _resolve_inside_workspace(args.claim_file, workspace, "claim-file")
            if args.claim_file is not None
            else None
        )
        out_json = (
            _resolve_inside_workspace(args.out_json, workspace, "out-json")
            if args.out_json is not None
            else None
        )
        claim_text = _extract_claim_text(claim_file, args.claim_text)

        payload, out_path, code = build_record(
            workspace=workspace,
            poc_dir=poc_dir,
            candidate_id=args.candidate_id,
            command=args.command,
            cwd=cwd,
            claim_text=claim_text,
            network_claim=args.network_claim,
            require_runtime_markers=args.require_runtime_markers,
            target_app_chain=args.target_app_chain,
            out_json=out_json,
        )
    except ValueError as exc:
        print(json.dumps({"schema": SCHEMA, "tool": TOOL, "error": str(exc)}, indent=2), file=sys.stderr)
        return 2
    except Exception as exc:
        print(json.dumps({"schema": SCHEMA, "tool": TOOL, "error": str(exc)}, indent=2), file=sys.stderr)
        return 2

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(
        f"[{TOOL}] status={payload['execution']['status']} "
        f"preflight_allowed={payload['preflight']['execution_allowed']} "
        f"runtime_guard={payload['runtime_observation_guard']['status']} json={out_path}",
        file=sys.stderr,
    )
    return code


if __name__ == "__main__":
    raise SystemExit(main())
