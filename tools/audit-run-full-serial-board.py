#!/usr/bin/env python3
"""Cross-workspace serial board for audit-run-full.

Read-only by default. This tool answers the operator question "what is running,
what is certified, and what exact command comes next?" across existing audit
workspaces.
It may print mutating next-action commands, but it never executes them.

RELATED TOOLS:
- tools/audit-run-full-status.py: authoritative per-workspace certification
  status. This board calls it only when --live-status is set.
- tools/operator-status-surface.py: rich single-workspace operator page. This
  board is narrower and cross-workspace.
- tools/queue-next.py: global task queue. This board is driven by workspace
  run manifests instead of the perpetual queue.
- tools/hunt-orchestrate.py: deterministic hunt lane runner. This board only
  reports the next command.
- tools/swarm-orchestrator.py: worker fanout. This board reports serial audit
  run state and leaves fanout to the swarm tooling.

Schema: auditooor.audit_run_full_serial_board.v1.
"""
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.audit_run_full_serial_board.v1"
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_AUDITS_ROOT = Path.home() / "audits"
RUN_MANIFEST_REL = Path(".auditooor") / "audit_run_full_manifest.jsonl"
PIPELINE_MANIFEST_REL = Path(".auditooor") / "production_pipeline_manifest.json"
REPAIR_SIDECAR_GLOBS = ("*next_audit_run_command*.json", "*repair_command_plan*.json")
DISCOVERY_THRESHOLD = 4
DISCOVERY_NAME_DENY = {
    "--help",
    "<project>",
    "acme",
    "foo",
    "nonexistent-workspace",
    "sample",
    "smoketest",
    "ws",
    "x",
}
DISCOVERY_PREFIX_DENY = ("test-", "bar-", "prb-proxy-fwdtest")
DISCOVERY_FILE_WEIGHTS = {
    "INTAKE_BASELINE.md": 3,
    "engage_report.md": 3,
    "AUDIT_PIN.txt": 2,
    "candidate.json": 2,
    "SCOPE.md": 2,
    "SEVERITY.md": 2,
    "targets.tsv": 1,
    "PRIOR_CONCERNS.md": 1,
}
DISCOVERY_DIR_WEIGHTS = {
    "submissions": 2,
    ".audit_logs": 1,
    "agent_outputs": 1,
    "mining_rounds": 1,
    "poc-tests": 1,
    "prior_audits": 1,
    "reports": 1,
    "scope_review": 1,
    "swarm": 1,
}
DISCOVERY_SOURCE_MARKERS = (
    "Cargo.toml",
    "foundry.toml",
    "go.mod",
    "package.json",
    "contracts",
    "repo",
    "src",
    "test",
)

PASS_EVENTS = {"stage-pass"}
WARN_EVENTS = {"stage-warn"}
FAIL_EVENTS = {"stage-fail", "fail", "error"}
COMPLETE_EVENTS = {"complete"}
STAGE_TERMINAL_EVENTS = PASS_EVENTS | WARN_EVENTS | FAIL_EVENTS


@dataclass(frozen=True)
class ProcessInfo:
    pid: str
    elapsed: str
    command: str


def read_jsonl(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    if not path.exists():
        return rows, errors
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"{path}:{lineno}: {exc}")
            continue
        if isinstance(payload, dict):
            rows.append(payload)
        else:
            errors.append(f"{path}:{lineno}: row is not an object")
    return rows, errors


def read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def latest_run_rows(rows: list[dict[str, Any]]) -> tuple[str | None, list[dict[str, Any]]]:
    latest_start_index: int | None = None
    latest_run_id: str | None = None
    for index, row in enumerate(rows):
        if row.get("event") == "start":
            latest_start_index = index
            run_id = row.get("run_id")
            latest_run_id = str(run_id) if run_id else None
    if latest_start_index is None:
        return latest_run_id, rows
    sliced = rows[latest_start_index:]
    if latest_run_id is None:
        return latest_run_id, sliced
    return latest_run_id, [
        row for row in sliced
        if row.get("run_id") in {latest_run_id, None} or row.get("event") == "start"
    ]


def stage_statuses(run_rows: list[dict[str, Any]]) -> dict[str, str]:
    statuses: dict[str, str] = {}
    for row in run_rows:
        stage = row.get("stage")
        event = row.get("event")
        if not stage or not event:
            continue
        if event == "stage-start" or event in STAGE_TERMINAL_EVENTS:
            statuses[str(stage)] = str(event)
    return statuses


def active_stage_from_rows(run_rows: list[dict[str, Any]]) -> str | None:
    statuses = stage_statuses(run_rows)
    for row in reversed(run_rows):
        stage = row.get("stage")
        if not stage:
            continue
        if statuses.get(str(stage)) == "stage-start":
            return str(stage)
        return None
    return None


def run_ps() -> str:
    proc = subprocess.run(
        ["ps", "-axo", "pid,etime,command"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    return proc.stdout


def _split_command_words(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def _is_make_executable(word: str) -> bool:
    return Path(word).name in {"make", "gmake"}


def _make_command_tail(words: list[str]) -> list[str] | None:
    for index, word in enumerate(words):
        if not _is_make_executable(word):
            continue
        prefix = words[:index]
        if not prefix:
            return words[index + 1:]
        if Path(prefix[0]).name == "env" and all("=" in item for item in prefix[1:]):
            return words[index + 1:]
        return None
    return None


def _make_tail_is_dry_run(words: list[str]) -> bool:
    return any(word in {"-n", "--just-print", "--dry-run", "--recon"} for word in words)


def _workspace_arg_matches(words: list[str], workspace: Path) -> bool:
    expected = workspace.resolve(strict=False)
    for word in words:
        if not word.startswith("WS="):
            continue
        raw = word.split("=", 1)[1].strip()
        if not raw:
            continue
        try:
            if Path(raw).expanduser().resolve(strict=False) == expected:
                return True
        except OSError:
            continue
    return False


def _is_make_audit_run_full_for_workspace(command: str, workspace: Path) -> bool:
    words = _split_command_words(command)
    tail = _make_command_tail(words)
    if tail is None:
        return False
    if _make_tail_is_dry_run(tail):
        return False
    return "audit-run-full" in tail and _workspace_arg_matches(tail, workspace)


def active_serial_processes_from_ps(ps_text: str, workspace: Path) -> list[ProcessInfo]:
    out: list[ProcessInfo] = []
    for line in ps_text.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) < 3 or not parts[0].isdigit():
            continue
        command = parts[2]
        if not _is_make_audit_run_full_for_workspace(command, workspace):
            continue
        out.append(ProcessInfo(pid=parts[0], elapsed=parts[1], command=command))
    return out


def workspace_name_denied(name: str) -> bool:
    return name in DISCOVERY_NAME_DENY or name.startswith(DISCOVERY_PREFIX_DENY)


def workspace_discovery_score(child: Path) -> int:
    if workspace_name_denied(child.name):
        return -100
    score = 0
    for relative, weight in DISCOVERY_FILE_WEIGHTS.items():
        if (child / relative).exists():
            score += weight
    for relative, weight in DISCOVERY_DIR_WEIGHTS.items():
        if (child / relative).exists():
            score += weight
    if (child / ".auditooor" / "repo_strategy.json").exists():
        score += 1
    if (child / ".auditooor" / "impact_contracts.json").exists():
        score += 1
    if (child / ".auditooor" / "commit_lifecycle_ledger.json").exists():
        score += 1
    if any((child / marker).exists() for marker in DISCOVERY_SOURCE_MARKERS):
        score += 1
    return score


def discover_workspaces(audits_root: Path, include_no_manifest: bool = False) -> list[Path]:
    if not audits_root.exists():
        return []
    workspaces: list[Path] = []
    for child in sorted(audits_root.iterdir()):
        if not child.is_dir():
            continue
        has_run = (child / RUN_MANIFEST_REL).exists()
        has_pipeline = (child / PIPELINE_MANIFEST_REL).exists()
        has_audit_shape = workspace_discovery_score(child) >= DISCOVERY_THRESHOLD
        if has_run or has_pipeline or (include_no_manifest and has_audit_shape):
            workspaces.append(child.resolve())
    return workspaces


def status_command(workspace: Path) -> str:
    return f"python3 tools/audit-run-full-status.py {shlex.quote(str(workspace))} --json"


def launch_command(workspace: Path) -> str:
    return (
        "AUDIT_RUN_FULL_ENFORCE_AUTONOMOUS_PROOF_CONVERSION=0 "
        "ENFORCE_AUTONOMOUS_PROOF_CONVERSION=0 "
        f"make audit-run-full WS={shlex.quote(str(workspace))} "
        "STRICT=1 EXECUTE_READY=1 JSON=1 TOP_N=10 MAX_FUNCTIONS=0"
    )


def mcp_refresh_command(workspace: Path) -> str:
    return f"bash tools/auditooor-session-start.sh {shlex.quote(str(workspace))}"


def intake_repair_command(workspace: Path) -> str:
    quoted = shlex.quote(str(workspace))
    return (
        f"python3 tools/engage.py --workspace {quoted} "
        "--stage intake-baseline --summary"
    )


def hunt_coverage_command(workspace: Path) -> str:
    # hunt-coverage-gate persists G15 sidecars. The board only emits read-only checks.
    return status_command(workspace)


def hunt_completeness_command(workspace: Path) -> str:
    return f"python3 tools/hunt-completeness-check.py {shlex.quote(str(workspace))} --json"


def command_kind(action: str) -> str:
    if action in {
        "wait-active",
        "certified",
        "certification-check",
        "recheck-hunt-completeness",
        "inspect-hunt-coverage",
        "inspect-failed-stage",
        "inspect-partial-run",
    }:
        return "read-only"
    return "workspace-mutating"


def load_operator_repair_commands(workspace: Path) -> list[dict[str, Any]]:
    auditooor_dir = workspace / ".auditooor"
    if not auditooor_dir.exists():
        return []
    out: list[dict[str, Any]] = []
    seen_commands: set[str] = set()
    paths: list[Path] = []
    for pattern in REPAIR_SIDECAR_GLOBS:
        paths.extend(sorted(auditooor_dir.glob(pattern)))
    for path in sorted(set(paths)):
        payload = read_json(path)
        if not payload:
            continue
        if isinstance(payload.get("next_command"), str):
            command = str(payload["next_command"])
            if command not in seen_commands:
                out.append({
                    "label": "repair_command",
                    "command": command,
                    "command_kind": "workspace-mutating",
                    "source": str(path),
                    "safe_to_run_without_touching_submissions": bool(
                        payload.get("safe_to_run_without_touching_submissions") is True
                    ),
                    "reason": "; ".join(str(item) for item in payload.get("blockers", [])[:2])
                    if isinstance(payload.get("blockers"), list)
                    else "",
                })
                seen_commands.add(command)
        minimal = payload.get("minimal_next_command")
        if isinstance(minimal, dict) and isinstance(minimal.get("command"), str):
            command = str(minimal["command"])
            if command not in seen_commands:
                out.append({
                    "label": "side_effect_reduced_repair_command",
                    "command": command,
                    "command_kind": "workspace-mutating",
                    "source": str(path),
                    "safe_to_run_without_touching_submissions": any(
                        "No submission draft edits" in str(item)
                        for item in minimal.get("expected_non_outputs", [])
                    )
                    if isinstance(minimal.get("expected_non_outputs"), list)
                    else False,
                    "reason": str(minimal.get("intent") or ""),
                })
                seen_commands.add(command)
    return out


def load_live_status(workspace: Path, timeout: int = 90) -> dict[str, Any] | None:
    try:
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "audit-run-full-status.py"), str(workspace), "--json"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "status_error": f"audit-run-full-status timed out after {timeout}s",
            "status_returncode": 124,
        }
    if proc.returncode != 0:
        return {
            "status_error": proc.stderr.strip() or proc.stdout.strip(),
            "status_returncode": proc.returncode,
        }
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return {"status_error": str(exc), "status_returncode": proc.returncode}
    return payload if isinstance(payload, dict) else None


def classify_next_action(
    workspace: Path,
    *,
    latest_event: str | None,
    latest_stage: str | None,
    active_stage: str | None,
    active_processes: list[ProcessInfo],
    live_status: dict[str, Any] | None,
) -> tuple[str, str, str]:
    if active_processes:
        return (
            "wait-active",
            status_command(workspace),
            "serial audit-run-full process is active",
        )

    if live_status:
        if live_status.get("certification_complete") is True:
            return (
                "certified",
                status_command(workspace),
                "audit-run-full certification is complete",
            )
        blockers = live_status.get("certification_blockers") or []
        status = str(live_status.get("status") or "")
        live_deep = live_status.get("live_deep_freshness") or {}
        if live_deep.get("verdict") == "fail-stale-deep-manifest":
            return (
                "rerun-serial-for-fresh-deep",
                launch_command(workspace),
                "deep-engine manifests are stale for the current run",
            )
        if (
            "missing-current-run-deep-proof" in blockers
            or "missing-deep-proof" in blockers
            or "deep-proof-missing" in blockers
        ):
            return (
                "rerun-serial-for-fresh-deep",
                launch_command(workspace),
                "latest complete run is missing current-run deep proof",
            )
        if status == "bounded-complete" or any("bounded" in str(item) for item in blockers):
            return (
                "rerun-serial",
                launch_command(workspace),
                "latest run was bounded and cannot certify full scope",
            )
        if blockers == ["latest-run-not-terminal-complete"]:
            return (
                "rerun-serial",
                launch_command(workspace),
                "latest run is not terminal complete",
            )

    if latest_event == "complete":
        return (
            "certification-check",
            status_command(workspace),
            "manifest has a terminal complete row",
        )

    if latest_event in FAIL_EVENTS:
        if latest_stage == "mcp-preflight":
            return (
                "refresh-mcp-preflight",
                mcp_refresh_command(workspace),
                "latest run failed at mcp-preflight",
            )
        if latest_stage == "intake-truth":
            return (
                "repair-intake",
                intake_repair_command(workspace),
                "latest run failed at intake-truth",
            )
        if latest_stage == "hunt-coverage":
            return (
                "inspect-hunt-coverage",
                hunt_coverage_command(workspace),
                "latest run failed at hunt-coverage",
            )
        if latest_stage == "hunt-full":
            return (
                "recheck-hunt-completeness",
                hunt_completeness_command(workspace),
                "latest run failed at hunt-full",
            )
        return (
            "inspect-failed-stage",
            status_command(workspace),
            f"latest run failed at {latest_stage or 'unknown-stage'}",
        )

    if active_stage:
        return (
            "inspect-partial-run",
            status_command(workspace),
            f"manifest has an unterminated {active_stage} stage and no active process",
        )

    if latest_event in WARN_EVENTS:
        return (
            "inspect-partial-run",
            status_command(workspace),
            f"manifest ended on advisory warning at {latest_stage or 'unknown-stage'}",
        )

    return (
        "refresh-mcp-preflight",
        mcp_refresh_command(workspace),
        "no terminal audit-run-full certification found; refresh MCP before serial launch",
    )


def summarize_workspace(
    workspace: Path,
    *,
    ps_text: str,
    live_status: bool = False,
) -> dict[str, Any]:
    manifest = workspace / RUN_MANIFEST_REL
    rows, parse_errors = read_jsonl(manifest)
    latest_run_id, run_rows = latest_run_rows(rows)
    latest_row = run_rows[-1] if run_rows else None
    latest_event = str(latest_row.get("event")) if latest_row and latest_row.get("event") else None
    latest_stage = str(latest_row.get("stage")) if latest_row and latest_row.get("stage") else None
    active_stage = active_stage_from_rows(run_rows)
    processes = active_serial_processes_from_ps(ps_text, workspace)
    live_payload = load_live_status(workspace) if live_status and manifest.exists() else None

    if live_payload and isinstance(live_payload.get("latest_run_id"), str):
        latest_run_id = str(live_payload["latest_run_id"])
    if live_payload and isinstance(live_payload.get("status"), str):
        state = str(live_payload["status"])
    elif processes:
        state = "running"
    elif latest_event == "complete":
        state = "complete"
    elif latest_event in FAIL_EVENTS:
        state = "failed"
    elif rows:
        state = "partial"
    else:
        state = "no-run-yet"

    action, command, reason = classify_next_action(
        workspace,
        latest_event=latest_event,
        latest_stage=latest_stage,
        active_stage=active_stage,
        active_processes=processes,
        live_status=live_payload,
    )
    operator_status = classify_operator_status(
        raw_state=state,
        latest_event=latest_event,
        active_processes=processes,
        live_status=live_payload,
        manifest_present=manifest.exists(),
    )
    blockers = []
    if live_payload and isinstance(live_payload.get("certification_blockers"), list):
        blockers = [str(item) for item in live_payload.get("certification_blockers", [])[:3]]
    repair_commands = load_operator_repair_commands(workspace)

    return {
        "workspace": str(workspace),
        "name": workspace.name,
        "operator_status": operator_status,
        "manifest": str(manifest),
        "manifest_present": manifest.exists(),
        "latest_run_id": latest_run_id,
        "latest_event": latest_event,
        "latest_stage": latest_stage,
        "active_stage": active_stage,
        "state": state,
        "active_processes": [
            {"pid": p.pid, "elapsed": p.elapsed, "command": p.command}
            for p in processes
        ],
        "next_action": action,
        "next_command_kind": command_kind(action),
        "next_command": command,
        "next_reason": reason,
        "operator_repair_commands": repair_commands,
        "cert_blockers": blockers,
        "parse_errors": parse_errors,
        "live_status": live_payload,
    }


def classify_operator_status(
    *,
    raw_state: str,
    latest_event: str | None,
    active_processes: list[ProcessInfo],
    live_status: dict[str, Any] | None,
    manifest_present: bool,
) -> str:
    if live_status and live_status.get("certification_complete") is True:
        return "certified"
    if active_processes or raw_state in {"running", "stale-running"}:
        return "running"
    if not manifest_present or raw_state in {"missing", "no-run-yet"}:
        return "no-run"
    if latest_event == "complete" and live_status is None:
        return "failed"
    return "failed"


def compact_reason(row: dict[str, Any]) -> str:
    if row.get("active_processes"):
        return "active process"
    if row.get("operator_status") == "certified":
        return "certified"
    latest_stage = row.get("latest_stage")
    if row.get("latest_event") in FAIL_EVENTS and latest_stage:
        return f"failed at {latest_stage}"
    if row.get("next_action") == "certification-check":
        return "needs status check"
    if row.get("next_action") == "refresh-mcp-preflight":
        return "refresh mcp"
    if row.get("next_action") == "rerun-serial-for-fresh-deep":
        return "fresh deep needed"
    if row.get("next_action") == "rerun-serial":
        return "full rerun"
    if row.get("next_reason"):
        return str(row["next_reason"])
    return ""


def pid_elapsed(row: dict[str, Any]) -> str:
    processes = row.get("active_processes") or []
    if not processes:
        return ""
    first = processes[0]
    pid = first.get("pid", "?")
    elapsed = first.get("elapsed", "?")
    suffix = "" if len(processes) == 1 else f"+{len(processes) - 1}"
    return f"{pid}:{elapsed}{suffix}"


def priority_key(row: dict[str, Any]) -> tuple[int, str]:
    action_order = {
        "wait-active": 0,
        "rerun-serial-for-fresh-deep": 1,
        "rerun-serial": 2,
        "recheck-hunt-completeness": 3,
        "inspect-hunt-coverage": 4,
        "repair-intake": 5,
        "refresh-mcp-preflight": 6,
        "inspect-failed-stage": 7,
        "inspect-partial-run": 8,
        "launch-serial": 9,
        "certification-check": 10,
        "certified": 11,
    }
    return (action_order.get(str(row.get("next_action")), 99), str(row.get("name")))


def render_human(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "No audit workspaces found."
    headers = [
        "workspace",
        "operator_status",
        "raw_state",
        "stage",
        "pid_elapsed",
        "next_action",
        "command_kind",
        "blockers",
        "why",
        "next_command",
    ]
    row_values: list[dict[str, str]] = []
    for row in rows:
        stage = row.get("active_stage") or row.get("latest_stage") or ""
        blockers = ",".join(row.get("cert_blockers") or [])
        row_values.append({
            "workspace": str(row.get("name") or ""),
            "operator_status": str(row.get("operator_status") or ""),
            "raw_state": str(row.get("state") or ""),
            "stage": str(stage),
            "pid_elapsed": pid_elapsed(row),
            "next_action": str(row.get("next_action") or ""),
            "command_kind": str(row.get("next_command_kind") or ""),
            "blockers": blockers,
            "why": compact_reason(row),
            "next_command": str(row.get("next_command") or ""),
        })
    widths = {
        header: max(len(header), *(len(values[header]) for values in row_values))
        for header in headers
    }
    line = "  ".join(h.ljust(widths[h]) for h in headers)
    out = [line, "  ".join("-" * widths[h] for h in headers)]
    for values in row_values:
        out.append("  ".join(str(values[h]).ljust(widths[h]) for h in headers))
    repair_lines = render_repair_sidecars(rows)
    if repair_lines:
        out.extend(["", "Operator repair sidecars:", *repair_lines])
    return "\n".join(out)


def render_repair_sidecars(rows: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    for row in rows:
        repairs = row.get("operator_repair_commands") or []
        if not isinstance(repairs, list):
            continue
        for repair in repairs:
            if not isinstance(repair, dict):
                continue
            label = str(repair.get("label") or "repair_command")
            source = Path(str(repair.get("source") or "")).name
            command = str(repair.get("command") or "")
            if not command:
                continue
            out.append(f"- {row.get('name')}: {label} from {source}: {command}")
    return out


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workspace",
        action="append",
        type=Path,
        help="Workspace path. May be repeated. Defaults to discovering under --audits-root.",
    )
    parser.add_argument(
        "--audits-root",
        type=Path,
        default=DEFAULT_AUDITS_ROOT,
        help="Root directory for workspace discovery.",
    )
    parser.add_argument(
        "--include-no-manifest",
        action="store_true",
        help="Include audit-shaped workspaces with no audit-run-full manifest.",
    )
    parser.add_argument("--live-status", action="store_true", help="Call audit-run-full-status.py per workspace.")
    parser.add_argument("--limit", type=int, default=0, help="Limit returned rows after priority sorting.")
    parser.add_argument("--json", action="store_true", help="Emit JSON.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.workspace:
        workspaces = [p.expanduser().resolve() for p in args.workspace]
    else:
        workspaces = discover_workspaces(
            args.audits_root.expanduser().resolve(),
            include_no_manifest=args.include_no_manifest,
        )
    ps_text = run_ps()
    rows = [
        summarize_workspace(ws, ps_text=ps_text, live_status=args.live_status)
        for ws in workspaces
    ]
    rows = sorted(rows, key=priority_key)
    if args.limit and args.limit > 0:
        rows = rows[: args.limit]
    payload = {
        "schema": SCHEMA,
        "audits_root": str(args.audits_root.expanduser()),
        "live_status": bool(args.live_status),
        "count": len(rows),
        "workspaces": rows,
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render_human(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
