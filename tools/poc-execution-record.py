#!/usr/bin/env python3
"""Record execution evidence for a generated PoC task brief.

This is deliberately small and operator-facing. It turns a dormant
``poc_task_briefs/*.md`` file into a durable execution manifest with the exact
commands attempted, captured output paths, source graph hash, workspace commit,
impact assertion status, and final result.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

# Local import: every emitted manifest carries ``evidence_class`` (item #14).
# An execution manifest with at least one real command attempted is
# ``executed_with_manifest``; a stub manifest (no commands recorded) is
# ``scaffolded_unverified``.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence_class as _evidence_class  # noqa: E402
from lib.foundry_version import build_inventory as _build_foundry_inventory  # noqa: E402


SCHEMA_VERSION = "auditooor.poc_execution_manifest.v1"
FINAL_RESULTS = {"proved", "disproved", "blocked_env", "blocked_path", "needs_human"}
IMPACT_ASSERTIONS = {"exploit_impact", "setup_or_branch_only", "not_demonstrated", "unknown"}


def derive_evidence_class(commands: list[dict[str, Any]], final_result: str) -> str:
    """Return the appropriate ``evidence_class`` for an execution manifest.

    Item #14: a manifest with no commands attempted is still scaffold-only;
    only real run output (``--run`` or recorded ``--command``) earns
    ``executed_with_manifest``. ``human_verified`` requires a separate
    review pass and is not emitted here.
    """
    has_real_run = any(
        isinstance(cmd, dict)
        and cmd.get("status") in {"pass", "fail"}
        for cmd in commands
    )
    has_recorded_run = any(
        isinstance(cmd, dict)
        and cmd.get("status") == "recorded_without_execution"
        for cmd in commands
    )
    if has_real_run:
        return _evidence_class.EXECUTED_WITH_MANIFEST
    if has_recorded_run and final_result in {"proved", "disproved"}:
        # Operator recorded an external run + a definitive verdict. Treat
        # the manifest as executed_with_manifest.
        return _evidence_class.EXECUTED_WITH_MANIFEST
    return _evidence_class.SCAFFOLDED_UNVERIFIED


def slug(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9_.-]+", "-", value)
    return value.strip("-") or "candidate"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def git_head(path: Path) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return proc.stdout.strip() if proc.returncode == 0 else ""
    except OSError:
        return ""


def load_existing(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def clean_join_id(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    text = re.sub(r"[\x00-\x20`]+", "", text)
    if not re.fullmatch(r"[A-Za-z0-9._:\-]{1,200}", text):
        raise SystemExit(f"[poc-execution] ERR invalid proof/detector join id: {value}")
    return text


def workspace_relative_existing(path: Path | None, workspace: Path) -> str:
    if path is None or not path.is_file():
        return ""
    try:
        return path.relative_to(workspace).as_posix()
    except ValueError:
        return ""


def bound_sources(paths: list[Path], workspace: Path) -> list[dict[str, Any]]:
    """Bind replay-relevant source and harness files to the execution record."""

    rows: list[dict[str, Any]] = []
    for raw in paths:
        path = raw.expanduser().resolve()
        if not path.is_file():
            raise SystemExit(f"[poc-execution] ERR bound source not found: {raw}")
        try:
            relative = path.relative_to(workspace).as_posix()
        except ValueError as exc:
            raise SystemExit(f"[poc-execution] ERR bound source outside workspace: {raw}") from exc
        rows.append({"path": relative, "sha256": sha256_file(path), "size": path.stat().st_size})
    return sorted(rows, key=lambda row: row["path"])


def run_command(command: str, cwd: Path, out_dir: Path, index: int) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = out_dir / f"command_{index:03d}.stdout.log"
    stderr_path = out_dir / f"command_{index:03d}.stderr.log"
    started = int(time.time())
    proc = subprocess.run(
        command,
        cwd=str(cwd),
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout_path.write_text(proc.stdout, encoding="utf-8")
    stderr_path.write_text(proc.stderr, encoding="utf-8")
    return {
        "command": command,
        "cwd": str(cwd),
        "started_at_unix": started,
        "exit_code": proc.returncode,
        "status": "pass" if proc.returncode == 0 else "fail",
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }


def recorded_command(command: str, cwd: Path) -> dict[str, Any]:
    return {
        "command": command,
        "cwd": str(cwd),
        "exit_code": None,
        "status": "recorded_without_execution",
        "stdout_path": "",
        "stderr_path": "",
    }


def build_manifest(args: argparse.Namespace) -> tuple[dict[str, Any], Path]:
    ws = args.workspace.expanduser().resolve()
    if not ws.is_dir():
        raise SystemExit(f"[poc-execution] ERR workspace not found: {ws}")
    brief = args.brief.expanduser().resolve()
    if not brief.is_file():
        raise SystemExit(f"[poc-execution] ERR brief not found: {brief}")
    candidate_id = args.candidate_id or brief.stem
    safe_id = slug(candidate_id)
    out_dir = (args.out_dir.expanduser().resolve() if args.out_dir else ws / "poc_execution" / safe_id)
    manifest_path = args.out_json.expanduser().resolve() if args.out_json else out_dir / "execution_manifest.json"
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.final_result == "proved" and args.impact_assertion != "exploit_impact":
        raise SystemExit(
            "[poc-execution] ERR final_result=proved requires --impact-assertion exploit_impact"
        )

    graph = ws / ".auditooor" / "semantic_graph.json"
    detector_action_graph = args.detector_action_graph.expanduser().resolve() if args.detector_action_graph else None
    existing = load_existing(manifest_path)
    commands = []
    if existing:
        commands.extend(existing.get("commands_attempted") or [])
    for cmd in args.command or []:
        commands.append(recorded_command(cmd, args.cwd.expanduser().resolve()))
    start_idx = len(commands) + 1
    for offset, cmd in enumerate(args.run or []):
        commands.append(run_command(cmd, args.cwd.expanduser().resolve(), out_dir, start_idx + offset))

    artifact_paths = sorted(set([str(Path(a).expanduser()) for a in args.artifact or []]))
    for cmd in commands:
        for key in ("stdout_path", "stderr_path"):
            if cmd.get(key):
                artifact_paths.append(str(cmd[key]))

    proof_task_id = clean_join_id(args.proof_task_id)
    bridge_row_id = clean_join_id(args.bridge_row_id)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "candidate_id": candidate_id,
        "brief_path": str(brief),
        "assigned_model": args.assigned_model,
        "workspace": str(ws),
        "workspace_commit": git_head(ws),
        "source_graph_path": str(graph) if graph.is_file() else "",
        "source_graph_sha256": sha256_file(graph) if graph.is_file() else "",
        "proof_task_id": proof_task_id,
        "proof_queue_relationship": "addresses_advisory_work_item" if proof_task_id else "",
        "bridge_row_id": bridge_row_id,
        "bridge_relationship": "addresses_high_impact_execution_bridge_row" if bridge_row_id else "",
        "detector_slug": clean_join_id(args.detector_slug),
        "detector_obligation": clean_join_id(args.detector_obligation),
        "detector_action_graph": workspace_relative_existing(detector_action_graph, ws),
        "detector_action_graph_sha256": sha256_file(detector_action_graph) if detector_action_graph and detector_action_graph.is_file() else "",
        "commands_attempted": commands,
        "foundry_version_inventory": _build_foundry_inventory(ws),
        "artifact_paths": sorted(set(artifact_paths)),
        "bound_sources": bound_sources(args.bound_source or [], ws),
        "impact_assertion": args.impact_assertion,
        "impact_notes": args.impact_notes,
        "final_result": args.final_result,
        "notes": args.notes,
        "updated_at_unix": int(time.time()),
        # Item #14: closeout consumers must NEVER count anything below
        # ``executed_with_manifest`` as proof.
        "evidence_class": derive_evidence_class(commands, args.final_result),
    }
    return manifest, manifest_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--brief", required=True, type=Path)
    parser.add_argument("--candidate-id")
    parser.add_argument("--assigned-model", default="")
    parser.add_argument("--proof-task-id", default="", help="Optional proof_obligation_queue task id this execution record addresses.")
    parser.add_argument("--bridge-row-id", default="", help="Optional High/Critical bridge row id this execution record closes or updates.")
    parser.add_argument("--detector-slug", default="", help="Optional detector slug this execution record addresses.")
    parser.add_argument(
        "--detector-obligation",
        default="",
        help="Optional detector action graph proof obligation id this execution record addresses.",
    )
    parser.add_argument(
        "--detector-action-graph",
        type=Path,
        help="Optional detector action graph JSON path backing this execution record.",
    )
    parser.add_argument("--cwd", type=Path, default=Path.cwd())
    parser.add_argument("--command", action="append", help="Record a command that was already attempted.")
    parser.add_argument("--run", action="append", help="Execute this command and capture stdout/stderr.")
    parser.add_argument("--artifact", action="append", help="Additional artifact path to include.")
    parser.add_argument("--bound-source", action="append", type=Path, help="Workspace source or harness file bound by hash to this execution.")
    parser.add_argument("--impact-assertion", choices=sorted(IMPACT_ASSERTIONS), default="unknown")
    parser.add_argument("--impact-notes", default="")
    parser.add_argument("--final-result", choices=sorted(FINAL_RESULTS), default="needs_human")
    parser.add_argument("--notes", default="")
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    manifest, path = build_manifest(args)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.print_json:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    print(
        f"[poc-execution] OK result={manifest['final_result']} "
        f"impact={manifest['impact_assertion']} json={path}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
