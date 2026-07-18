#!/usr/bin/env python3
"""Daily pillar refresh runner.

Refreshes local, deterministic control-plane artifacts across known audit
workspaces:

* ``docs/LIVE_TARGET_REPORT.md`` and ``docs/LIVE_TARGET_REPORT.json``
* invariant ledger indexing/checks, dry-run by default
* P3 anti-pattern catalog validation
* operator action tracker ledger output when available
* V3 status/checkpoint snapshots after the operator ledger refreshes

Default mode avoids LLM/API spend and avoids invariant-ledger mutation. Pass
``--write-invariants`` to allow ``invariant-ledger.py --from-scope`` writes.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_AUDITS_ROOT = Path.home() / "audits"
DEFAULT_REPORT_DIR = REPO_ROOT / "reports" / "pillar_refresh_daily"
SCHEMA = "auditooor.pillar_refresh_daily.v1"


@dataclass
class StepResult:
    name: str
    command: list[str]
    cwd: str
    status: str
    returncode: int | None = None
    stdout_tail: str = ""
    stderr_tail: str = ""
    artifact_paths: list[str] = field(default_factory=list)
    note: str = ""
    stdout_full: str = field(default="", repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "command": self.command,
            "cwd": self.cwd,
            "status": self.status,
            "returncode": self.returncode,
            "stdout_tail": self.stdout_tail,
            "stderr_tail": self.stderr_tail,
            "artifact_paths": self.artifact_paths,
            "note": self.note,
        }


def _tail(text: str, limit: int = 4000) -> str:
    if len(text) <= limit:
        return text
    return text[-limit:]


def _run_step(
    name: str,
    command: list[str],
    *,
    cwd: Path = REPO_ROOT,
    dry_run: bool = False,
    ok_returncodes: set[int] | None = None,
    artifact_paths: list[Path] | None = None,
    timeout: int = 300,
    note: str = "",
) -> StepResult:
    artifacts = [str(p) for p in artifact_paths or []]
    if dry_run:
        return StepResult(
            name=name,
            command=command,
            cwd=str(cwd),
            status="planned",
            artifact_paths=artifacts,
            note=note,
        )
    ok = ok_returncodes or {0}
    try:
        proc = subprocess.run(
            command,
            cwd=str(cwd),
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return StepResult(
            name=name,
            command=command,
            cwd=str(cwd),
            status="timeout",
            returncode=124,
            stdout_tail=_tail(exc.stdout or ""),
            stderr_tail=_tail(exc.stderr or ""),
            artifact_paths=artifacts,
            note=note,
        )
    status = "ok" if proc.returncode in ok else "failed"
    return StepResult(
        name=name,
        command=command,
        cwd=str(cwd),
        status=status,
        returncode=proc.returncode,
            stdout_tail=_tail(proc.stdout),
            stderr_tail=_tail(proc.stderr),
            artifact_paths=artifacts,
            note=note,
            stdout_full=proc.stdout,
        )


def _workspace_markers(path: Path) -> int:
    markers = [
        "engage_report.json",
        "engage_report.md",
        "INTAKE_BASELINE.json",
        "SCOPE.md",
        "INVARIANT_LEDGER.md",
        ".auditooor",
        "submissions",
    ]
    return sum(1 for marker in markers if (path / marker).exists())


def discover_workspaces(audits_root: Path = DEFAULT_AUDITS_ROOT) -> list[Path]:
    """Discover likely audit workspaces below ``audits_root``."""
    if not audits_root.is_dir():
        return []
    workspaces: list[Path] = []
    for child in sorted(audits_root.iterdir()):
        if not child.is_dir():
            continue
        if child.name.startswith("."):
            continue
        if _workspace_markers(child) >= 2:
            workspaces.append(child.resolve())
    return workspaces


def parse_workspace_args(values: list[str], audits_root: Path) -> list[Path]:
    """Parse repeated/comma-separated workspace args.

    Relative names resolve first under ``audits_root`` and then under the
    current working directory.
    """
    if not values:
        return discover_workspaces(audits_root)
    out: list[Path] = []
    for raw in values:
        for part in raw.split(","):
            item = part.strip()
            if not item:
                continue
            p = Path(item).expanduser()
            if not p.is_absolute():
                candidate = audits_root / item
                p = candidate if candidate.exists() else Path.cwd() / item
            out.append(p.resolve())
    deduped: list[Path] = []
    seen: set[Path] = set()
    for ws in out:
        if ws in seen:
            continue
        seen.add(ws)
        deduped.append(ws)
    return deduped


def refresh_workspace(
    workspace: Path,
    *,
    dry_run: bool,
    top_n: int,
    write_invariants: bool,
    strict_live_target: bool,
) -> dict[str, Any]:
    steps: list[StepResult] = []
    workspace_exists = workspace.is_dir()
    docs_dir = workspace / "docs"
    live_md = docs_dir / "LIVE_TARGET_REPORT.md"
    live_json = docs_dir / "LIVE_TARGET_REPORT.json"

    if not workspace_exists:
        return {
            "workspace": str(workspace),
            "status": "missing_workspace",
            "steps": [],
        }

    live_cmd = [
        sys.executable,
        str(REPO_ROOT / "tools" / "live-target-intelligence-report.py"),
        "--workspace",
        str(workspace),
        "--output",
        str(live_md),
        "--output-json",
        str(live_json),
        "--top-n",
        str(top_n),
    ]
    if strict_live_target:
        live_cmd.append("--strict")
    steps.append(
        _run_step(
            "live-target-report",
            live_cmd,
            dry_run=dry_run,
            artifact_paths=[live_md, live_json],
        )
    )

    inv_cmd = [
        sys.executable,
        str(REPO_ROOT / "tools" / "invariant-ledger.py"),
        "--workspace",
        str(workspace),
        "--from-scope",
    ]
    inv_note = "safe default: dry-run indexing only"
    if write_invariants:
        inv_note = "explicit --write-invariants enabled"
    else:
        inv_cmd.extend(["--dry-run", "--json"])
    steps.append(
        _run_step(
            "invariant-index",
            inv_cmd,
            dry_run=dry_run,
            ok_returncodes={0, 2},
            artifact_paths=[] if not write_invariants else [
                workspace / ".auditooor" / "invariant_ledger.json",
                workspace / "INVARIANT_LEDGER.md",
            ],
            note=inv_note,
        )
    )

    if (workspace / ".auditooor" / "invariant_ledger.json").is_file():
        steps.append(
            _run_step(
                "invariant-ledger-check",
                [
                    sys.executable,
                    str(REPO_ROOT / "tools" / "invariant-ledger.py"),
                    "--workspace",
                    str(workspace),
                    "--check",
                ],
                dry_run=dry_run,
                ok_returncodes={0, 1},
                note="returncode 1 is recorded as validation debt, not a runner crash",
            )
        )

    if (workspace / ".auditooor" / "generated_invariants.json").is_file():
        steps.append(
            _run_step(
                "invariant-discovery-adoption",
                [
                    sys.executable,
                    str(REPO_ROOT / "tools" / "invariant-discovery-adoption.py"),
                    "--workspace",
                    str(workspace),
                    "--print-json",
                ],
                dry_run=dry_run,
                ok_returncodes={0, 1},
                artifact_paths=[
                    workspace / ".auditooor" / "invariant_discovery_adoption.json",
                    workspace / ".auditooor" / "invariant_discovery_adoption.md",
                ],
                note="local review/index refresh; no --adopt-ledger by default",
            )
        )

    status = "ok"
    if any(step.status in {"failed", "timeout"} for step in steps):
        status = "attention"
    if dry_run:
        status = "planned"
    return {
        "workspace": str(workspace),
        "status": status,
        "steps": [step.to_dict() for step in steps],
    }


def run_refresh(args: argparse.Namespace) -> dict[str, Any]:
    generated_at = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    audits_root = Path(args.audits_root).expanduser().resolve()
    workspaces = parse_workspace_args(args.workspaces, audits_root)

    workspace_rows = [
        refresh_workspace(
            ws,
            dry_run=args.dry_run,
            top_n=args.top_n,
            write_invariants=args.write_invariants,
            strict_live_target=args.strict_live_target,
        )
        for ws in workspaces
    ]

    global_steps: list[StepResult] = []
    global_steps.append(
        _run_step(
            "anti-pattern-catalog-validate",
            [
                sys.executable,
                str(REPO_ROOT / "tools" / "antipattern-catalog-build.py"),
                "--validate",
                "--json",
            ],
            dry_run=args.dry_run,
            artifact_paths=[],
        )
    )

    report_dir = Path(args.report_dir).expanduser().resolve()
    operator_json = report_dir / "operator_action_tracker.json"
    operator_md = report_dir / "operator_action_tracker.md"
    snapshot_date = generated_at.split("T", 1)[0]
    canonical_operator_dir = REPO_ROOT / "reports" / "v3_operator_action_snapshots"
    canonical_operator_json = canonical_operator_dir / f"snapshot_{snapshot_date}.json"
    canonical_operator_md = canonical_operator_dir / f"snapshot_{snapshot_date}.md"
    global_steps.append(
        _run_step(
            "operator-action-tracker-json",
            [
                sys.executable,
                str(REPO_ROOT / "tools" / "operator-action-tracker.py"),
                "--workspace",
                str(REPO_ROOT),
                "--audits-root",
                str(audits_root),
                "--json",
                "--no-delta",
            ],
            dry_run=args.dry_run,
            artifact_paths=[operator_json],
            note="captured by pillar-refresh-daily into report_dir and canonical META-2 snapshot dir when not dry-run",
        )
    )
    global_steps.append(
        _run_step(
            "operator-action-tracker-markdown",
            [
                sys.executable,
                str(REPO_ROOT / "tools" / "operator-action-tracker.py"),
                "--workspace",
                str(REPO_ROOT),
                "--audits-root",
                str(audits_root),
                "--markdown",
                "--no-delta",
            ],
            dry_run=args.dry_run,
            artifact_paths=[operator_md],
            note="captured by pillar-refresh-daily into report_dir and canonical META-2 snapshot dir when not dry-run",
        )
    )

    if not args.dry_run:
        report_dir.mkdir(parents=True, exist_ok=True)
        canonical_operator_dir.mkdir(parents=True, exist_ok=True)
        for step, paths in [
            (global_steps[-2], [operator_json, canonical_operator_json]),
            (global_steps[-1], [operator_md, canonical_operator_md]),
        ]:
            if step.status == "ok":
                body = step.stdout_full
                text = body if body.endswith("\n") else body + "\n"
                for path in paths:
                    path.write_text(text, encoding="utf-8")

    status_snapshot_json = REPO_ROOT / "reports" / "v3_daily_status" / "snapshot_<timestamp>.json"
    status_snapshot_md = REPO_ROOT / "reports" / "v3_daily_status" / "snapshot_<timestamp>.md"
    global_steps.append(
        _run_step(
            "v3-daily-status-snapshot-json",
            [
                sys.executable,
                str(REPO_ROOT / "tools" / "v3-daily-status-snapshot.py"),
                "--workspace",
                str(REPO_ROOT),
                "--json",
                "--write-snapshot",
            ],
            dry_run=args.dry_run,
            artifact_paths=[status_snapshot_json],
            note="writes timestamped JSON checkpoint under reports/v3_daily_status/",
        )
    )
    global_steps.append(
        _run_step(
            "v3-daily-status-snapshot-markdown",
            [
                sys.executable,
                str(REPO_ROOT / "tools" / "v3-daily-status-snapshot.py"),
                "--workspace",
                str(REPO_ROOT),
                "--markdown",
                "--write-snapshot",
            ],
            dry_run=args.dry_run,
            artifact_paths=[status_snapshot_md],
            note="writes timestamped Markdown checkpoint under reports/v3_daily_status/",
        )
    )

    any_failed = any(
        step.status in {"failed", "timeout"}
        for row in workspace_rows
        for step in [StepResult(**s) for s in row.get("steps", [])]
    ) or any(step.status in {"failed", "timeout"} for step in global_steps)
    payload = {
        "schema": SCHEMA,
        "generated_at": generated_at,
        "repo_root": str(REPO_ROOT),
        "audits_root": str(audits_root),
        "dry_run": bool(args.dry_run),
        "write_invariants": bool(args.write_invariants),
        "workspace_count": len(workspace_rows),
        "status": "attention" if any_failed else ("planned" if args.dry_run else "ok"),
        "workspaces": workspace_rows,
        "global_steps": [step.to_dict() for step in global_steps],
    }

    if not args.dry_run:
        summary_json = report_dir / "pillar_refresh_daily_summary.json"
        summary_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        payload["summary_path"] = str(summary_json)
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workspaces",
        "--workspace",
        action="append",
        default=[],
        help="Workspace path/name, repeatable or comma-separated. Defaults to ~/audits discovery.",
    )
    parser.add_argument("--audits-root", default=str(DEFAULT_AUDITS_ROOT))
    parser.add_argument("--report-dir", default=str(DEFAULT_REPORT_DIR))
    parser.add_argument("--top-n", type=int, default=50)
    parser.add_argument("--dry-run", action="store_true", help="Plan commands without writing or executing tools.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable summary.")
    parser.add_argument(
        "--write-invariants",
        action="store_true",
        help="Allow invariant-ledger.py --from-scope writes. Default is dry-run indexing only.",
    )
    parser.add_argument(
        "--strict-live-target",
        action="store_true",
        help="Fail live-target report refresh when engage_report is missing.",
    )
    return parser


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Pillar Refresh Daily",
        "",
        f"- Generated: `{payload['generated_at']}`",
        f"- Status: `{payload['status']}`",
        f"- Dry run: `{payload['dry_run']}`",
        f"- Workspaces: `{payload['workspace_count']}`",
        "",
        "## Workspace Results",
        "",
    ]
    for row in payload["workspaces"]:
        lines.append(f"### {row['workspace']}")
        lines.append(f"- Status: `{row['status']}`")
        for step in row.get("steps", []):
            rc = "" if step["returncode"] is None else f" rc={step['returncode']}"
            lines.append(f"- `{step['name']}`: `{step['status']}`{rc}")
        lines.append("")
    lines.extend(["## Global Steps", ""])
    for step in payload["global_steps"]:
        rc = "" if step["returncode"] is None else f" rc={step['returncode']}"
        lines.append(f"- `{step['name']}`: `{step['status']}`{rc}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    payload = run_refresh(args)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render_markdown(payload))
    return 0 if payload["status"] in {"ok", "planned"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
