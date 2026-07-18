#!/usr/bin/env python3
"""
workspace-state.py — Legacy/local workspace phase tracker

Tracks which audit phase each workspace is in, plus lightweight local metadata
(findings count, submissions_count, last run time). Used by workspace
bootstrap helpers, local inventory/reporting commands, and operators
who want a lightweight progress snapshot across sessions.

Important: canonical filed-finding truth lives in the workspace's active
SUBMISSIONS.md ledger, not in this local JSON snapshot. `submissions_count`
is only a convenience mirror for local status views.

Usage:
    workspace-state.py list                          # show all workspaces
    workspace-state.py get <ws>                      # show one workspace
    workspace-state.py set <ws> --phase <N>          # set phase 1-8
    workspace-state.py next <ws>                     # advance phase
    workspace-state.py reset <ws>                    # reset to phase 1
    workspace-state.py bump <ws> --findings <n>      # add findings
    workspace-state.py bump <ws> --submissions <n>   # add local submission count
    workspace-state.py init <ws> --name <str>        # register new workspace
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from submission_counts import summarize_workspace

STATE_DIR = Path.home() / ".auditooor"
STATE_FILE = STATE_DIR / "workspace_state.json"

PHASE_NAMES = {
    1: "orient",
    2: "scan",
    3: "correlate",
    4: "swarm_discover",
    5: "manual_dispatch",
    6: "synthesize",
    7: "auto_fix_pre_submit",
    8: "summary",
    9: "submitted",
}


def _load() -> Dict[str, Any]:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"workspaces": {}, "version": 1}


def _save(data: Dict[str, Any]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(data, indent=2, default=str))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_workspace(ws_path: str, name: Optional[str] = None) -> None:
    data = _load()
    ws = os.path.abspath(os.path.expanduser(ws_path))
    key = ws
    if key not in data["workspaces"]:
        data["workspaces"][key] = {
            "path": ws,
            "name": name or os.path.basename(ws),
            "phase": 1,
            "phase_name": PHASE_NAMES[1],
            "findings_count": 0,
            "submissions_count": 0,
            "created_at": _now(),
            "updated_at": _now(),
            "status": "active",
            "notes": "",
        }
        _save(data)
        print(f"Initialized workspace: {name or os.path.basename(ws)} (phase 1: orient)")
    else:
        print(f"Workspace already exists: {data['workspaces'][key]['name']}")


def set_phase(ws_path: str, phase: int) -> None:
    data = _load()
    ws = os.path.abspath(os.path.expanduser(ws_path))
    ws_data = data["workspaces"].get(ws)
    if not ws_data:
        print(f"Workspace not tracked: {ws}")
        print("Run: workspace-state.py init <ws> [--name <name>]")
        sys.exit(1)
    ws_data["phase"] = phase
    ws_data["phase_name"] = PHASE_NAMES.get(phase, f"phase_{phase}")
    ws_data["updated_at"] = _now()
    _save(data)
    print(f"Set {ws_data['name']} → phase {phase}: {ws_data['phase_name']}")


def next_phase(ws_path: str) -> None:
    data = _load()
    ws = os.path.abspath(os.path.expanduser(ws_path))
    ws_data = data["workspaces"].get(ws)
    if not ws_data:
        print(f"Workspace not tracked: {ws}")
        sys.exit(1)
    current = ws_data["phase"]
    if current >= max(PHASE_NAMES.keys()):
        print(f"{ws_data['name']} already at final phase ({current})")
        return
    set_phase(ws_path, current + 1)


def bump(ws_path: str, findings: int = 0, submissions: int = 0) -> None:
    data = _load()
    ws = os.path.abspath(os.path.expanduser(ws_path))
    ws_data = data["workspaces"].get(ws)
    if not ws_data:
        print(f"Workspace not tracked: {ws}")
        sys.exit(1)
    if findings:
        ws_data["findings_count"] = ws_data.get("findings_count", 0) + findings
    if submissions:
        ws_data["submissions_count"] = ws_data.get("submissions_count", 0) + submissions
    ws_data["updated_at"] = _now()
    _save(data)
    print(
        f"Updated {ws_data['name']}: {ws_data['findings_count']} findings, "
        f"{ws_data['submissions_count']} submissions (local snapshot)"
    )


def sync_submissions(ws_path: str) -> None:
    data = _load()
    ws = os.path.abspath(os.path.expanduser(ws_path))
    ws_data = data["workspaces"].get(ws)
    if not ws_data:
        print(f"Workspace not tracked: {ws}")
        sys.exit(1)

    summary = summarize_workspace(Path(ws))
    if summary["source_kind"] == "missing":
        print(f"No canonical SUBMISSIONS.md found for {ws_data['name']}: {ws}")
        sys.exit(1)

    ws_data["submissions_count"] = int(summary["submitted"])
    ws_data["updated_at"] = _now()
    _save(data)
    print(
        f"Synced {ws_data['name']} local submissions snapshot → {ws_data['submissions_count']} "
        f"(source: {summary['source_kind']})"
    )


def reset(ws_path: str) -> None:
    data = _load()
    ws = os.path.abspath(os.path.expanduser(ws_path))
    ws_data = data["workspaces"].get(ws)
    if not ws_data:
        print(f"Workspace not tracked: {ws}")
        sys.exit(1)
    ws_data["phase"] = 1
    ws_data["phase_name"] = PHASE_NAMES[1]
    ws_data["updated_at"] = _now()
    _save(data)
    print(f"Reset {ws_data['name']} → phase 1: orient")


def get_workspace(ws_path: str) -> None:
    data = _load()
    ws = os.path.abspath(os.path.expanduser(ws_path))
    ws_data = data["workspaces"].get(ws)
    if not ws_data:
        print(f"Workspace not tracked: {ws}")
        sys.exit(1)
    print(json.dumps(ws_data, indent=2))


def list_workspaces(status_filter: Optional[str] = None) -> None:
    data = _load()
    workspaces: List[Dict[str, Any]] = list(data["workspaces"].values())
    if status_filter:
        workspaces = [w for w in workspaces if w.get("status") == status_filter]
    if not workspaces:
        print("No workspaces tracked.")
        print(f"State file: {STATE_FILE}")
        return

    # Header
    print(f"{'Workspace':<20} {'Phase':<18} {'Findings':>8} {'Subs*':>5} {'Status':<10} {'Last Update':<20}")
    print("-" * 90)
    for w in sorted(workspaces, key=lambda x: x.get("updated_at", ""), reverse=True):
        name = w.get("name", "?")[:19]
        phase = f"{w['phase']}: {w.get('phase_name', '?')}"[:17]
        findings = w.get("findings_count", 0)
        subs = w.get("submissions_count", 0)
        status = w.get("status", "?")[:9]
        updated = w.get("updated_at", "?")[:19]
        print(f"{name:<20} {phase:<18} {findings:>8} {subs:>5} {status:<10} {updated:<20}")
    print("\n* Subs = local snapshot only; canonical filed findings live in the workspace SUBMISSIONS.md ledger.")
    print(f"State file: {STATE_FILE}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Legacy/local workspace phase tracker. Canonical filed findings live in "
            "the workspace SUBMISSIONS.md ledger."
        )
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="Register a new workspace")
    p_init.add_argument("ws", help="Path to workspace directory")
    p_init.add_argument("--name", help="Display name")

    p_set = sub.add_parser("set", help="Set workspace phase (1-9)")
    p_set.add_argument("ws", help="Path to workspace directory")
    p_set.add_argument("--phase", type=int, required=True)

    p_next = sub.add_parser("next", help="Advance workspace to next phase")
    p_next.add_argument("ws", help="Path to workspace directory")

    p_get = sub.add_parser("get", help="Show workspace details")
    p_get.add_argument("ws", help="Path to workspace directory")

    p_reset = sub.add_parser("reset", help="Reset workspace to phase 1")
    p_reset.add_argument("ws", help="Path to workspace directory")

    p_bump = sub.add_parser("bump", help="Increment local findings/submissions counters")
    p_bump.add_argument("ws", help="Path to workspace directory")
    p_bump.add_argument("--findings", type=int, default=0)
    p_bump.add_argument("--submissions", type=int, default=0)

    p_sync = sub.add_parser(
        "sync-submissions",
        help="Sync local submissions_count from the canonical SUBMISSIONS.md ledger",
    )
    p_sync.add_argument("ws", help="Path to workspace directory")

    p_list = sub.add_parser("list", help="List all tracked workspaces")
    p_list.add_argument("--status", help="Filter by status (active, paused, submitted)")

    args = parser.parse_args()

    if args.cmd == "init":
        init_workspace(args.ws, args.name)
    elif args.cmd == "set":
        set_phase(args.ws, args.phase)
    elif args.cmd == "next":
        next_phase(args.ws)
    elif args.cmd == "get":
        get_workspace(args.ws)
    elif args.cmd == "reset":
        reset(args.ws)
    elif args.cmd == "bump":
        bump(args.ws, args.findings, args.submissions)
    elif args.cmd == "sync-submissions":
        sync_submissions(args.ws)
    elif args.cmd == "list":
        list_workspaces(args.status)


if __name__ == "__main__":
    main()
