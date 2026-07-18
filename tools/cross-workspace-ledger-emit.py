#!/usr/bin/env python3
"""cross-workspace-ledger-emit.py — fan a universal-task-ledger row out to the
appropriate cross-workspace tool.

PR #658 Tier-B item #10: "adopt-don't-rewrite" thin emitter. The 5 existing
cross-* tools keep their current CLIs; this script is a routing shim that reads
a ledger row by task_id and delegates to whichever tool the router map selects.

Router map lives in: reference/cross_ws_router_map.json
(extend that file to add new routes — no code change required)

Usage
-----
    # Dry-run (default) — shows the command that WOULD be executed
    python3 tools/cross-workspace-ledger-emit.py \\
        --workspace ~/audits/dydx \\
        --row TCOMMIT_MINING-20260509-cometbft-fork \\
        --dry-run

    # Actually invoke the downstream tool
    python3 tools/cross-workspace-ledger-emit.py \\
        --workspace ~/audits/dydx \\
        --row TCOMMIT_MINING-20260509-cometbft-fork \\
        --apply

    # Refresh repo-wide state dashboard (does not require --row)
    python3 tools/cross-workspace-ledger-emit.py --refresh-state

    # List available row types and their routed tool
    python3 tools/cross-workspace-ledger-emit.py --list-routes

    # Override audits root (default: ~/audits)
    python3 tools/cross-workspace-ledger-emit.py \\
        --workspace ~/audits/spark \\
        --row TFILING_LIFECYCLE-20260509-lead1 \\
        --audits-dir /mnt/audits \\
        --dry-run

Exit codes
----------
    0  Success (or dry-run preview printed)
    1  Route not found for this row type
    2  Downstream tool returned non-zero exit
    3  Usage / input error

Written by Claude Sonnet 4.6 for PR #658 Tier-B #10. Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

# ── paths ─────────────────────────────────────────────────────────────────────

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
ROUTER_MAP_PATH = REPO / "reference" / "cross_ws_router_map.json"

DEFAULT_AUDITS_DIR = Path.home() / "audits"

# Known ledger JSONL locations (searched in order)
LEDGER_CANDIDATES = [
    Path("/Users/wolf/Documents/Codex/auditooor/obsidian-vault/universal_task_ledger.jsonl"),
    REPO.parent / "obsidian-vault" / "universal_task_ledger.jsonl",
    REPO / "obsidian-vault" / "universal_task_ledger.jsonl",
]

# ── helpers ───────────────────────────────────────────────────────────────────


def _load_router_map() -> dict[str, Any]:
    if not ROUTER_MAP_PATH.is_file():
        _die(f"[fatal] router map not found: {ROUTER_MAP_PATH}", 3)
    try:
        return json.loads(ROUTER_MAP_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        _die(f"[fatal] malformed router map JSON: {exc}", 3)


def _find_ledger(override: str | None) -> Path | None:
    if override:
        p = Path(override).expanduser().resolve()
        return p if p.is_file() else None
    for candidate in LEDGER_CANDIDATES:
        if candidate.is_file():
            return candidate
    return None


def _load_row(ledger_path: Path, task_id: str) -> dict[str, Any] | None:
    """Return the first JSONL row matching task_id, or None."""
    try:
        with ledger_path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if row.get("id") == task_id:
                    return row
    except OSError as exc:
        _die(f"[fatal] cannot read ledger {ledger_path}: {exc}", 3)
    return None


def _resolve_tool_path(tool_rel: str) -> Path:
    """Resolve tool path relative to REPO, then fall back to absolute."""
    p = (REPO / tool_rel).resolve()
    if not p.is_file():
        p = Path(tool_rel).expanduser().resolve()
    return p


def _substitute(template: str, ctx: dict[str, str]) -> str:
    """Replace {key} placeholders in a CLI flag value."""
    for k, v in ctx.items():
        template = template.replace(f"{{{k}}}", v)
    return template


def _build_cli(entry: dict[str, Any], ctx: dict[str, str]) -> list[str]:
    """Expand CLI flag templates into a concrete argv list."""
    tool_path = str(_resolve_tool_path(entry["tool"]))
    argv = [sys.executable, tool_path]
    for flag in entry.get("cli_flags", []):
        expanded = _substitute(flag, ctx)
        argv.append(expanded)
    return argv


def _die(msg: str, code: int = 1) -> None:
    print(msg, file=sys.stderr)
    sys.exit(code)


# ── actions ───────────────────────────────────────────────────────────────────


def cmd_list_routes(router_map: dict[str, Any]) -> None:
    """Print a human-readable table of all configured routes."""
    print(f"{'row_type':<35} {'tool':<50} {'profile'}")
    print("-" * 100)
    for key, entry in router_map.items():
        if key.startswith("_"):
            continue
        tool = entry.get("tool", "")
        profile = entry.get("profile", "")
        print(f"{key:<35} {tool:<50} {profile}")
    # also show the state-refresh pseudo-route
    sr = router_map.get("_state_refresh", {})
    if sr:
        print(f"{'(--refresh-state)':<35} {sr.get('tool',''):<50} {sr.get('profile','')}")


def cmd_refresh_state(router_map: dict[str, Any], audits_dir: Path, dry_run: bool) -> None:
    """Invoke cross-workspace-state-aggregator.py."""
    entry = router_map.get("_state_refresh")
    if not entry:
        _die("[error] _state_refresh entry missing from router map", 1)
    ctx = {"audits_dir": str(audits_dir)}
    argv = _build_cli(entry, ctx)
    _run_or_preview(argv, dry_run)


def cmd_emit_row(
    row: dict[str, Any],
    router_map: dict[str, Any],
    workspace: Path,
    audits_dir: Path,
    dry_run: bool,
    paste_ready_path: str | None,
) -> None:
    """Fan the given ledger row to its routed tool."""
    row_type = row.get("type", "")
    entry = router_map.get(row_type)
    if not entry:
        available = [k for k in router_map if not k.startswith("_")]
        _die(
            f"[error] no route for row type {row_type!r}.\n"
            f"        Available types: {', '.join(sorted(available))}",
            1,
        )

    # Derive workspace name (basename of workspace path or row's workspace field)
    ws_field = row.get("workspace") or str(workspace)
    ws_path = Path(ws_field).expanduser().resolve()
    workspace_name = ws_path.name

    # paste_ready resolution
    paste_ready = paste_ready_path or ""
    if entry.get("requires_paste_ready") and not paste_ready:
        # Try evidence_paths from the row
        for ep in row.get("evidence_paths", []):
            ep_path = Path(ep).expanduser()
            if ep_path.suffix == ".md" and "paste" in ep_path.name.lower():
                paste_ready = str(ep_path)
                break
        if not paste_ready:
            _die(
                f"[error] row type {row_type!r} requires a paste-ready markdown path.\n"
                f"        Pass --paste-ready <path> or set evidence_paths in the ledger row.",
                3,
            )

    ctx: dict[str, str] = {
        "workspace": str(ws_path),
        "workspace_name": workspace_name,
        "audits_dir": str(audits_dir),
        "paste_ready": paste_ready,
        "out": str(REPO / "reports" / f"cross_ws_{row.get('id','out')}.json"),
        "task_id": row.get("id", ""),
        "engagement": row.get("engagement") or workspace_name,
    }

    argv = _build_cli(entry, ctx)
    print(f"[emit] row {row.get('id')!r} type={row_type!r} → {entry['tool']}")
    _run_or_preview(argv, dry_run)


def _run_or_preview(argv: list[str], dry_run: bool) -> None:
    cmd_str = " ".join(argv)
    if dry_run:
        print(f"[dry-run] would execute:\n  {cmd_str}")
    else:
        print(f"[run] {cmd_str}")
        result = subprocess.run(argv)
        if result.returncode != 0:
            _die(
                f"[error] downstream tool exited {result.returncode}",
                2,
            )


# ── CLI ───────────────────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cross-workspace-ledger-emit.py",
        description=(
            "Fan a universal-task-ledger row out to the appropriate cross-workspace tool.\n"
            "Uses reference/cross_ws_router_map.json to select the target tool.\n"
            "--dry-run is the default; pass --apply to actually invoke the tool."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--workspace", "-w",
        metavar="PATH",
        help="Absolute path to the engagement workspace (e.g. ~/audits/dydx). "
             "Used to resolve workspace-relative context.",
    )
    p.add_argument(
        "--row", "-r",
        metavar="TASK_ID",
        help="task_id of the ledger row to emit (e.g. TCOMMIT_MINING-20260509-cometbft-fork).",
    )
    p.add_argument(
        "--ledger",
        metavar="PATH",
        help="Override path to universal_task_ledger.jsonl. "
             "Default: auto-discover from known vault locations.",
    )
    p.add_argument(
        "--audits-dir",
        metavar="PATH",
        default=str(DEFAULT_AUDITS_DIR),
        help=f"Root directory containing audit workspaces (default: {DEFAULT_AUDITS_DIR}).",
    )
    p.add_argument(
        "--paste-ready",
        metavar="PATH",
        help="Path to paste-ready markdown (required when row type is filing_lifecycle or in_engagement_hunt).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Print the command that would be executed without running it (default: ON).",
    )
    p.add_argument(
        "--apply",
        action="store_true",
        default=False,
        help="Actually invoke the downstream tool (overrides --dry-run).",
    )
    p.add_argument(
        "--refresh-state",
        action="store_true",
        default=False,
        help="Invoke cross-workspace-state-aggregator.py to refresh the repo-wide dashboard.",
    )
    p.add_argument(
        "--list-routes",
        action="store_true",
        default=False,
        help="List all configured row_type → tool routes from the router map.",
    )
    return p


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)

    router_map = _load_router_map()
    dry_run = not args.apply  # --apply overrides --dry-run
    audits_dir = Path(args.audits_dir).expanduser().resolve()

    # ── list-routes ────────────────────────────────────────────────────────
    if args.list_routes:
        cmd_list_routes(router_map)
        return

    # ── refresh-state ──────────────────────────────────────────────────────
    if args.refresh_state:
        cmd_refresh_state(router_map, audits_dir, dry_run)
        return

    # ── single row emit ────────────────────────────────────────────────────
    if not args.row:
        parser.error("--row TASK_ID is required unless --list-routes or --refresh-state is given.")

    # Resolve workspace
    workspace = Path(args.workspace).expanduser().resolve() if args.workspace else Path.cwd()

    # Locate and load ledger
    ledger_path = _find_ledger(args.ledger)

    if ledger_path is None:
        # Synthetic stub row — useful for CI / tests where no real ledger exists
        print(
            f"[warn] no ledger found; synthesising minimal row stub for task_id={args.row!r}",
            file=sys.stderr,
        )
        # Try to infer type from task_id prefix (e.g. TCOMMIT_MINING-... → commit_mining)
        task_id = args.row
        inferred_type = _infer_type_from_id(task_id)
        row: dict[str, Any] = {
            "schema": "auditooor.universal_task_ledger.v1",
            "id": task_id,
            "type": inferred_type,
            "title": task_id,
            "status": "planned",
            "owner_agent": "orchestrator",
            "priority": "P2",
            "created_at": "2026-01-01T00:00:00Z",
            "last_touched": "2026-01-01T00:00:00Z",
            "workspace": str(workspace),
        }
    else:
        row = _load_row(ledger_path, args.row)
        if row is None:
            _die(f"[error] task_id {args.row!r} not found in ledger {ledger_path}", 3)

    cmd_emit_row(
        row=row,
        router_map=router_map,
        workspace=workspace,
        audits_dir=audits_dir,
        dry_run=dry_run,
        paste_ready_path=args.paste_ready,
    )


def _infer_type_from_id(task_id: str) -> str:
    """Best-effort type inference from task_id prefix (T<TYPE>-<date>-<slug>)."""
    # Strip leading T, extract up to first -YYYYMMDD
    import re
    m = re.match(r"^T([A-Z_]+)-\d{8}-", task_id)
    if not m:
        return "klbq_burndown"
    prefix = m.group(1).lower()
    # Map uppercase prefix to schema enum value
    mapping = {
        "klbq_burndown": "klbq_burndown",
        "retro_audit": "retro_audit",
        "corpus_mining": "corpus_mining",
        "detector_authoring": "detector_authoring",
        "cross_engagement_propagation": "cross_engagement_propagation",
        "in_engagement_hunt": "in_engagement_hunt",
        "filing_lifecycle": "filing_lifecycle",
        "rule_codification": "rule_codification",
        "triager_response": "triager_response",
        "tooling_ship": "tooling_ship",
        "pr_landing": "pr_landing",
        "next_loop_priority": "next_loop_priority",
        "commit_mining": "commit_mining",
        "external_intel_intake": "external_intel_intake",
        "regression_repro": "regression_repro",
    }
    return mapping.get(prefix, "klbq_burndown")


if __name__ == "__main__":
    main()
