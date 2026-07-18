#!/usr/bin/env python3
"""Offline entrypoint report for auditooor Obsidian/shared-memory surfaces."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.obsidian_memory_entrypoints.v1"
GENERATED_DATE = "2026-05-05"
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ACTIVE_VAULT = Path("/Users/wolf/Documents/Codex/auditooor/obsidian-vault")
DEFAULT_MEMORY_ROOTS = (
    Path("/Users/wolf/Documents/Codex/auditooor"),
)

OBSIDIAN_OPEN_NOTE = (
    "The active vault is the folder itself. Obsidian should register it via "
    "'Open folder as vault'; a shell/CLI open of the folder may only open a "
    "file-browser window and may not register the vault in Obsidian."
)
NON_OBSIDIAN_USAGE = (
    "Obsidian is optional for reading the memory surface. The Markdown and JSON "
    "entrypoints listed here are plain files and remain usable from a terminal, "
    "editor, or automation without opening Obsidian."
)


KEY_VAULT_FILES = (
    "INDEX.md",
    "DASHBOARD.md",
    "INDEX_active.md",
    "NEXT_LOOP.md",
    "gap-analysis/2026-05-05.md",
    "gap-analysis/candidates.jsonl",
    "dispatch/next_dispatch_manifest.json",
    "dispatch/next_dispatch_manifest.preview.json",
    "harness-failures/INDEX.md",
    "knowledge-gaps/INDEX.md",
    "agent-memory/INDEX.md",
    "anti-patterns/INDEX.md",
    "tools-api/INDEX.md",
    "bug-classes/INDEX.md",
    "calibration/INDEX.md",
    "make-targets/INDEX.md",
)

SHARED_MEMORY_ENTRYPOINTS = (
    ("shared-memory markdown", "docs/SHARED_MEMORY_INDEX_2026-05-05.md"),
    ("shared-memory json", "reports/shared_memory_index_2026-05-05.json"),
    ("shared-memory helper", "tools/shared-memory-index.py"),
)

MEMORY_BRIEF_ENTRYPOINTS = (
    ("memory brief markdown", "docs/MEMORY_BRIEF_2026-05-05.md"),
    ("memory brief json", "reports/memory_brief_2026-05-05.json"),
    ("memory brief helper", "tools/memory-brief.py"),
)

VAULT_COMMANDS = (
    "make vault-refresh",
    "make vault-deepen",
    "make vault-dashboard",
    "make vault-sync",
    "make vault-status",
    "python3 tools/obsidian-vault-emit.py --vault-dir obsidian-vault",
    "python3 tools/obsidian-vault-emit.py --vault-dir obsidian-vault --deep",
    "python3 tools/obsidian-vault-dashboard.py --vault-dir obsidian-vault",
    "python3 tools/obsidian-vault-sync.py --vault-dir obsidian-vault --status",
)

MCP_COMMANDS = (
    "make vault-mcp-server",
    "make vault-mcp-self-test",
    "python3 tools/vault-mcp-server.py --vault-dir obsidian-vault",
    "python3 tools/vault-mcp-server.py --self-test",
)

MEMORY_COMMANDS = (
    "make shared-memory-index",
    "make memory-brief",
    "python3 tools/shared-memory-index.py",
    "python3 tools/memory-brief.py",
)

WORKSPACE_VAULT_FILES = (
    "DASHBOARD.md",
    "INDEX_active.md",
    "NEXT_LOOP.md",
    "gap-analysis/2026-05-05.md",
    "dispatch/next_dispatch_manifest.preview.json",
    "harness-failures/INDEX.md",
    "knowledge-gaps/INDEX.md",
)


@dataclass(frozen=True)
class Entry:
    label: str
    path: Path

    def as_dict(self, root: Path | None = None) -> dict[str, Any]:
        display = _display_path(self.path, root)
        return {
            "label": self.label,
            "path": display,
            "exists": self.path.exists(),
            "kind": _kind(self.path),
        }


def _kind(path: Path) -> str:
    if path.is_dir():
        return "dir"
    if path.is_file():
        return "file"
    return "missing"


def _display_path(path: Path, root: Path | None = None) -> str:
    try:
        if root is not None:
            return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        pass
    return str(path)


def _dedupe(paths: list[Path]) -> list[Path]:
    seen: set[str] = set()
    out: list[Path] = []
    for path in paths:
        key = str(path.expanduser())
        if key in seen:
            continue
        seen.add(key)
        out.append(path.expanduser())
    return out


def _git(root: Path, *args: str) -> str:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=root,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return ""
    if proc.returncode != 0:
        return ""
    return proc.stdout.strip()


def git_branch(root: Path) -> str:
    return _git(root, "branch", "--show-current") or _git(root, "rev-parse", "--abbrev-ref", "HEAD") or "unknown"


def candidate_vault_dirs(root: Path) -> list[Path]:
    env = os.environ.get("AUDITOOOR_OBSIDIAN_VAULT")
    paths: list[Path] = []
    if env:
        paths.append(Path(env))
    paths.extend(memory_roots(root))
    paths = [path / "obsidian-vault" if path.name != "obsidian-vault" else path for path in paths]
    paths.append(DEFAULT_ACTIVE_VAULT)
    return _dedupe(paths)


def memory_roots(root: Path) -> list[Path]:
    env = os.environ.get("AUDITOOOR_MEMORY_ROOT")
    paths: list[Path] = []
    if env:
        paths.append(Path(env))
    paths.extend([root, *DEFAULT_MEMORY_ROOTS])
    return _dedupe(paths)


def choose_memory_root(root: Path, candidates: list[Path]) -> Path:
    markers = (
        "docs/SHARED_MEMORY_INDEX_2026-05-05.md",
        "reports/shared_memory_index_2026-05-05.json",
        "tools/vault-mcp-server.py",
        "tools/obsidian-vault-emit.py",
    )
    for candidate in candidates:
        if any((candidate / marker).exists() for marker in markers):
            return candidate
    return root


def choose_primary_vault(candidates: list[Path]) -> Path:
    env = os.environ.get("AUDITOOOR_OBSIDIAN_VAULT")
    if env:
        env_path = Path(env).expanduser().resolve()
        if env_path.exists():
            return env_path
    active = DEFAULT_ACTIVE_VAULT.expanduser().resolve()
    for candidate in candidates:
        if candidate.expanduser().resolve() == active and candidate.exists():
            return active
    scored = [
        (sum(1 for rel in KEY_VAULT_FILES if (path / rel).exists()), path.exists(), path)
        for path in candidates
    ]
    scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return scored[0][2]


def _makefile_has_target(root: Path, target: str) -> bool:
    makefile = root / "Makefile"
    if not makefile.exists():
        return False
    text = makefile.read_text(encoding="utf-8", errors="replace")
    return f"\n{target}:" in f"\n{text}"


def _command_status(root: Path, command: str) -> dict[str, Any]:
    status: dict[str, Any] = {"command": command}
    if command.startswith("make "):
        target = command.split()[1]
        status["available"] = _makefile_has_target(root, target)
        status["availability_check"] = f"Makefile target {target}"
        return status
    if command.startswith("python3 tools/"):
        script = command.split()[1]
        status["available"] = (root / script).exists()
        status["availability_check"] = script
        return status
    status["available"] = None
    status["availability_check"] = "not_checked"
    return status


def _entry_count(entries: list[dict[str, Any]]) -> dict[str, int]:
    present = sum(1 for entry in entries if entry.get("exists"))
    return {"total": len(entries), "present": present, "missing": len(entries) - present}


def _command_count(entries: list[dict[str, Any]]) -> dict[str, int]:
    present = sum(1 for entry in entries if entry.get("available") is True)
    missing = sum(1 for entry in entries if entry.get("available") is False)
    return {"total": len(entries), "available": present, "missing": missing}


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _read_jsonl(path: Path, limit: int) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if len(rows) >= limit:
                break
            if not line.strip():
                continue
            data = json.loads(line)
            if isinstance(data, dict):
                rows.append(data)
    except (OSError, json.JSONDecodeError):
        return rows
    return rows


def _brief_for_category(memory_brief: dict[str, Any] | None, category: str) -> dict[str, Any] | None:
    if not memory_brief:
        return None
    for brief in memory_brief.get("briefs", []):
        if isinstance(brief, dict) and brief.get("category") == category:
            return brief
    return None


def _find_object(brief: dict[str, Any] | None, category: str, source_path: str) -> dict[str, Any] | None:
    if not brief:
        return None
    objects = brief.get("objects_by_source_category", {}).get(category, [])
    for obj in objects:
        if isinstance(obj, dict) and obj.get("source_path") == source_path:
            return obj
    return None


def _strings(values: list[Any] | tuple[Any, ...] | None) -> list[str]:
    if not values:
        return []
    return [str(value) for value in values if value not in (None, "")]


def _compact_blocked_command_templates(values: Any) -> list[dict[str, Any]]:
    if not isinstance(values, list):
        return []
    rows: list[dict[str, Any]] = []
    for item in values[:3]:
        if not isinstance(item, dict):
            continue
        rows.append(
            {
                "command": str(item.get("command") or ""),
                "missing_inputs": _strings(item.get("missing_inputs"))[:4],
                "unblock_criteria": _strings(item.get("unblock_criteria"))[:3],
            }
        )
    return rows


def _date_prefix(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    match = re.search(r"20\d{2}-\d{2}-\d{2}", value)
    return match.group(0) if match else ""


def _compact_text(value: Any, limit: int = 220) -> str:
    text = " ".join(str(value).split())
    if len(text) > limit:
        return text[: limit - 3].rstrip() + "..."
    return text


def _guard(
    scope: str,
    status: str,
    message: str,
    *,
    evidence: Any = None,
    blocking: bool = False,
    freshness_scope: str = "memory_metadata",
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "scope": scope,
        "status": status,
        "message": _compact_text(message, 320),
        "blocking": blocking,
        "freshness_scope": freshness_scope,
    }
    if evidence is not None:
        row["evidence"] = evidence
    return row


def _guard_summary(guards: list[dict[str, Any]]) -> dict[str, Any]:
    blocking = [row for row in guards if row.get("blocking")]
    nonblocking = [row for row in guards if not row.get("blocking") and row.get("status") != "READY"]
    return {
        "operational_status": "BLOCKED" if blocking else "READY",
        "blocking_count": len(blocking),
        "nonblocking_count": len(nonblocking),
        "blocking_scopes": [str(row.get("scope") or "") for row in blocking],
        "nonblocking_scopes": [str(row.get("scope") or "") for row in nonblocking],
    }


def _vault_freshness_guard(primary_vault: Path, generated_date: str) -> dict[str, Any] | None:
    if not primary_vault.exists():
        return _guard(
            "external_active_vault",
            "ADVISORY",
            "external active Obsidian vault is missing; generated shared-memory reports remain authoritative",
            evidence=str(primary_vault),
            freshness_scope="external_active_vault",
        )
    dashboard = primary_vault / "DASHBOARD.md"
    if not dashboard.is_file():
        return _guard(
            "external_active_vault_dashboard",
            "ADVISORY",
            "external active-vault dashboard is missing; use generated shared-memory reports first",
            evidence=str(dashboard),
            freshness_scope="external_active_vault",
        )
    text = dashboard.read_text(encoding="utf-8", errors="replace")[:8_000]
    generated_match = re.search(r"generated:\s*\"?([^\"\n]+)", text, flags=re.I)
    generated_value = _compact_text(generated_match.group(1), 80) if generated_match else ""
    vault_date = _date_prefix(generated_value)
    if vault_date and vault_date != generated_date:
        return _guard(
            "external_active_vault_freshness",
            "ADVISORY",
            f"external active-vault dashboard was generated on {vault_date}; generated shared-memory reports are expected for {generated_date}",
            evidence={"dashboard": str(dashboard), "generated": generated_value},
            freshness_scope="external_active_vault",
        )
    return None


def _workspace_vault_entries(memory_root: Path) -> list[dict[str, Any]]:
    workspace_vault = memory_root / "obsidian-vault"
    return [Entry(label=rel, path=workspace_vault / rel).as_dict(memory_root) for rel in WORKSPACE_VAULT_FILES]


def build_operational_snapshot(memory_root: Path, selected_branch: str) -> dict[str, Any]:
    memory_brief = _read_json(memory_root / "reports" / "memory_brief_2026-05-05.json")
    known_limitations = _read_json(memory_root / "reports" / "known_limitations_dispatch_2026-05-05.json")
    known_status = _read_json(memory_root / "reports" / "known_limitations_harness_memory_status_2026-05-05.json")
    dispatch_preview = _read_json(memory_root / "obsidian-vault" / "dispatch" / "next_dispatch_manifest.preview.json")
    goal_loop = _read_json(memory_root / "reports" / "goal_loop_status_2026-05-05.json")
    next_loop_candidates = _read_jsonl(memory_root / "obsidian-vault" / "gap-analysis" / "candidates.jsonl", limit=2)

    audit_handoff = _brief_for_category(memory_brief, "audit_handoff")
    current_state = _find_object(audit_handoff, "current_state", "docs/CURRENT_STATE.md")
    goal_loop_note = _find_object(audit_handoff, "goal_loop", "docs/GOAL_LOOP_STATUS_2026-05-05.md")
    model_handoff = _find_object(audit_handoff, "model_handoff", "reports/memory_audit_packet_status_2026-05-05.json")
    day_to_day = _find_object(
        audit_handoff,
        "operational_memory_day_to_day",
        "reports/operational_memory_day_to_day_2026-05-05.json",
    )

    work_items = known_limitations.get("work_items", []) if known_limitations else []
    blocked_items = [
        {
            "limitation_id": str(item.get("limitation_id") or ""),
            "dispatch_lane": str(item.get("dispatch_lane") or ""),
            "blocker": str(item.get("blocker") or ""),
            "next_action": str(item.get("next_action") or ""),
        }
        for item in work_items
        if isinstance(item, dict) and not item.get("dispatch_ready")
    ][:3]

    scheduled_loops = []
    for row in (known_limitations or {}).get("loop_schedule", [])[:2]:
        if not isinstance(row, dict):
            continue
        scheduled_loops.append(
            {
                "loop_index": int(row.get("loop_index") or 0),
                "items": _strings(row.get("items")),
                "lanes": _strings(row.get("lanes")),
                "total_expected_loop_cost": int(row.get("total_expected_loop_cost") or 0),
            }
        )

    preview_slots = []
    for slot in (dispatch_preview or {}).get("emitted", [])[:5]:
        if not isinstance(slot, dict):
            continue
        preview_slots.append(
            {
                "slot_id": str(slot.get("slot_id") or ""),
                "category": str(slot.get("category") or ""),
                "gap_id": str(slot.get("gap_id") or ""),
                "dispatchable": bool(slot.get("dispatchable")),
            }
        )

    next_candidates = []
    for row in next_loop_candidates:
        next_candidates.append(
            {
                "gap_id": str(row.get("gap_id") or ""),
                "category": str(row.get("category") or ""),
                "title": str(row.get("title") or ""),
                "priority_score": row.get("priority_score"),
                "remediation": str(row.get("remediation") or ""),
            }
        )

    summary = (known_limitations or {}).get("summary", {}) if known_limitations else {}
    status_summary = (known_status or {}).get("summary", {}) if known_status else {}
    harness_memory_actionability = []
    for row in ((known_status or {}).get("open_focus_rows", []) if known_status else []):
        if not isinstance(row, dict):
            continue
        harness_memory_actionability.append(
            {
                "id": str(row.get("id") or ""),
                "dispatch_lane": str(row.get("dispatch_lane") or ""),
                "current_status": str(row.get("current_status") or row.get("status") or ""),
                "next_action_status": str(row.get("next_action_status") or ""),
                "next_action": str(row.get("next_action") or ""),
                "actionable_now_commands": _strings(row.get("actionable_now_commands"))[:4],
                "blocked_command_templates": _compact_blocked_command_templates(row.get("blocked_command_templates")),
            }
        )
    goal_policy = (goal_loop or {}).get("goal_policy", {}) if goal_loop else {}
    known_limitations_branch = str((known_limitations or {}).get("branch") or "")
    return {
        "branch": selected_branch,
        "priority_order": ["MEMORY", "HARNESS", "KNOWN LIMITATION BURNDOWN"],
        "source_metadata": {
            "selected_memory_root": str(memory_root),
            "selected_memory_root_branch": selected_branch,
            "known_limitations_branch": known_limitations_branch,
            "known_limitations_branch_mismatch": bool(
                known_limitations_branch and selected_branch != "unknown" and known_limitations_branch != selected_branch
            ),
        },
        "current_state": {
            "github_state": _strings((current_state or {}).get("key_points"))[:1],
            "memory_state": _strings((current_state or {}).get("key_points"))[1:2],
            "goal_status": _strings((goal_loop_note or {}).get("key_points"))[:1],
            "terminal_completion_allowed": goal_policy.get("terminal_completion_allowed"),
        },
        "active_blockers": {
            "blocked_total": int(summary.get("blocked_total") or 0),
            "harness_memory_open_focus_rows": int(status_summary.get("open_focus_row_count") or 0),
            "harness_memory_actionable_open_rows": int(status_summary.get("open_rows_with_actionable_now_commands") or 0),
            "blocked_backlog": _strings((known_limitations or {}).get("blocked_backlog")),
            "items": blocked_items,
            "harness_memory_actionability": harness_memory_actionability[:4],
        },
        "next_loop": {
            "top_ready_now": _strings((known_limitations or {}).get("top_ready_now")),
            "scheduled_loops": scheduled_loops,
            "top_gap_candidates": next_candidates,
            "dispatch_preview": {
                "dispatchable": bool((dispatch_preview or {}).get("dispatchable")),
                "candidate_count": int((dispatch_preview or {}).get("candidate_count") or 0),
                "emitted_count": len((dispatch_preview or {}).get("emitted", [])),
                "preview_slots": preview_slots,
            },
        },
        "pr_605_handoff": {
            "branch": selected_branch,
            "source_branch_from_known_limitations": known_limitations_branch,
            "goal_state": str(goal_policy.get("status") or ""),
            "memory_packet_blocked_items_count": int(((model_handoff or {}).get("counts") or {}).get("blocked_items_count") or 0),
            "day_to_day_dispatch_blocker_count": int(((day_to_day or {}).get("counts") or {}).get("dispatch_blocker_count") or 0),
            "read_first": [
                "obsidian-vault/DASHBOARD.md",
                "obsidian-vault/INDEX_active.md",
                "obsidian-vault/NEXT_LOOP.md",
                "reports/known_limitations_dispatch_2026-05-05.json",
                "obsidian-vault/dispatch/next_dispatch_manifest.preview.json",
                "docs/MEMORY_BRIEF_2026-05-05.md",
            ],
            "commands": [
                "make vault-status",
                "make shared-memory-index",
                "make memory-brief",
            ],
        },
    }


def build_stale_source_guards(
    memory_root: Path,
    selected_branch: str,
    operational_snapshot: dict[str, Any],
    primary_vault: Path | None = None,
    generated_date: str = GENERATED_DATE,
) -> list[dict[str, Any]]:
    guards: list[dict[str, Any]] = []
    source_metadata = operational_snapshot.get("source_metadata", {})
    known_branch = source_metadata.get("known_limitations_branch")
    if isinstance(known_branch, str) and known_branch and selected_branch != "unknown" and known_branch != selected_branch:
        guards.append(
            _guard(
                "known_limitations_branch_mismatch",
                "WARN",
                "known-limitations dispatch branch metadata does not match selected memory-root branch",
                evidence={
                    "selected_memory_root": str(memory_root),
                    "selected_memory_root_branch": selected_branch,
                    "known_limitations_branch": known_branch,
                },
                blocking=False,
                freshness_scope="memory_metadata",
            )
        )
    if primary_vault is not None:
        vault_guard = _vault_freshness_guard(primary_vault, generated_date)
        if vault_guard:
            guards.append(vault_guard)
    if not guards:
        guards.append(
            _guard(
                "selected_memory_root",
                "READY",
                "entrypoint metadata was derived from the selected memory root",
                evidence={"selected_memory_root": str(memory_root), "selected_memory_root_branch": selected_branch},
            )
        )
    return guards


def build_report(root: Path = REPO_ROOT, generated_date: str = GENERATED_DATE) -> dict[str, Any]:
    root = root.resolve()
    root_candidates = memory_roots(root)
    memory_root = choose_memory_root(root, root_candidates).resolve()
    selected_branch = git_branch(memory_root)
    vault_candidates = candidate_vault_dirs(root)
    primary_vault = choose_primary_vault(vault_candidates)
    workspace_vault_entries = _workspace_vault_entries(memory_root)
    operational_snapshot = build_operational_snapshot(memory_root, selected_branch)
    stale_source_guards = build_stale_source_guards(
        memory_root,
        selected_branch,
        operational_snapshot,
        primary_vault=primary_vault,
        generated_date=generated_date,
    )

    vault_files = [
        Entry(label=rel, path=primary_vault / rel).as_dict()
        for rel in KEY_VAULT_FILES
    ]
    shared_memory = [
        Entry(label=label, path=memory_root / rel).as_dict(memory_root)
        for label, rel in SHARED_MEMORY_ENTRYPOINTS
    ]
    memory_brief = [
        Entry(label=label, path=memory_root / rel).as_dict(memory_root)
        for label, rel in MEMORY_BRIEF_ENTRYPOINTS
    ]
    vault_commands = [_command_status(memory_root, command) for command in VAULT_COMMANDS]
    mcp_commands = [_command_status(memory_root, command) for command in MCP_COMMANDS]
    memory_commands = [_command_status(memory_root, command) for command in MEMORY_COMMANDS]

    return {
        "schema": SCHEMA,
        "generated_date": generated_date,
        "repo_root": str(root),
        "memory_root": str(memory_root),
        "memory_branch": selected_branch,
        "network_used": False,
        "gui_opened": False,
        "active_vault": str(DEFAULT_ACTIVE_VAULT),
        "obsidian_open_note": OBSIDIAN_OPEN_NOTE,
        "non_obsidian_usage": NON_OBSIDIAN_USAGE,
        "human_answer": (
            f"Active vault: {primary_vault}. In Obsidian, use Open folder as vault; "
            "CLI open may not register it. Without Obsidian, read the Markdown "
            "docs and JSON reports directly."
        ),
        "primary_vault": {
            "path": str(primary_vault),
            "exists": primary_vault.exists(),
            "open_in_obsidian": "Open folder as vault",
        },
        "candidate_vaults": [
            {"path": str(path), "exists": path.exists(), "kind": _kind(path)}
            for path in vault_candidates
        ],
        "candidate_memory_roots": [
            {"path": str(path), "exists": path.exists(), "kind": _kind(path)}
            for path in root_candidates
        ],
        "key_vault_files": vault_files,
        "workspace_vault_files": workspace_vault_entries,
        "shared_memory_entrypoints": shared_memory,
        "memory_brief_entrypoints": memory_brief,
        "vault_commands": vault_commands,
        "mcp_commands": mcp_commands,
        "memory_commands": memory_commands,
        "operational_snapshot": operational_snapshot,
        "stale_source_guards": stale_source_guards,
        "freshness_summary": _guard_summary(stale_source_guards),
        "entrypoint_counts": {
            "candidate_vaults": {
                "total": len(vault_candidates),
                "present": sum(1 for path in vault_candidates if path.exists()),
                "missing": sum(1 for path in vault_candidates if not path.exists()),
            },
            "candidate_memory_roots": {
                "total": len(root_candidates),
                "present": sum(1 for path in root_candidates if path.exists()),
                "missing": sum(1 for path in root_candidates if not path.exists()),
            },
            "key_vault_files": _entry_count(vault_files),
            "workspace_vault_files": _entry_count(workspace_vault_entries),
            "shared_memory_entrypoints": _entry_count(shared_memory),
            "memory_brief_entrypoints": _entry_count(memory_brief),
            "vault_commands": _command_count(vault_commands),
            "mcp_commands": _command_count(mcp_commands),
            "memory_commands": _command_count(memory_commands),
        },
    }


def render_markdown(report: dict[str, Any]) -> str:
    counts = report["entrypoint_counts"]
    snapshot = report.get("operational_snapshot", {})
    current_state = snapshot.get("current_state", {})
    active_blockers = snapshot.get("active_blockers", {})
    next_loop = snapshot.get("next_loop", {})
    handoff = snapshot.get("pr_605_handoff", {})
    freshness = report.get("freshness_summary", {})
    blocking_guards = [row for row in report.get("stale_source_guards", []) if row.get("blocking")]
    nonblocking_guards = [
        row
        for row in report.get("stale_source_guards", [])
        if not row.get("blocking") and row.get("status") != "READY"
    ]
    lines = [
        "# Obsidian Memory Entrypoints - 2026-05-05",
        "",
        "Tiny offline pointer for humans and agents. No GUI or network is required.",
        "",
        "## Where to Look",
        "",
        f"- Active vault: `{report['active_vault']}`",
        f"- Obsidian vault folder: `{report['primary_vault']['path']}`",
        f"- Memory/control-plane root: `{report['memory_root']}`",
        f"- Memory/control-plane branch: `{report['memory_branch']}`",
        "- In Obsidian: use **Open folder as vault** and select that folder.",
        "- CLI caveat: `open <vault-folder>` may only open the folder in a file browser and may not register the vault in Obsidian.",
        "- Without Obsidian: read the Markdown docs and JSON reports directly; the memory surface is plain files.",
        "- First notes: `INDEX.md`, `INDEX_active.md`, `NEXT_LOOP.md`.",
        "- Model handoff surface: `docs/SHARED_MEMORY_INDEX_2026-05-05.md` and `docs/MEMORY_BRIEF_2026-05-05.md`.",
        "",
        "## Obsidian Optional",
        "",
        report["obsidian_open_note"],
        "",
        report["non_obsidian_usage"],
        "",
        "## Entrypoint Counts",
        "",
        "| Group | Present/Available | Total | Missing |",
        "|---|---:|---:|---:|",
    ]
    for key in (
        "candidate_vaults",
        "candidate_memory_roots",
        "key_vault_files",
        "workspace_vault_files",
        "shared_memory_entrypoints",
        "memory_brief_entrypoints",
        "vault_commands",
        "mcp_commands",
        "memory_commands",
    ):
        item = counts[key]
        present = item.get("present", item.get("available", 0))
        lines.append(f"| `{key}` | {present} | {item['total']} | {item['missing']} |")

    lines.extend(
        [
            "",
            "## Freshness Guards",
            "",
            f"- Operational freshness: `{freshness.get('operational_status', 'UNKNOWN')}`; blocking `{freshness.get('blocking_count', 0)}`; nonblocking `{freshness.get('nonblocking_count', 0)}`",
        ]
    )
    if blocking_guards:
        for row in blocking_guards:
            lines.append(f"- `{row['status']}` `{row['scope']}`: {row['message']}")
    else:
        lines.append("- No blocking stale-memory guards.")
    for row in nonblocking_guards:
        lines.append(f"- `{row['status']}` `{row['scope']}`: {row['message']}")

    if snapshot.get("priority_order"):
        lines.extend(
            [
                "",
                "## Priority Order",
                "",
                "- " + " > ".join(str(item) for item in snapshot["priority_order"]),
            ]
        )

    lines.extend(
        [
            "",
            "## Current Loop",
            "",
        ]
    )
    for bullet in current_state.get("github_state", []):
        lines.append(f"- {bullet}")
    for bullet in current_state.get("memory_state", []):
        lines.append(f"- {bullet}")
    for bullet in current_state.get("goal_status", []):
        lines.append(f"- {bullet}")
    lines.append(
        f"- Terminal completion allowed: `{current_state.get('terminal_completion_allowed')}`"
    )
    lines.extend(
        [
            "",
            "## Active Blockers",
            "",
            f"- Known blocked limitations: `{active_blockers.get('blocked_total', 0)}`",
            f"- Harness-memory open focus rows: `{active_blockers.get('harness_memory_open_focus_rows', 0)}`",
            f"- Harness-memory actionable open rows: `{active_blockers.get('harness_memory_actionable_open_rows', 0)}`",
            f"- Blocked backlog ids: `{', '.join(active_blockers.get('blocked_backlog', [])) or 'none'}`",
        ]
    )
    for item in active_blockers.get("items", []):
        lines.append(
            f"- `{item['limitation_id']}` (`{item['dispatch_lane']}`): {item['blocker']} Next: {item['next_action']}"
        )
    for item in active_blockers.get("harness_memory_actionability", []):
        lines.append(
            f"- `{item['id']}` `{item['next_action_status']}`: actionable_now_commands "
            f"`{len(item.get('actionable_now_commands', []))}`; blocked_templates "
            f"`{len(item.get('blocked_command_templates', []))}`"
        )
        if item.get("actionable_now_commands"):
            lines.append(f"  - Actionable now: `{item['actionable_now_commands'][0]}`")
        if item.get("blocked_command_templates"):
            lines.append(f"  - Blocked template: `{item['blocked_command_templates'][0]['command']}`")
    lines.extend(
        [
            "",
            "## Next-Loop Work",
            "",
            f"- Top ready-now items: `{', '.join(next_loop.get('top_ready_now', [])) or 'none'}`",
        ]
    )
    for row in next_loop.get("scheduled_loops", []):
        items = ", ".join(row.get("items", [])) or "none"
        lanes = ", ".join(row.get("lanes", [])) or "none"
        lines.append(
            f"- Loop {row['loop_index']}: items `{items}` on lanes `{lanes}` (expected cost `{row['total_expected_loop_cost']}`)"
        )
    for row in next_loop.get("top_gap_candidates", []):
        lines.append(
            f"- Gap `{row['gap_id']}` (`{row['category']}`): {row['title']} (priority `{row['priority_score']}`)"
        )
    preview = next_loop.get("dispatch_preview", {})
    lines.append(
        f"- Dispatch preview: `dispatchable={preview.get('dispatchable')}`; candidates `{preview.get('candidate_count', 0)}`; emitted slots `{preview.get('emitted_count', 0)}`"
    )
    for row in preview.get("preview_slots", []):
        lines.append(
            f"- `{row['slot_id']}` `{row['category']}` `{row['gap_id']}` dispatchable=`{row['dispatchable']}`"
        )
    lines.extend(
        [
            "",
            "## PR #605 Handoff",
            "",
            f"- Branch: `{handoff.get('branch')}`",
            f"- Goal state: `{handoff.get('goal_state')}`",
            f"- Memory packet blocked items: `{handoff.get('memory_packet_blocked_items_count')}`",
            f"- Day-to-day dispatch blockers: `{handoff.get('day_to_day_dispatch_blocker_count')}`",
            f"- Read first: `{', '.join(handoff.get('read_first', []))}`",
            f"- Refresh commands: `{', '.join(handoff.get('commands', []))}`",
            "",
            "## MCP / Vault Commands",
            "",
        ]
    )
    for entry in report["mcp_commands"]:
        marker = "available" if entry["available"] else "missing"
        lines.append(f"- `{entry['command']}` - {marker}")
    for entry in report["vault_commands"]:
        marker = "available" if entry["available"] else "missing"
        lines.append(f"- `{entry['command']}` - {marker}")
    lines.extend(["", "## Workspace Vault Files", ""])
    for entry in report["workspace_vault_files"]:
        marker = "present" if entry["exists"] else "missing"
        lines.append(f"- `{entry['path']}` - {marker}")
    lines.extend(["", "## Key Vault Files", ""])
    for entry in report["key_vault_files"]:
        marker = "present" if entry["exists"] else "missing"
        lines.append(f"- `{entry['path']}` - {marker}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=str(REPO_ROOT), help="auditooor repository root")
    parser.add_argument("--json", action="store_true", help="print JSON report to stdout")
    parser.add_argument("--markdown", action="store_true", help="print Markdown report to stdout")
    parser.add_argument("--output", help="write JSON report to this path")
    parser.add_argument("--markdown-output", help="write Markdown report to this path")
    args = parser.parse_args()

    report = build_report(Path(args.repo_root))

    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.markdown_output:
        output = Path(args.markdown_output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(render_markdown(report), encoding="utf-8")

    if args.markdown:
        print(render_markdown(report), end="")
    elif args.json or not (args.output or args.markdown_output):
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
