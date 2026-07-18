#!/usr/bin/env python3
"""Generate a low-context memory retrieval/bootstrap packet.

The packet is an offline handoff surface for Codex/Claude/Kimi/Minimax.  It
pulls only the live state needed to resume work: current checkout state,
memory-root state, closed/open KLBQ rows, next commands, and source-staleness
guards.  It deliberately points back to exact artifacts instead of expanding
the full docs/reports tree into a prompt.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "auditooor.memory_retrieval_bootstrap.v1"
DEFAULT_DATE = "2026-05-05"
DEFAULT_JSON_OUT = f"reports/memory_retrieval_bootstrap_{DEFAULT_DATE}.json"
DEFAULT_MARKDOWN_OUT = f"agent_briefs/AGENT_BOOTSTRAP_QUERY_{DEFAULT_DATE}.md"

ACTIVE_INTEGRATION_KLBQ = {"KLBQ-002"}
DEFAULT_MEMORY_ROOT_CANDIDATES: tuple[Path, ...] = ()
DEFAULT_VAULT_CANDIDATES = (
    Path("/Users/wolf/Documents/Codex/auditooor/obsidian-vault"),
    Path("/Users/wolf/Documents/Obsidian Vault"),
)

REQUIRED_MEMORY_ARTIFACTS = (
    "shared_memory_index",
    "memory_brief",
    "obsidian_memory_entrypoints",
    "known_limitations_harness_memory_status",
    "model_takeover_readiness",
)
OPTIONAL_MEMORY_ARTIFACTS = (
    "model_takeover_provider_handoff",
    "goal_loop_status",
    "known_limitations_dispatch",
    "next_50_loops",
    "scanner_worker_active_claims",
)
MEMORY_ARTIFACT_SPECS: dict[str, dict[str, Any]] = {
    "shared_memory_index": {
        "stem": "shared_memory_index",
        "fallback_path": "reports/shared_memory_index_2026-05-05.json",
        "required": True,
    },
    "memory_brief": {
        "stem": "memory_brief",
        "fallback_path": "reports/memory_brief_2026-05-05.json",
        "required": True,
    },
    "obsidian_memory_entrypoints": {
        "stem": "obsidian_memory_entrypoints",
        "fallback_path": "reports/obsidian_memory_entrypoints_2026-05-05.json",
        "required": True,
    },
    "known_limitations_harness_memory_status": {
        "stem": "known_limitations_harness_memory_status",
        "fallback_path": "reports/known_limitations_harness_memory_status_2026-05-05.json",
        "required": True,
    },
    "model_takeover_readiness": {
        "stem": "model_takeover_readiness",
        "fallback_path": "reports/model_takeover_readiness_2026-05-05.json",
        "required": True,
    },
    "model_takeover_provider_handoff": {
        "stem": "model_takeover_provider_handoff",
        "fallback_path": "reports/model_takeover_provider_handoff_2026-05-05.json",
        "required": False,
    },
    "goal_loop_status": {
        "stem": "goal_loop_status",
        "fallback_path": "reports/goal_loop_status_2026-05-05.json",
        "required": False,
    },
    "known_limitations_dispatch": {
        "stem": "known_limitations_dispatch",
        "fallback_path": "reports/known_limitations_dispatch_2026-05-05.json",
        "required": False,
    },
    "next_50_loops": {
        "stem": "next_50_loops",
        "fallback_path": "reports/next_50_loops_2026-05-05.json",
        "required": False,
    },
    "scanner_worker_active_claims": {
        "stem": "scanner_worker_active_claims",
        "fallback_path": "reports/scanner_worker_active_claims_2026-05-05.json",
        "required": False,
    },
}
MEMORY_ARTIFACT_ORDER = REQUIRED_MEMORY_ARTIFACTS + OPTIONAL_MEMORY_ARTIFACTS
VAULT_ENTRYPOINTS = (
    "DASHBOARD.md",
    "INDEX_active.md",
    "NEXT_LOOP.md",
    "dispatch/next_dispatch_manifest.preview.json",
    "knowledge-gaps/INDEX.md",
    "harness-failures/INDEX.md",
)
MEMORY_HANDOFF_COMMAND_PREFIXES = (
    "make vault-",
    "make shared-memory-index",
    "make memory-brief",
    "python3 tools/obsidian-",
    "python3 tools/shared-memory-index.py",
    "python3 tools/memory-brief.py",
)
SCANNER_WORKER_SLOT_CAP = 11
ASSIGNABLE_SCANNER_COORDINATION_STATUSES = {"unclaimed_from_local_checkout"}
SCANNER_DO_NOT_REDISPATCH_STATUSES = {
    "already_committed",
    "claimed_dirty_worktree",
    "local_evidence_present_refresh_needed",
}
SCANNER_REFRESH_RECOMMENDED_STATUSES = {
    "already_committed",
    "local_evidence_present_refresh_needed",
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _latest_report_rel_path(root: Path, stem: str, fallback_rel: str) -> str:
    reports_dir = root / "reports"
    if not reports_dir.is_dir():
        return fallback_rel
    matches = sorted(reports_dir.glob(f"{stem}_*.json"), key=lambda path: path.name)
    if not matches:
        return fallback_rel
    return str(matches[-1].relative_to(root))


def _resolve_memory_artifact_paths(memory_root: Path) -> dict[str, str]:
    paths: dict[str, str] = {}
    for key in MEMORY_ARTIFACT_ORDER:
        spec = MEMORY_ARTIFACT_SPECS[key]
        paths[key] = _latest_report_rel_path(memory_root, str(spec["stem"]), str(spec["fallback_path"]))
    return paths


def read_json(path: Path) -> tuple[dict[str, Any], str | None]:
    if not path.is_file():
        return {}, "missing"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {}, f"invalid JSON: {exc}"
    if not isinstance(payload, dict):
        return {}, "top-level JSON is not an object"
    return payload, None


def read_text(path: Path, limit: int = 40_000) -> str:
    if not path.is_file():
        return ""
    text = path.read_text(encoding="utf-8", errors="replace")
    return text[:limit]


def compact_text(value: Any, limit: int = 220) -> str:
    text = " ".join(str(value).split())
    if len(text) > limit:
        return text[: limit - 3].rstrip() + "..."
    return text


def _compact_path_list(value: Any, limit: int = 6) -> list[str]:
    return [compact_text(item, 160) for item in _list_from(value)[:limit] if compact_text(item, 160)]


def scanner_coordination_guidance(scanner_snapshot: dict[str, Any]) -> dict[str, Any]:
    raw_guidance = _dict_from(scanner_snapshot.get("scanner_coordination_guidance"))
    if raw_guidance:
        return {
            "do_not_redispatch_statuses": [
                compact_text(item, 80)
                for item in _list_from(raw_guidance.get("do_not_redispatch_statuses"))[:6]
            ],
            "do_not_redispatch_sample_row_ids": [
                compact_text(item, 120)
                for item in _list_from(raw_guidance.get("do_not_redispatch_sample_row_ids"))[:10]
            ],
            "refresh_inventory_before_more_detector_assignments": bool(
                raw_guidance.get("refresh_inventory_before_more_detector_assignments")
            ),
            "refresh_recommended_statuses": [
                compact_text(item, 80)
                for item in _list_from(raw_guidance.get("refresh_recommended_statuses"))[:6]
            ],
            "reason": compact_text(raw_guidance.get("reason"), 260),
        }

    selector = _dict_from(scanner_snapshot.get("scanner_worker_next_rows"))
    selection = _dict_from(selector.get("selection"))
    counts = {
        str(key): int(value)
        for key, value in _dict_from(selection.get("skipped_counts")).items()
        if str(key) and isinstance(value, int) and value > 0
    }
    statuses = [status for status in sorted(SCANNER_DO_NOT_REDISPATCH_STATUSES) if counts.get(status, 0)]
    refresh_statuses = [status for status in sorted(SCANNER_REFRESH_RECOMMENDED_STATUSES) if counts.get(status, 0)]
    return {
        "do_not_redispatch_statuses": statuses,
        "do_not_redispatch_sample_row_ids": [
            compact_text(row.get("row_id"), 120)
            for row in _list_from(scanner_snapshot.get("skipped_worker_slots"))[:10]
            if isinstance(row, dict)
            and compact_text(row.get("skip_reason"), 80) in SCANNER_DO_NOT_REDISPATCH_STATUSES
        ],
        "refresh_inventory_before_more_detector_assignments": bool(refresh_statuses),
        "refresh_recommended_statuses": refresh_statuses,
        "reason": (
            "scanner-worker-next-rows skipped rows with committed or complete local evidence; refresh scanner inventory before assigning more detector work from stale memory"
            if refresh_statuses
            else "scanner skip samples only show dirty local claims; avoid those rows until commit or refresh"
            if statuses
            else "no stale scanner skip signal was present"
        ),
    }


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
    return proc.stdout.rstrip("\n")


def git_status_path(status_line: str) -> str:
    if len(status_line) < 4:
        return status_line.strip()
    path = status_line[3:].strip()
    if " -> " in path:
        path = path.rsplit(" -> ", 1)[-1].strip()
    return path


def git_state(root: Path, *, ignored_dirty_paths: Iterable[str] = ()) -> dict[str, Any]:
    status = _git(root, "status", "--short")
    dirty_paths = [line for line in status.splitlines() if line.strip()]
    ignored = set(ignored_dirty_paths)
    external_dirty_paths = [
        line for line in dirty_paths if git_status_path(line) not in ignored
    ]
    ignored_paths = [
        line for line in dirty_paths if git_status_path(line) in ignored
    ]
    external_dirty_path_names = [git_status_path(line) for line in external_dirty_paths]
    ignored_path_names = [git_status_path(line) for line in ignored_paths]
    return {
        "root": str(root.resolve()),
        "branch": _git(root, "branch", "--show-current") or _git(root, "rev-parse", "--abbrev-ref", "HEAD") or "unknown",
        "head_at_generation": _git(root, "rev-parse", "--short", "HEAD") or "unknown",
        "dirty": bool(external_dirty_paths),
        "dirty_path_count": len(external_dirty_paths),
        "dirty_path_sample": external_dirty_paths[:8],
        "dirty_paths": external_dirty_path_names[:80],
        "raw_dirty_path_count": len(dirty_paths),
        "ignored_self_generated_dirty_path_count": len(ignored_paths),
        "ignored_self_generated_dirty_path_sample": ignored_paths[:8],
        "ignored_self_generated_dirty_paths": ignored_path_names[:20],
    }


def _has_report_with_stem(root: Path, stem: str) -> bool:
    reports_dir = root / "reports"
    if not reports_dir.is_dir():
        return False
    return any(path.is_file() for path in reports_dir.glob(f"{stem}_*.json"))


def choose_memory_root(root: Path, explicit: str | None) -> Path:
    if explicit:
        return Path(explicit).expanduser().resolve()
    env = os.environ.get("AUDITOOOR_MEMORY_ROOT")
    if env:
        return Path(env).expanduser().resolve()
    if _has_report_with_stem(root, "shared_memory_index"):
        return root.resolve()
    for candidate in DEFAULT_MEMORY_ROOT_CANDIDATES:
        if _has_report_with_stem(candidate, "shared_memory_index"):
            return candidate.resolve()
    return root.resolve()


def choose_vault_root(explicit: str | None, obsidian_report: dict[str, Any]) -> Path:
    if explicit:
        return Path(explicit).expanduser().resolve()
    env = os.environ.get("AUDITOOOR_OBSIDIAN_VAULT")
    if env:
        return Path(env).expanduser().resolve()
    primary = obsidian_report.get("primary_vault")
    if isinstance(primary, dict) and isinstance(primary.get("path"), str):
        path = Path(primary["path"]).expanduser()
        if path.exists():
            return path.resolve()
    for candidate in DEFAULT_VAULT_CANDIDATES:
        if candidate.exists():
            return candidate.resolve()
    return DEFAULT_VAULT_CANDIDATES[0].resolve()


def date_prefix(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    match = re.search(r"20\d{2}-\d{2}-\d{2}", value)
    return match.group(0) if match else ""


def artifact_date(payload: dict[str, Any]) -> str:
    for key in ("generated_date", "date", "generated_at", "generated"):
        found = date_prefix(payload.get(key))
        if found:
            return found
    return ""


def guard(
    scope: str,
    status: str,
    message: str,
    *,
    evidence: Any = None,
    blocking: bool | None = None,
    freshness_scope: str = "operational_memory",
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "scope": scope,
        "status": status,
        "message": compact_text(message, 320),
        "blocking": status == "BLOCKED" if blocking is None else blocking,
        "freshness_scope": freshness_scope,
    }
    if evidence is not None:
        row["evidence"] = evidence
    return row


def guard_summary(guards: list[dict[str, Any]]) -> dict[str, Any]:
    blocking = [row for row in guards if row.get("blocking")]
    nonblocking = [row for row in guards if not row.get("blocking") and row.get("status") != "READY"]
    return {
        "operational_status": "BLOCKED" if blocking else "READY",
        "blocking_count": len(blocking),
        "nonblocking_count": len(nonblocking),
        "blocking_scopes": [str(row.get("scope") or "") for row in blocking],
        "nonblocking_scopes": [str(row.get("scope") or "") for row in nonblocking],
        "status_counts": {
            status: sum(1 for row in guards if row.get("status") == status)
            for status in sorted({str(row.get("status") or "") for row in guards})
        },
    }


def is_memory_handoff_command(command: str) -> bool:
    return command.startswith(MEMORY_HANDOFF_COMMAND_PREFIXES)


def artifact_inventory(memory_root: Path) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], dict[str, str]]:
    rows: list[dict[str, Any]] = []
    loaded: dict[str, dict[str, Any]] = {}
    paths = _resolve_memory_artifact_paths(memory_root)
    for key in MEMORY_ARTIFACT_ORDER:
        rel = paths[key]
        path = memory_root / rel
        payload, error = read_json(path)
        required = bool(MEMORY_ARTIFACT_SPECS[key]["required"])
        rows.append(
            {
                "key": key,
                "path": rel,
                "required": required,
                "present": error is None,
                "error": error,
                "schema": payload.get("schema", "") if not error else "",
                "artifact_date": artifact_date(payload) if not error else "",
            }
        )
        if not error:
            loaded[key] = payload
    return rows, loaded, paths


def vault_inventory(vault_root: Path) -> dict[str, Any]:
    files = []
    for rel in VAULT_ENTRYPOINTS:
        path = vault_root / rel
        files.append({"path": rel, "present": path.is_file()})
    dashboard_text = read_text(vault_root / "DASHBOARD.md", limit=8_000)
    generated = ""
    last_sync = ""
    generated_match = re.search(r"generated:\s*\"?([^\"\n]+)", dashboard_text, flags=re.I)
    sync_match = re.search(r"last_sync:\s*\"?([^\"\n]+)", dashboard_text, flags=re.I)
    if generated_match:
        generated = compact_text(generated_match.group(1), 80)
    if sync_match:
        last_sync = compact_text(sync_match.group(1), 80)
    return {
        "root": str(vault_root),
        "present": vault_root.is_dir(),
        "files": files,
        "generated": generated,
        "last_sync": last_sync,
    }


def _list_from(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _dict_from(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _slug(value: Any) -> str:
    text = str(value or "").lower()
    text = re.sub(r"[^a-z0-9]+", "_", text).strip("_")
    while "__" in text:
        text = text.replace("__", "_")
    return text


def _path_is_within(path: str, prefix: str) -> bool:
    clean_path = path.strip().strip("/")
    clean_prefix = prefix.strip().strip("/")
    if not clean_path or not clean_prefix:
        return False
    return clean_path == clean_prefix or clean_path.startswith(clean_prefix.rstrip("/") + "/")


def _scanner_slot_dirty_matches(slot: dict[str, Any], dirty_paths: list[str]) -> list[str]:
    row_slug = _slug(slot.get("row_id"))
    row_hyphen = row_slug.replace("_", "-")
    owned_paths = [str(item).strip() for item in _list_from(slot.get("owned_paths")) if str(item).strip()]
    matches: list[str] = []
    for dirty_path in dirty_paths:
        normalized_dirty = _slug(dirty_path)
        matched = any(_path_is_within(dirty_path, owned) for owned in owned_paths)
        if not matched and row_slug and len(row_slug) > 5:
            matched = row_slug in normalized_dirty or row_hyphen in dirty_path.lower()
        if matched and dirty_path not in matches:
            matches.append(dirty_path)
    return matches[:8]


def _existing_row_evidence_paths(root: Path, slot: dict[str, Any]) -> tuple[list[str], dict[str, bool]]:
    row_slug = _slug(slot.get("row_id"))
    fixture_candidates: list[str] = []
    test_candidates: list[str] = []
    for raw in _list_from(slot.get("owned_paths")):
        text = str(raw).strip()
        if not text:
            continue
        if text.startswith("detectors/fixtures/"):
            parts = Path(text).parts
            if len(parts) >= 3:
                fixture_candidates.append(str(Path(*parts[:3])))
        if text.startswith("tools/tests/test_") and text.endswith(".py"):
            test_candidates.append(text)
    if row_slug:
        fixture_candidates.extend(
            [
                f"detectors/fixtures/{row_slug}",
                f"detectors/fixtures/{row_slug.replace('_', '-')}",
            ]
        )
        test_candidates.append(f"tools/tests/test_{row_slug}.py")

    existing: list[str] = []
    flags = {
        "fixture_dir_present": False,
        "smoke_json_present": False,
        "test_present": False,
    }
    for rel in sorted(dict.fromkeys(fixture_candidates)):
        path = root / rel
        if not path.exists():
            continue
        flags["fixture_dir_present"] = True
        existing.append(rel)
        if path.is_dir():
            smoke = sorted(path.glob("*smoke*.json"))
            if smoke:
                flags["smoke_json_present"] = True
                existing.extend(str(item.relative_to(root)) for item in smoke[:3])
    for rel in sorted(dict.fromkeys(test_candidates)):
        path = root / rel
        if path.is_file():
            flags["test_present"] = True
            existing.append(rel)
    return sorted(dict.fromkeys(existing))[:8], flags


def scanner_slot_coordination(root: Path, slot: dict[str, Any], current_state: dict[str, Any]) -> dict[str, Any]:
    dirty_matches = _scanner_slot_dirty_matches(slot, _list_from(current_state.get("dirty_paths")))
    evidence_paths, evidence_flags = _existing_row_evidence_paths(root, slot)
    if dirty_matches:
        status = "claimed_dirty_worktree"
        note = "Matching uncommitted row paths exist in the active checkout; do not redispatch until that worker commits or the coordinator refreshes memory."
    elif evidence_flags["smoke_json_present"] and evidence_flags["test_present"]:
        status = "local_evidence_present_refresh_needed"
        note = "Local smoke/test evidence exists for this row; refresh scanner burndown before assigning it from a stale packet."
    elif evidence_paths:
        status = "local_partial_evidence_present"
        note = "Some local row artifacts exist; inspect before assigning because the packet may be stale."
    else:
        status = "unclaimed_from_local_checkout"
        note = "No matching dirty paths or row-local proof artifacts were detected in the active checkout."
    return {
        "local_coordination_status": status,
        "matching_dirty_paths": dirty_matches,
        "local_evidence_paths": evidence_paths,
        "coordination_note": note,
    }


def _row_id(row: dict[str, Any]) -> str:
    value = row.get("id") or row.get("limitation_id") or row.get("gap_id") or ""
    return str(value)


def compact_klbq_row(row: dict[str, Any], source: str) -> dict[str, Any]:
    return {
        "id": _row_id(row),
        "source": source,
        "dispatch_lane": row.get("dispatch_lane", ""),
        "current_status": row.get("current_status") or row.get("status") or "",
        "owner_lane": row.get("owner_lane", ""),
        "next_action_status": compact_text(row.get("next_action_status", ""), 160),
        "next_action": compact_text(row.get("next_action", ""), 260),
        "actionable_now_commands": [compact_text(item, 240) for item in _list_from(row.get("actionable_now_commands"))[:5]],
        "blocked_command_templates": [
            {
                "command": compact_text(item.get("command", ""), 240),
                "missing_inputs": [compact_text(raw, 100) for raw in _list_from(item.get("missing_inputs"))[:4]],
                "unblock_criteria": [compact_text(raw, 160) for raw in _list_from(item.get("unblock_criteria"))[:3]],
            }
            for item in _list_from(row.get("blocked_command_templates"))[:3]
            if isinstance(item, dict)
        ],
        "blockers": [compact_text(item, 220) for item in _list_from(row.get("blockers"))[:4]],
        "verification_commands": [compact_text(item, 220) for item in _list_from(row.get("verification_commands"))[:4]],
        "evidence_paths": [compact_text(item, 160) for item in _list_from(row.get("evidence_paths"))[:5]],
        "open": bool(row.get("open")),
    }


def klbq_open_closed_ids(klbq_status: dict[str, Any]) -> tuple[set[str], set[str]]:
    open_ids: set[str] = set()
    closed_ids: set[str] = set()
    for key in ("verified_focus_rows", "related_harness_memory_rows", "open_focus_rows"):
        for row in _list_from(klbq_status.get(key)):
            if not isinstance(row, dict):
                continue
            klbq_id = _row_id(row)
            if not klbq_id.startswith("KLBQ-"):
                continue
            status_text = str(row.get("current_status") or row.get("status") or "").lower()
            row_is_open = bool(row.get("open")) or "open" in status_text or "partial" in status_text
            if row_is_open:
                open_ids.add(klbq_id)
            else:
                closed_ids.add(klbq_id)
    return open_ids, closed_ids


def extract_klbq_state(klbq_status: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    closed: list[dict[str, Any]] = []
    open_rows: list[dict[str, Any]] = []
    for key in ("verified_focus_rows", "related_harness_memory_rows", "open_focus_rows"):
        for row in _list_from(klbq_status.get(key)):
            if not isinstance(row, dict):
                continue
            klbq_id = _row_id(row)
            if not klbq_id.startswith("KLBQ-"):
                continue
            compact = compact_klbq_row(row, key)
            status_text = str(compact.get("current_status", "")).lower()
            row_is_open = bool(row.get("open")) or "open" in status_text or "partial" in status_text
            if row_is_open:
                compact["open"] = True
                open_rows.append(compact)
            else:
                compact["open"] = False
                closed.append(compact)
    seen_closed: set[str] = set()
    deduped_closed = []
    for row in closed:
        key = f"{row['id']}:{row['source']}"
        if key not in seen_closed:
            seen_closed.add(key)
            deduped_closed.append(row)
    seen_open: set[str] = set()
    deduped_open = []
    for row in open_rows:
        key = f"{row['id']}:{row['source']}"
        if key not in seen_open:
            seen_open.add(key)
            deduped_open.append(row)
    return deduped_closed, deduped_open


def extract_priority(
    obsidian_report: dict[str, Any],
    klbq_status: dict[str, Any],
    readiness: dict[str, Any],
    memory_state: dict[str, Any],
    *,
    current_root: Path | None = None,
    current_state: dict[str, Any] | None = None,
    scanner_active_claims: dict[str, Any] | None = None,
    scanner_active_claims_path: str = "reports/scanner_worker_active_claims_2026-05-05.json",
) -> dict[str, Any]:
    snapshot = _dict_from(obsidian_report.get("operational_snapshot"))
    next_loop = _dict_from(snapshot.get("next_loop"))
    active_blockers = _dict_from(snapshot.get("active_blockers"))
    operational_current_state = _dict_from(snapshot.get("current_state"))
    open_ids, closed_ids = klbq_open_closed_ids(klbq_status)
    closed_only = closed_ids - open_ids
    blocked_backlog = [
        str(item)
        for item in _list_from(active_blockers.get("blocked_backlog"))
        if str(item) not in closed_only
    ]
    selected_branch = str(memory_state.get("branch") or "")
    actionable_open_rows = [
        {
            "id": row["id"],
            "next_action_status": row.get("next_action_status", ""),
            "actionable_now_command_count": len(row.get("actionable_now_commands", [])),
            "blocked_command_template_count": len(row.get("blocked_command_templates", [])),
        }
        for row in extract_klbq_state(klbq_status)[1]
        if row.get("actionable_now_commands") or row.get("blocked_command_templates")
    ]
    scanner_snapshot = _dict_from(klbq_status.get("scanner_burndown_snapshot"))
    scanner_worker_slots = []
    skipped_scanner_worker_slots = [
        {
            "row_id": compact_text(row.get("row_id", ""), 120),
            "rank": row.get("rank"),
            "lane": compact_text(row.get("lane", ""), 80),
            "local_coordination_status": compact_text(row.get("local_coordination_status", ""), 80),
            "skip_reason": compact_text(row.get("skip_reason", ""), 120),
            "coordination_note": compact_text(row.get("coordination_note", ""), 220),
            "matching_dirty_paths": _compact_path_list(row.get("matching_dirty_paths")),
            "local_evidence_paths": _compact_path_list(row.get("local_evidence_paths")),
            "committed_after_queue_paths": _compact_path_list(row.get("committed_after_queue_paths")),
        }
        for row in _list_from(scanner_snapshot.get("skipped_worker_slots"))[:10]
        if isinstance(row, dict)
    ]
    worker_slot_coordination_counts: dict[str, int] = {
        str(key): int(value)
        for key, value in _dict_from(scanner_snapshot.get("worker_slot_coordination_counts")).items()
        if str(key)
        and isinstance(value, int)
    }
    for row in _list_from(scanner_snapshot.get("next_worker_slots")):
        if not isinstance(row, dict):
            continue
        slot = {
            "slot_id": compact_text(row.get("slot_id", ""), 40),
            "row_id": compact_text(row.get("row_id", ""), 120),
            "lane": compact_text(row.get("lane", ""), 80),
            "rank": row.get("rank"),
            "model_hint": compact_text(row.get("model_hint", ""), 80),
            "owned_paths": [compact_text(item, 160) for item in _list_from(row.get("owned_paths"))[:6]],
            "acceptance_criteria": [
                compact_text(item, 160) for item in _list_from(row.get("acceptance_criteria"))[:4]
            ],
        }
        if current_root is not None and current_state is not None:
            slot.update(scanner_slot_coordination(current_root, slot, current_state))
        status_key = str(slot.get("local_coordination_status") or "uncoordinated")
        if not worker_slot_coordination_counts:
            worker_slot_coordination_counts[status_key] = worker_slot_coordination_counts.get(status_key, 0) + 1
        if current_root is not None and current_state is not None:
            if status_key not in ASSIGNABLE_SCANNER_COORDINATION_STATUSES:
                skipped = dict(slot)
                skipped["skip_reason"] = status_key
                skipped_scanner_worker_slots.append(skipped)
                continue
        scanner_worker_slots.append(slot)
        if len(scanner_worker_slots) >= SCANNER_WORKER_SLOT_CAP:
            break
    return {
        "priority_order": ["MEMORY", "HARNESS", "KNOWN LIMITATION BURNDOWN"],
        "execution_priority_policy": _dict_from(klbq_status.get("execution_priority_policy")),
        "current_branch_from_memory": selected_branch,
        "branch_from_obsidian_report": snapshot.get("branch") or "",
        "branch_from_klbq_status": klbq_status.get("branch") or "",
        "goal_status": _list_from(operational_current_state.get("goal_status"))[:2],
        "terminal_completion_allowed": operational_current_state.get("terminal_completion_allowed"),
        "top_ready_now": _list_from(next_loop.get("top_ready_now"))[:8],
        "blocked_backlog": blocked_backlog[:8],
        "scheduled_loops": _list_from(next_loop.get("scheduled_loops"))[:3],
        "top_gap_candidates": _list_from(next_loop.get("top_gap_candidates"))[:3],
        "actionable_open_rows": actionable_open_rows[:6],
        "scanner_worker_slots": scanner_worker_slots,
        "scanner_worker_slot_count": len(scanner_worker_slots),
        "scanner_worker_slot_cap": SCANNER_WORKER_SLOT_CAP,
        "active_scanner_claims": compact_active_scanner_claims(scanner_active_claims, scanner_active_claims_path),
        "skipped_scanner_worker_slots": skipped_scanner_worker_slots[:10],
        "skipped_scanner_worker_slot_count": (
            scanner_snapshot.get("skipped_worker_slot_count")
            if scanner_snapshot.get("skipped_worker_slot_count") is not None
            else len(skipped_scanner_worker_slots)
        ),
        "scanner_worker_slot_coordination_counts": dict(sorted(worker_slot_coordination_counts.items())),
        "scanner_worker_next_rows": _dict_from(scanner_snapshot.get("scanner_worker_next_rows")),
        "scanner_coordination_guidance": scanner_coordination_guidance(scanner_snapshot),
        "readiness_categories": _dict_from(readiness.get("categories")),
    }


def compact_active_scanner_claims(payload: dict[str, Any] | None, source_path: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {
            "present": False,
            "active": 0,
            "completed": 0,
            "active_rows": [],
            "source_path": source_path,
        }
    claims = [
        row for row in _list_from(payload.get("active_claims"))
        if isinstance(row, dict)
    ]
    active_claims = [
        row for row in claims
        if compact_text(row.get("status"), 40) == "active"
    ]
    completed_claims = [
        row for row in claims
        if compact_text(row.get("status"), 40) == "completed"
    ]
    summary = _dict_from(payload.get("summary"))
    return {
        "present": True,
        "source_path": source_path,
        "updated_at": compact_text(payload.get("updated_at"), 80),
        "active": int(summary.get("active", len(active_claims)) or 0),
        "completed": int(summary.get("completed", len(completed_claims)) or 0),
        "active_rows": [
            {
                "agent_id": compact_text(row.get("agent_id"), 80),
                "row_id": compact_text(row.get("row_id"), 120),
            }
            for row in active_claims[:SCANNER_WORKER_SLOT_CAP]
        ],
    }


def extract_commit_mining_source_disposition(klbq_status: dict[str, Any]) -> dict[str, Any]:
    snapshot = _dict_from(klbq_status.get("commit_mining_source_disposition_snapshot"))
    if not snapshot:
        return {
            "status": "not_recorded",
            "queued_actionable_count": 0,
            "completed_next_step_count": 0,
            "source_packets_emitted": 0,
            "source_packets_seen": 0,
            "top_dispositions": [],
            "strict_caveat": "Commit-mining source disposition is not present in the selected harness-memory status packet.",
        }
    return {
        "status": compact_text(snapshot.get("status", ""), 120),
        "path": compact_text(snapshot.get("path", ""), 160),
        "queued_actionable_count": snapshot.get("queued_actionable_count", 0),
        "completed_next_step_count": snapshot.get("completed_next_step_count", 0),
        "source_packets_emitted": snapshot.get("source_packets_emitted", 0),
        "source_packets_seen": snapshot.get("source_packets_seen", 0),
        "blocked_no_op_count": snapshot.get("blocked_no_op_count", 0),
        "top_dispositions": [
            {
                "status": compact_text(item.get("status", ""), 120),
                "source_row_id": compact_text(item.get("source_row_id", ""), 80),
                "task_id": compact_text(item.get("task_id", ""), 100),
                "target": compact_text(item.get("target", ""), 80),
                "action_type": compact_text(item.get("action_type", ""), 80),
                "packet_status": compact_text(item.get("packet_status", ""), 100),
                "next_action": compact_text(item.get("next_action", ""), 220),
                "evidence_path": compact_text(item.get("evidence_path", ""), 160),
            }
            for item in _list_from(snapshot.get("top_dispositions"))[:5]
            if isinstance(item, dict)
        ],
        "strict_caveat": compact_text(snapshot.get("strict_caveat", ""), 260),
    }


def add_command(
    commands: list[dict[str, Any]],
    seen: set[str],
    scope: str,
    lane: str,
    command: str,
    reason: str,
    source_path: str,
) -> None:
    if not command or command in seen:
        return
    seen.add(command)
    commands.append(
        {
            "scope": scope,
            "lane": lane,
            "command": command,
            "reason": compact_text(reason, 220),
            "source_path": source_path,
        }
    )


def exact_next_commands(
    current_root: Path,
    memory_root: Path,
    obsidian_report: dict[str, Any],
    open_klbq: list[dict[str, Any]],
    *,
    obsidian_report_path: str,
    klbq_status_path: str,
) -> list[dict[str, Any]]:
    commands: list[dict[str, Any]] = []
    seen: set[str] = set()
    add_command(
        commands,
        seen,
        "bootstrap",
        "memory",
        "python3 tools/memory-retrieval-bootstrap.py --root . --print-markdown",
        "Regenerate or print this compact retrieval packet from the active checkout.",
        "tools/memory-retrieval-bootstrap.py",
    )
    add_command(
        commands,
        seen,
        "current_checkout",
        "memory",
        f"git -C {current_root} status --short",
        "Check whether the handoff branch/worktree changed before editing.",
        ".git",
    )
    add_command(
        commands,
        seen,
        "memory_root",
        "memory",
        f"git -C {memory_root} status --short",
        "Check whether the source memory root is dirty before trusting refreshed state.",
        obsidian_report_path,
    )

    handoff = _dict_from(_dict_from(obsidian_report.get("operational_snapshot")).get("pr_605_handoff"))
    for raw in _list_from(handoff.get("commands"))[:5]:
        if not isinstance(raw, str):
            continue
        if not is_memory_handoff_command(raw):
            continue
        if raw.startswith("make "):
            target = raw.split(maxsplit=1)[1]
            command = f"make -C {memory_root} {target}"
        elif raw.startswith("python3 "):
            command = f"cd {memory_root} && {raw}"
        else:
            command = raw
        add_command(
            commands,
            seen,
            "memory_refresh",
            "memory",
            command,
            "Memory-root handoff command recorded by the operational snapshot.",
            obsidian_report_path,
        )

    add_command(
        commands,
        seen,
        "model_takeover",
        "memory",
        f"python3 {memory_root / 'tools' / 'model-takeover-handoff.py'} --root {memory_root} --mode compact-check --stdout-format summary",
        "Rebuild the bounded model-takeover handoff check before provider handoff.",
        "tools/model-takeover-handoff.py",
    )

    for row in open_klbq:
        if row["id"] in ACTIVE_INTEGRATION_KLBQ:
            continue
        row_commands = row.get("actionable_now_commands") or row.get("verification_commands", [])
        for command in row_commands[:3]:
            rooted_command = command
            if isinstance(command, str) and not command.startswith(("git -C ", "make -C ", "cd ")):
                rooted_command = f"cd {memory_root} && {command}"
            add_command(
                commands,
                seen,
                row["id"],
                "klbq",
                rooted_command,
                f"Actionable-now command for open {row['id']} row."
                if row.get("actionable_now_commands")
                else f"Verification command for open {row['id']} row.",
                klbq_status_path,
            )
    return commands[:16]


def build_guards(
    current_root: Path,
    current_state: dict[str, Any],
    memory_root: Path,
    memory_state: dict[str, Any],
    vault: dict[str, Any],
    artifacts: list[dict[str, Any]],
    loaded: dict[str, dict[str, Any]],
    open_klbq: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    guards: list[dict[str, Any]] = []
    for row in artifacts:
        if row["required"] and not row["present"]:
            guards.append(
                guard(
                    "required_artifact",
                    "BLOCKED",
                    f"{row['path']} is missing or invalid",
                    evidence=row,
                    blocking=True,
                    freshness_scope="memory_artifact",
                )
            )
        elif row["present"] and row["artifact_date"] and row["artifact_date"] < DEFAULT_DATE:
            status = "BLOCKED" if row["required"] else "WARN"
            guards.append(
                guard(
                    "artifact_freshness",
                    status,
                    f"{row['path']} has artifact date {row['artifact_date']} older than {DEFAULT_DATE}",
                    evidence=row["path"],
                    blocking=row["required"],
                    freshness_scope="memory_artifact",
                )
            )
    if not current_root.exists():
        guards.append(
            guard(
                "current_root",
                "BLOCKED",
                "current checkout root is missing",
                evidence=str(current_root),
                blocking=True,
                freshness_scope="checkout_state",
            )
        )
    obsidian = loaded.get("obsidian_memory_entrypoints", {})
    current_branch = current_state.get("branch")
    memory_branch = memory_state.get("branch")
    if current_branch in (None, "", "unknown"):
        guards.append(
            guard(
                "current_branch_mismatch",
                "WARN",
                "current checkout branch could not be resolved",
                evidence=current_branch,
                blocking=False,
                freshness_scope="checkout_state",
            )
        )
    elif (
        current_root.resolve() != memory_root.resolve()
        and memory_branch not in (None, "", "unknown")
        and current_branch != memory_branch
    ):
        guards.append(
            guard(
                "current_memory_branch_mismatch",
                "WARN",
                "current checkout branch does not match selected memory-root branch",
                evidence={"current_branch": current_branch, "memory_branch": memory_branch},
                blocking=False,
                freshness_scope="memory_metadata",
            )
        )
    if current_state.get("dirty"):
        guards.append(
            guard(
                "current_dirty",
                "WARN",
                "current checkout has uncommitted changes; commit or inspect before treating packet as final",
                evidence=current_state.get("dirty_path_sample"),
                blocking=False,
                freshness_scope="checkout_state",
            )
        )
    if memory_state.get("dirty"):
        guards.append(
            guard(
                "memory_root_dirty",
                "WARN",
                "memory source root is dirty; generated packet records it as external mutable state",
                evidence=memory_state.get("dirty_path_sample"),
                blocking=False,
                freshness_scope="checkout_state",
            )
        )

    readiness = loaded.get("model_takeover_readiness", {})
    readiness_root = readiness.get("root")
    if isinstance(readiness_root, str) and Path(readiness_root).resolve() != memory_root.resolve():
        guards.append(
            guard(
                "readiness_root_mismatch",
                "WARN",
                "model-takeover readiness root does not match selected memory root",
                evidence={"readiness_root": readiness_root, "memory_root": str(memory_root)},
                blocking=False,
                freshness_scope="memory_metadata",
            )
        )

    report_memory_root = obsidian.get("memory_root")
    if isinstance(report_memory_root, str) and Path(report_memory_root).resolve() != memory_root.resolve():
        guards.append(
            guard(
                "obsidian_memory_root_mismatch",
                "WARN",
                "obsidian entrypoint report points at a different memory root",
                evidence={"report_memory_root": report_memory_root, "memory_root": str(memory_root)},
                blocking=False,
                freshness_scope="memory_metadata",
            )
        )
    obsidian_snapshot = _dict_from(obsidian.get("operational_snapshot"))
    report_branch = obsidian.get("memory_branch") or obsidian_snapshot.get("branch")
    selected_branch = memory_state.get("branch")
    if (
        isinstance(report_branch, str)
        and report_branch
        and selected_branch
        and selected_branch != "unknown"
        and report_branch != selected_branch
    ):
        guards.append(
            guard(
                "obsidian_branch_mismatch",
                "WARN",
                "obsidian entrypoint report branch metadata does not match selected memory-root branch",
                evidence={"report_branch": report_branch, "memory_branch": selected_branch, "memory_root": str(memory_root)},
                blocking=False,
                freshness_scope="memory_metadata",
            )
        )

    klbq_branch = loaded.get("known_limitations_harness_memory_status", {}).get("branch")
    if (
        isinstance(klbq_branch, str)
        and klbq_branch
        and selected_branch
        and selected_branch != "unknown"
        and klbq_branch != selected_branch
    ):
        guards.append(
            guard(
                "klbq_branch_mismatch",
                "WARN",
                "known-limitations harness-memory branch metadata does not match selected memory-root branch",
                evidence={"klbq_branch": klbq_branch, "memory_branch": selected_branch, "memory_root": str(memory_root)},
                blocking=False,
                freshness_scope="memory_metadata",
            )
        )
    klbq_worktree = loaded.get("known_limitations_harness_memory_status", {}).get("worktree")
    if isinstance(klbq_worktree, str) and Path(klbq_worktree).resolve() != memory_root.resolve():
        guards.append(
            guard(
                "klbq_worktree_mismatch",
                "WARN",
                "known-limitations harness-memory worktree metadata does not match selected memory root",
                evidence={"klbq_worktree": klbq_worktree, "memory_root": str(memory_root)},
                blocking=False,
                freshness_scope="memory_metadata",
            )
        )

    if not vault.get("present"):
        guards.append(
            guard(
                "obsidian_vault",
                "ADVISORY",
                "external active Obsidian vault directory is not present; generated memory reports remain authoritative",
                evidence=vault.get("root"),
                blocking=False,
                freshness_scope="external_active_vault",
            )
        )
    for file_row in vault.get("files", []):
        if file_row.get("path") in {"DASHBOARD.md", "INDEX_active.md", "NEXT_LOOP.md"} and not file_row.get("present"):
            guards.append(
                guard(
                    "obsidian_vault_file",
                    "ADVISORY",
                    "external active-vault entrypoint is missing; use generated memory reports first",
                    evidence=file_row,
                    blocking=False,
                    freshness_scope="external_active_vault",
                )
            )
    vault_date = date_prefix(vault.get("generated"))
    if vault_date and vault_date < DEFAULT_DATE:
        guards.append(
            guard(
                "obsidian_vault_freshness",
                "ADVISORY",
                f"external active-vault dashboard was generated on {vault_date}; generated memory reports are expected on or after {DEFAULT_DATE}",
                evidence=vault.get("generated"),
                blocking=False,
                freshness_scope="external_active_vault",
            )
        )

    active_overlap = [row for row in open_klbq if row.get("id") in ACTIVE_INTEGRATION_KLBQ]
    for row in active_overlap:
        guards.append(
            guard(
                "active_integration_boundary",
                "WARN",
                f"{row['id']} is open active-integration state; do not edit its producer/source-root integration in this branch",
                evidence={"id": row["id"], "next_action": row.get("next_action")},
                blocking=False,
                freshness_scope="coordination_boundary",
            )
        )
    if not guards:
        guards.append(guard("all_sources", "READY", "all required source guards passed", blocking=False))
    return guards


def retrieval_order(memory_root: Path, vault_root: Path, artifact_paths: dict[str, str]) -> list[dict[str, str]]:
    return [
        {
            "order": "1",
            "path": DEFAULT_MARKDOWN_OUT,
            "why": "This generated bootstrap query is the first low-context handoff surface.",
        },
        {
            "order": "2",
            "path": DEFAULT_JSON_OUT,
            "why": "Machine-readable version with stale-source guards and exact commands.",
        },
        {
            "order": "3",
            "path": str(memory_root / artifact_paths["known_limitations_harness_memory_status"]),
            "why": "Closed/open KLBQ states and exact verification commands.",
        },
        {
            "order": "4",
            "path": str(memory_root / artifact_paths["obsidian_memory_entrypoints"]),
            "why": "Current priority, branch/worktree handoff, and memory-root entrypoints.",
        },
        {
            "order": "5",
            "path": str(memory_root / artifact_paths["model_takeover_provider_handoff"]),
            "why": "Provider-specific bounded takeover packet if a model handoff needs more detail.",
        },
        {
            "order": "6",
            "path": str(vault_root / "INDEX_active.md"),
            "why": "Vault fallback only after generated packet/source reports are insufficient.",
        },
    ]


def build_packet(
    root: Path,
    *,
    memory_root: Path | None = None,
    vault_root: Path | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    root = root.resolve()
    memory_root = (memory_root or choose_memory_root(root, None)).resolve()
    artifacts, loaded, artifact_paths = artifact_inventory(memory_root)
    obsidian_report = loaded.get("obsidian_memory_entrypoints", {})
    vault_root = (vault_root or choose_vault_root(None, obsidian_report)).resolve()

    self_generated_outputs = {DEFAULT_JSON_OUT, DEFAULT_MARKDOWN_OUT}
    current_state = git_state(root, ignored_dirty_paths=self_generated_outputs)
    memory_state = git_state(
        memory_root,
        ignored_dirty_paths=self_generated_outputs if memory_root == root else (),
    )
    vault = vault_inventory(vault_root)
    klbq_status = loaded.get("known_limitations_harness_memory_status", {})
    readiness = loaded.get("model_takeover_readiness", {})
    scanner_active_claims = loaded.get("scanner_worker_active_claims", {})
    closed_klbq, open_klbq = extract_klbq_state(klbq_status)
    guards = build_guards(root, current_state, memory_root, memory_state, vault, artifacts, loaded, open_klbq)
    active_boundary_ids = sorted(
        str(row.get("id"))
        for row in open_klbq
        if row.get("id") in ACTIVE_INTEGRATION_KLBQ
    )
    handoff_contract = [
        "Do not infer closure from missing rows; use closed_klbq_states only when row-level evidence is present.",
        "Treat scanner, harness, and source-replay rows as operational status, not exploit or submission proof.",
    ]
    if active_boundary_ids:
        handoff_contract.insert(
            1,
            f"Do not edit {'/'.join(active_boundary_ids)} integration paths from this branch; they are active external integration state.",
        )

    return {
        "schema": SCHEMA,
        "date": DEFAULT_DATE,
        "generated_at": generated_at or utc_now(),
        "current_checkout": current_state,
        "memory_source": {
            **memory_state,
            "artifact_inventory": artifacts,
        },
        "obsidian_vault": vault,
        "current_priority": extract_priority(
            obsidian_report,
            klbq_status,
            readiness,
            memory_state,
            current_root=root,
            current_state=current_state,
            scanner_active_claims=scanner_active_claims,
            scanner_active_claims_path=artifact_paths["scanner_worker_active_claims"],
        ),
        "commit_mining_source_disposition": extract_commit_mining_source_disposition(klbq_status),
        "closed_klbq_states": closed_klbq,
        "open_klbq_blocks": open_klbq,
        "stale_source_guards": guards,
        "freshness_summary": guard_summary(guards),
        "exact_next_commands": exact_next_commands(
            root,
            memory_root,
            obsidian_report,
            open_klbq,
            obsidian_report_path=artifact_paths["obsidian_memory_entrypoints"],
            klbq_status_path=artifact_paths["known_limitations_harness_memory_status"],
        ),
        "retrieval_order": retrieval_order(memory_root, vault_root, artifact_paths),
        "expected_token_saving_mechanism": (
            "Load this packet first, follow retrieval_order only for missing detail, and open full docs/reports "
            "only when a stale_source_guard or task-specific source path requires it."
        ),
        "handoff_contract": handoff_contract,
    }


def render_markdown(packet: dict[str, Any]) -> str:
    current = packet["current_checkout"]
    memory = packet["memory_source"]
    priority = packet["current_priority"]
    freshness = packet.get("freshness_summary", {})
    blocking_guards = [row for row in packet["stale_source_guards"] if row.get("blocking")]
    nonblocking_guards = [
        row
        for row in packet["stale_source_guards"]
        if not row.get("blocking") and row.get("status") != "READY"
    ]
    lines = [
        "# Agent Bootstrap Query",
        "",
        f"- Schema: `{packet['schema']}`",
        f"- Current branch: `{current['branch']}`",
        f"- Current worktree: `{current['root']}`",
        f"- Memory source: `{memory['root']}` branch `{memory['branch']}`",
        f"- Token-saving mechanism: {packet['expected_token_saving_mechanism']}",
        f"- Operational freshness: `{freshness.get('operational_status', 'UNKNOWN')}`; blocking `{freshness.get('blocking_count', 0)}`; nonblocking `{freshness.get('nonblocking_count', 0)}`",
        "",
        "## Stale-Source Guards",
        "",
    ]
    if blocking_guards:
        lines.append("### Blocking")
        lines.append("")
        for row in blocking_guards:
            lines.append(f"- `{row['status']}` `{row['scope']}`: {row['message']}")
        lines.append("")
    else:
        lines.append("- No blocking stale-memory guards.")
        lines.append("")
    if nonblocking_guards:
        lines.append("### Nonblocking / Advisory")
        lines.append("")
    for row in nonblocking_guards:
        lines.append(f"- `{row['status']}` `{row['scope']}`: {row['message']}")
    lines.extend(["", "## Current Priority", ""])
    if priority.get("goal_status"):
        for item in priority["goal_status"]:
            lines.append(f"- {compact_text(item, 220)}")
    lines.append(f"- Terminal completion allowed: `{priority.get('terminal_completion_allowed')}`")
    if priority.get("priority_order"):
        lines.append("- Priority order: " + " > ".join(str(item) for item in priority["priority_order"]))
    policy = _dict_from(priority.get("execution_priority_policy"))
    if policy.get("agent_usage"):
        lines.append(f"- Agent usage: {compact_text(policy.get('agent_usage'), 260)}")
    if priority.get("top_ready_now"):
        lines.append("- Top ready now: " + ", ".join(f"`{item}`" for item in priority["top_ready_now"]))
    if priority.get("blocked_backlog"):
        lines.append("- Blocked backlog: " + ", ".join(f"`{item}`" for item in priority["blocked_backlog"]))
    for row in priority.get("actionable_open_rows", [])[:4]:
        lines.append(
            f"- `{row['id']}` next_action_status=`{row.get('next_action_status', '')}`; "
            f"actionable_now_commands `{row.get('actionable_now_command_count', 0)}`; "
            f"blocked_templates `{row.get('blocked_command_template_count', 0)}`"
        )
    for loop in priority.get("scheduled_loops", [])[:2]:
        if not isinstance(loop, dict):
            continue
        items = ", ".join(str(item) for item in loop.get("items", [])[:5])
        lanes = ", ".join(str(item) for item in loop.get("lanes", [])[:4])
        lines.append(f"- Scheduled loop {loop.get('loop_index')}: {items} ({lanes})")
    if priority.get("scanner_worker_slots"):
        lines.extend(["", "### Scanner Worker Slots", ""])
        selector = _dict_from(priority.get("scanner_worker_next_rows"))
        selection = _dict_from(selector.get("selection"))
        if selection:
            lines.append(
                f"- selector selected `{selection.get('selected_count', 0)}` after scanning "
                f"`{selection.get('candidate_rows_scanned', 0)}` rows; skipped `{selection.get('skipped_counts', {})}`"
            )
        for slot in priority.get("scanner_worker_slots", [])[:5]:
            if not isinstance(slot, dict):
                continue
            owned = ", ".join(str(item) for item in _list_from(slot.get("owned_paths"))[:3]) or "-"
            lines.append(
                f"- `{slot.get('slot_id', '')}` `{slot.get('row_id', '')}` "
                f"lane=`{slot.get('lane', '')}` coordination=`{slot.get('local_coordination_status', '')}` "
                f"model=`{slot.get('model_hint', '')}` owned={owned}"
            )
    active_claims = _dict_from(priority.get("active_scanner_claims"))
    if active_claims.get("present"):
        lines.extend(["", "### Active Scanner Claims", ""])
        lines.append(
            f"- claim map `{active_claims.get('source_path')}` active `{active_claims.get('active', 0)}`; "
            f"completed `{active_claims.get('completed', 0)}`"
        )
        for row in _list_from(active_claims.get("active_rows"))[:5]:
            if not isinstance(row, dict):
                continue
            lines.append(
                f"- `{row.get('row_id', '')}` agent=`{row.get('agent_id', '')}`"
            )
    if priority.get("skipped_scanner_worker_slots"):
        lines.extend(["", "### Skipped Scanner Worker Slots", ""])
        guidance = _dict_from(priority.get("scanner_coordination_guidance"))
        if guidance:
            lines.append(
                "- refresh scanner inventory before more detector assignments: `"
                + str(bool(guidance.get("refresh_inventory_before_more_detector_assignments"))).lower()
                + "`; do_not_redispatch="
                + str(guidance.get("do_not_redispatch_statuses", []))
            )
            if guidance.get("reason"):
                lines.append(f"- guidance: {guidance.get('reason')}")
        for slot in priority.get("skipped_scanner_worker_slots", [])[:5]:
            if not isinstance(slot, dict):
                continue
            evidence = (
                _list_from(slot.get("matching_dirty_paths"))
                + _list_from(slot.get("local_evidence_paths"))
                + _list_from(slot.get("committed_after_queue_paths"))
            )
            evidence_text = ", ".join(str(item) for item in evidence[:3]) or "-"
            lines.append(
                f"- `{slot.get('row_id', '')}` rank=`{slot.get('rank', '')}` "
                f"coordination=`{slot.get('local_coordination_status', '')}` evidence={evidence_text}"
            )

    commit_mining = _dict_from(packet.get("commit_mining_source_disposition"))
    lines.extend(["", "## Commit-Mining Source Disposition", ""])
    lines.append(f"- Status: `{commit_mining.get('status', 'unknown')}`")
    lines.append(f"- Queued actionable rows: `{commit_mining.get('queued_actionable_count', 0)}`")
    lines.append(f"- Completed next steps: `{commit_mining.get('completed_next_step_count', 0)}`")
    lines.append(f"- Source packets emitted: `{commit_mining.get('source_packets_emitted', 0)}`")
    for row in _list_from(commit_mining.get("top_dispositions"))[:4]:
        if not isinstance(row, dict):
            continue
        lines.append(
            f"- `{row.get('source_row_id', '')}` `{row.get('status', '')}` "
            f"{row.get('target', '')}: {row.get('next_action', '')}"
        )
    caveat = commit_mining.get("strict_caveat")
    if caveat:
        lines.append(f"- Caveat: {caveat}")

    lines.extend(["", "## Closed KLBQ States", ""])
    for row in packet["closed_klbq_states"][:8]:
        lines.append(f"- `{row['id']}` `{row['current_status']}`: {row['next_action']}")
        if row.get("next_action_status"):
            lines.append(f"  - Next-action status: `{row['next_action_status']}`")
        if row.get("actionable_now_commands"):
            lines.append(f"  - Actionable now: `{row['actionable_now_commands'][0]}`")
        if row.get("verification_commands"):
            lines.append(f"  - Verify: `{row['verification_commands'][0]}`")
    if not packet["closed_klbq_states"]:
        lines.append("- None found in the selected memory source.")

    lines.extend(["", "## Open / Guarded KLBQ Rows", ""])
    for row in packet["open_klbq_blocks"][:8]:
        marker = " active integration boundary" if row["id"] in ACTIVE_INTEGRATION_KLBQ else ""
        lines.append(f"- `{row['id']}`{marker} `{row['current_status']}`: {row['next_action']}")
        if row.get("next_action_status"):
            lines.append(f"  - Next-action status: `{row['next_action_status']}`")
        if row.get("actionable_now_commands"):
            lines.append(f"  - Actionable now: `{row['actionable_now_commands'][0]}`")
        if row.get("blocked_command_templates"):
            lines.append(f"  - Blocked template: `{row['blocked_command_templates'][0]['command']}`")
        if row.get("blockers"):
            lines.append(f"  - Blocker: {row['blockers'][0]}")
    if not packet["open_klbq_blocks"]:
        lines.append("- None found in the selected memory source.")

    lines.extend(["", "## Exact Next Commands", ""])
    for row in packet["exact_next_commands"]:
        lines.append(f"- `{row['command']}`")
        lines.append(f"  - {row['reason']}")

    lines.extend(["", "## Retrieval Order", ""])
    for row in packet["retrieval_order"]:
        lines.append(f"{row['order']}. `{row['path']}` - {row['why']}")

    lines.extend(["", "## Contract", ""])
    for item in packet["handoff_contract"]:
        lines.append(f"- {item}")
    return "\n".join(lines).rstrip() + "\n"


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="active checkout root")
    parser.add_argument("--memory-root", help="existing generated-memory root to read")
    parser.add_argument("--vault-root", help="Obsidian vault root to inspect")
    parser.add_argument("--json-out", default=DEFAULT_JSON_OUT)
    parser.add_argument("--markdown-out", default=DEFAULT_MARKDOWN_OUT)
    parser.add_argument("--print-json", action="store_true")
    parser.add_argument("--print-markdown", action="store_true")
    parser.add_argument("--fail-on-stale", action="store_true", help="return 2 when any blocking stale-memory guard is present")
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    root = Path(args.root).expanduser().resolve()
    memory_root = choose_memory_root(root, args.memory_root)
    artifact_paths = _resolve_memory_artifact_paths(memory_root)
    obsidian_payload, _ = read_json(memory_root / artifact_paths["obsidian_memory_entrypoints"])
    vault_root = Path(args.vault_root).expanduser().resolve() if args.vault_root else choose_vault_root(None, obsidian_payload)
    packet = build_packet(root, memory_root=memory_root, vault_root=vault_root)
    markdown = render_markdown(packet)
    if args.print_json:
        print(json.dumps(packet, indent=2, sort_keys=True))
    elif args.print_markdown:
        print(markdown, end="")
    else:
        json_out = root / args.json_out
        md_out = root / args.markdown_out
        write_json(json_out, packet)
        write_text(md_out, markdown)
        print(f"memory-retrieval-bootstrap: wrote {json_out.relative_to(root)} and {md_out.relative_to(root)}")
    if args.fail_on_stale and any(row.get("blocking", row["status"] == "BLOCKED") for row in packet["stale_source_guards"]):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
