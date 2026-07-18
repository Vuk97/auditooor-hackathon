#!/usr/bin/env python3
"""task-finalization-ledger.py — durable closure rows for bounded dispatches.

MCL-3 turns an agent slot's terminal state into memory:

  - append one machine row to reports/task_finalization.jsonl
  - write one vault note under obsidian-vault/tasks/finalized/<task_id>.md
  - mirror the closure row to obsidian-vault/gap-analysis/_completed.jsonl

The tool is deliberately strict. A finalization row that cannot prove its
terminal artifact, verification result, changed files, and memory impact should
fail validation instead of silently teaching the loop bad state.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, NamedTuple


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VAULT = REPO_ROOT / "obsidian-vault"
DEFAULT_LEDGER = REPO_ROOT / "reports" / "task_finalization.jsonl"
DEFAULT_COMPLETED_LOG = DEFAULT_VAULT / "gap-analysis" / "_completed.jsonl"
DEFAULT_NOTES_DIR = DEFAULT_VAULT / "tasks" / "finalized"
SCHEMA = "auditooor.task_finalization.v1"
PR_RANGE_STATUS_SCHEMA = "auditooor.task_finalization_pr_range_status.v1"
PR_RANGE_BACKFILL_SCHEMA = "auditooor.task_finalization_pr_range_backfill.v1"
ENFORCE_ACTIVE_MANIFEST_SCHEMA = "auditooor.task_finalization_enforce_active_manifest.v1"
REQUIRED_ROW_FIELDS = (
    "schema",
    "task_id",
    "gap_id",
    "slot_id",
    "status",
    "finalization_row_kind",
    "owner",
    "dispatch_source",
    "source_manifest",
    "terminal_artifact",
    "changed_files",
    "verification",
    "open_followups",
    "docs_updated",
    "readme_updated",
    "frontdoor_updated",
    "outcome_or_calibration_updated",
    "memory_updates",
    "blocked_by",
    "closed_at",
)

GAP_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
KNOWLEDGE_GAP_REF_RE = re.compile(r"^KG-[0-9]{8}-[0-9]{3}$")
SLOT_ID_RE = re.compile(r"^slot-[1-5]$")
TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,96}$")
STATUS_VALUES = {"landed", "blocked", "failed", "deferred", "false_positive"}
FINALIZATION_KINDS = {"merged_pr", "killed_candidate", "failed_gate", "operator_deferred"}
GAP_RETIRING_STATUSES = {"landed", "false_positive"}
ALLOWED_KINDS_BY_STATUS = {
    "landed": {"merged_pr"},
    "blocked": {"operator_deferred", "failed_gate"},
    "failed": {"failed_gate"},
    "deferred": {"operator_deferred"},
    "false_positive": {"killed_candidate"},
}
COMMIT_ARTIFACT_RE = re.compile(r"^commit:([0-9a-fA-F]{7,40})(?::.*)?$")
GITHUB_ARTIFACT_RE = re.compile(
    r"^https://github\.com/Vuk97/auditooor/(?:pull/[1-9][0-9]*|commit/[0-9a-fA-F]{7,40})/?$")
PR_PULL_ARTIFACT_RE = re.compile(r"^https://github\.com/Vuk97/auditooor/pull/([1-9][0-9]*)/?$")
PR_COMMIT_ARTIFACT_RE = re.compile(r"^https://github\.com/Vuk97/auditooor/commit/([0-9a-fA-F]{7,40})/?$")
PR_MERGE_RE = re.compile(r"^Merge pull request #([1-9][0-9]*) from ([^/]+)/(.+)$")
PR_TASK_RE = re.compile(r"(?:^|[^A-Za-z0-9])pr([1-9][0-9]*)(?:$|[^A-Za-z0-9])", re.IGNORECASE)


class PrMerge(NamedTuple):
    pr_number: int
    merge_commit: str
    merged_at: str
    source_owner: str
    source_branch: str
    subject: str
    changed_files: tuple[str, ...]


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip("-._")
    return (slug or "task").lower()[:96]


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read JSON row: {path}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"finalization row must be a JSON object: {path}")
    return value


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSONL row") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_no}: row must be an object")
            rows.append(row)
    return rows


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")


def rel_display(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return str(path)


def list_from_value(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def clean_string_list(value: Any) -> list[str]:
    out: list[str] = []
    for item in list_from_value(value):
        text = str(item).strip()
        if text and text not in out:
            out.append(text)
    return out


def clean_knowledge_gap_refs(value: Any) -> list[str]:
    refs: list[str] = []
    for item in list_from_value(value):
        text = str(item).strip()
        if KNOWLEDGE_GAP_REF_RE.match(text) and text not in refs:
            refs.append(text)
    return refs


def commit_exists(sha: str) -> bool:
    res = subprocess.run(
        ["git", "cat-file", "-e", f"{sha}^{{commit}}"],
        cwd=REPO_ROOT, capture_output=True, text=True)
    return res.returncode == 0


def resolve_commit(commit: str) -> str:
    res = subprocess.run(
        ["git", "rev-parse", "--verify", f"{commit}^{{commit}}"],
        cwd=REPO_ROOT, capture_output=True, text=True)
    if res.returncode != 0:
        raise ValueError(res.stderr.strip() or f"cannot resolve commit {commit}")
    return res.stdout.strip()


def normalize_verification(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"commands": [], "passed": False}
    commands = []
    for item in list_from_value(value.get("commands")):
        if isinstance(item, dict):
            command = str(item.get("command") or "").strip()
            exit_code = item.get("exit_code")
            if command:
                commands.append({"command": command, "exit_code": exit_code})
        else:
            command = str(item).strip()
            if command:
                commands.append({"command": command, "exit_code": None})
    return {"commands": commands, "passed": value.get("passed") is True}


def normalize_row(row: dict[str, Any]) -> dict[str, Any]:
    gap_id = str(row.get("gap_id") or "").strip()
    slot_id = str(row.get("slot_id") or "").strip()
    status = str(row.get("status") or "").strip()
    task_id = str(row.get("task_id") or "").strip()
    if not task_id:
        task_id = slugify("-".join(part for part in (gap_id, slot_id, status) if part))
    normalized = {
        "schema": row.get("schema") or SCHEMA,
        "task_id": task_id,
        "gap_id": gap_id,
        "slot_id": slot_id,
        "status": status,
        "finalization_row_kind": str(row.get("finalization_row_kind") or "").strip(),
        "owner": str(row.get("owner") or "").strip(),
        "dispatch_source": str(row.get("dispatch_source") or "").strip(),
        "source_manifest": str(row.get("source_manifest") or "").strip(),
        "terminal_artifact": str(row.get("terminal_artifact") or "").strip(),
        "changed_files": clean_string_list(row.get("changed_files")),
        "verification": normalize_verification(row.get("verification")),
        "knowledge_gap_refs": clean_knowledge_gap_refs(row.get("knowledge_gap_refs")),
        "open_followups": clean_string_list(row.get("open_followups")),
        "docs_updated": row.get("docs_updated") is True,
        "readme_updated": row.get("readme_updated") is True,
        "frontdoor_updated": row.get("frontdoor_updated") is True,
        "outcome_or_calibration_updated": row.get("outcome_or_calibration_updated") is True,
        "memory_updates": clean_string_list(row.get("memory_updates")),
        "blocked_by": row.get("blocked_by") if row.get("blocked_by") is not None else None,
        "closed_at": str(row.get("closed_at") or utc_now()).strip(),
    }
    return normalized


def raw_row_errors(row: dict[str, Any]) -> list[str]:
    errors = [f"{key} is required" for key in REQUIRED_ROW_FIELDS if key not in row]
    if "knowledge_gap_refs" in row:
        refs = row["knowledge_gap_refs"]
        if not isinstance(refs, list) or any(
                not isinstance(item, str) or KNOWLEDGE_GAP_REF_RE.match(item) is None for item in refs):
            errors.append("knowledge_gap_refs must be a list of KG-YYYYMMDD-NNN ids")
    return errors


def artifact_proved(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip()
    if not text:
        return False
    if any(ord(ch) < 32 for ch in text) or "`" in text:
        return False
    if text.startswith("<") or text.endswith(">"):
        return False
    if " or " in text.lower() or "-or-" in text.lower():
        return False
    if text.startswith("commit:"):
        match = COMMIT_ARTIFACT_RE.match(text)
        return bool(match and commit_exists(match.group(1)))
    if text.startswith("https://github.com/Vuk97/auditooor/"):
        return bool(GITHUB_ARTIFACT_RE.match(text))
    if "://" in text or text.startswith("external:"):
        return False
    if text.startswith("/") or text.startswith("~"):
        return False
    parts = tuple(part for part in Path(text).parts if part and part != ".")
    if not parts or any(part == ".." or part.startswith(".") for part in parts):
        return False
    forbidden = {"_privacy_quarantine", "_archive", ".archive", ".privacy", ".git"}
    if any(part in forbidden for part in parts):
        return False
    rel = "/".join(parts)
    safe_prefixes = (
        "reports/",
        "docs/",
        "obsidian-vault/tasks/finalized/",
        "obsidian-vault/gap-analysis/",
        "obsidian-vault/dispatch/",
    )
    if not any(rel.startswith(prefix) for prefix in safe_prefixes):
        return False
    artifact_path = (REPO_ROOT / rel).resolve()
    try:
        artifact_path.relative_to(REPO_ROOT)
    except ValueError:
        return False
    return artifact_path.is_file()


def validate_row(row: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if row.get("schema") != SCHEMA:
        errors.append(f"schema must be {SCHEMA}")
    if not isinstance(row.get("task_id"), str) or TASK_ID_RE.match(row["task_id"]) is None:
        errors.append("task_id is required and must be slug-safe")
    if not isinstance(row.get("gap_id"), str) or GAP_ID_RE.match(row["gap_id"]) is None:
        errors.append("gap_id is required and must be slug-safe")
    if not isinstance(row.get("slot_id"), str) or SLOT_ID_RE.match(row["slot_id"]) is None:
        errors.append("slot_id must be slot-1..slot-5")
    if row.get("status") not in STATUS_VALUES:
        errors.append(f"status must be one of {sorted(STATUS_VALUES)}")
    if row.get("finalization_row_kind") not in FINALIZATION_KINDS:
        errors.append(f"finalization_row_kind must be one of {sorted(FINALIZATION_KINDS)}")
    elif row.get("status") in ALLOWED_KINDS_BY_STATUS:
        allowed_kinds = ALLOWED_KINDS_BY_STATUS[row["status"]]
        if row["finalization_row_kind"] not in allowed_kinds:
            errors.append(
                f"finalization_row_kind for status={row['status']} must be one of {sorted(allowed_kinds)}")
    if not row.get("owner"):
        errors.append("owner is required")
    if not row.get("dispatch_source") and not row.get("source_manifest"):
        errors.append("dispatch_source or source_manifest is required")
    if not artifact_proved(row.get("terminal_artifact")):
        errors.append("terminal_artifact must be non-placeholder proof")
    changed_files = row.get("changed_files")
    if not isinstance(changed_files, list) or any(not isinstance(item, str) or not item for item in changed_files):
        errors.append("changed_files must be a list of non-empty strings")
    if row.get("status") == "landed" and not changed_files:
        errors.append("landed rows require at least one changed file")
    verification = row.get("verification")
    verification_exit_codes: list[int] = []
    if not isinstance(verification, dict):
        errors.append("verification must be an object")
    else:
        commands = verification.get("commands")
        if not isinstance(commands, list) or not commands:
            errors.append("verification.commands must contain at least one command")
        else:
            for index, command_row in enumerate(commands):
                if not isinstance(command_row, dict) or not command_row.get("command"):
                    errors.append(f"verification.commands[{index}] must include command")
                elif not isinstance(command_row.get("exit_code"), int):
                    errors.append(f"verification.commands[{index}].exit_code must be an integer")
                else:
                    verification_exit_codes.append(command_row["exit_code"])
        if not isinstance(verification.get("passed"), bool):
            errors.append("verification.passed must be boolean")
        if verification.get("passed") is True and any(code != 0 for code in verification_exit_codes):
            errors.append("verification.passed=true requires all command exit codes to be 0")
        if row.get("status") == "landed" and verification.get("passed") is not True:
            errors.append("landed rows require verification.passed=true")
    for key in (
        "knowledge_gap_refs",
        "open_followups",
        "memory_updates",
    ):
        if not isinstance(row.get(key), list) or any(not isinstance(item, str) for item in row[key]):
            errors.append(f"{key} must be a list of strings")
    if any(KNOWLEDGE_GAP_REF_RE.match(item) is None for item in row.get("knowledge_gap_refs", [])):
        errors.append("knowledge_gap_refs must use KG-YYYYMMDD-NNN ids")
    for key in ("docs_updated", "readme_updated", "frontdoor_updated", "outcome_or_calibration_updated"):
        if not isinstance(row.get(key), bool):
            errors.append(f"{key} must be boolean")
    if row.get("status") in {"blocked", "deferred"} and not row.get("blocked_by") and not row.get("open_followups"):
        errors.append("blocked/deferred rows require blocked_by or open_followups")
    try:
        parse_closed_at(row.get("closed_at"))
    except ValueError:
        errors.append("closed_at must be ISO-8601 with explicit timezone")
    return errors


def completed_log_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "auditooor.gap_completion.v1",
        "gap_id": row["gap_id"],
        "slot_id": row["slot_id"],
        "status": row["status"],
        "finalization_row_kind": row["finalization_row_kind"],
        "owner": row["owner"],
        "terminal_artifact": row["terminal_artifact"],
        "closed_at": row["closed_at"],
        "verification": row["verification"],
        "knowledge_gap_refs": row.get("knowledge_gap_refs", []),
        "memory_updates": row["memory_updates"],
        "blocked_by": row.get("blocked_by"),
        "task_id": row["task_id"],
    }


def note_text(row: dict[str, Any]) -> str:
    lines = [
        "---",
        'category: "task-finalization"',
        f'task_id: "{row["task_id"]}"',
        f'gap_id: "{row["gap_id"]}"',
        f'slot_id: "{row["slot_id"]}"',
        f'status: "{row["status"]}"',
        f'closed_at: "{row["closed_at"]}"',
        f'schema: "{SCHEMA}"',
        "tags:",
        "  - memory/task-finalization",
        "---",
        "",
        f"# Finalized Task — {row['task_id']}",
        "",
        "## Summary",
        "",
        f"- Gap ID: `{row['gap_id']}`",
        f"- Slot ID: `{row['slot_id']}`",
        f"- Status: `{row['status']}`",
        f"- Owner: `{row['owner']}`",
        f"- Dispatch source: `{row['dispatch_source'] or row['source_manifest']}`",
        f"- Terminal artifact: `{row['terminal_artifact']}`",
        f"- Finalization kind: `{row['finalization_row_kind']}`",
        f"- Knowledge gap refs: `{', '.join(row.get('knowledge_gap_refs') or []) or 'none'}`",
        "",
        "## Changed Files",
        "",
    ]
    lines.extend(f"- `{path}`" for path in row["changed_files"]) if row["changed_files"] else lines.append("- _(none)_")
    lines.extend(["", "## Verification", ""])
    lines.append(f"- Passed: `{str(row['verification']['passed']).lower()}`")
    for command in row["verification"]["commands"]:
        lines.append(f"- `{command['command']}` → `{command['exit_code']}`")
    lines.extend(["", "## Followups", ""])
    lines.extend(f"- {item}" for item in row["open_followups"]) if row["open_followups"] else lines.append("- _(none)_")
    lines.extend(["", "## Memory Updates", ""])
    lines.extend(f"- `{item}`" for item in row["memory_updates"]) if row["memory_updates"] else lines.append("- _(none)_")
    lines.extend([
        "",
        "## Surface Updates",
        "",
        f"- Docs updated: `{str(row['docs_updated']).lower()}`",
        f"- README/front door updated: `{str(row['readme_updated'] or row['frontdoor_updated']).lower()}`",
        f"- Outcome/calibration memory updated: `{str(row['outcome_or_calibration_updated']).lower()}`",
    ])
    if row.get("blocked_by"):
        lines.extend(["", "## Blocked By", "", str(row["blocked_by"])])
    lines.append("")
    return "\n".join(lines)


def write_note(row: dict[str, Any], notes_dir: Path) -> Path:
    notes_dir.mkdir(parents=True, exist_ok=True)
    path = notes_dir / f"{row['task_id']}.md"
    path.write_text(note_text(row), encoding="utf-8")
    return path


def completed_log_has_task(completed_log: Path, task_id: str) -> bool:
    return any(str(row.get("task_id") or "") == task_id for row in read_jsonl(completed_log))


def repair_finalization_sidecars(row: dict[str, Any], ledger: Path, completed_log: Path, notes_dir: Path,
                                 dry_run: bool = False) -> dict[str, Any]:
    note_path = notes_dir / f"{row['task_id']}.md"
    completed_missing = not completed_log_has_task(completed_log, row["task_id"])
    note_missing = not note_path.is_file()
    if not dry_run:
        if completed_missing:
            append_jsonl(completed_log, completed_log_row(row))
        if note_missing:
            note_path = write_note(row, notes_dir)
    return {
        "row": row,
        "ledger": rel_display(ledger),
        "completed_log": rel_display(completed_log),
        "note_path": rel_display(note_path),
        "dry_run": dry_run,
        "ledger_reused": True,
        "sidecars_repaired": completed_missing or note_missing,
    }


def append_row(row: dict[str, Any], ledger: Path, completed_log: Path, notes_dir: Path,
               dry_run: bool = False) -> dict[str, Any]:
    raw_errors = raw_row_errors(row)
    if raw_errors:
        raise ValueError("; ".join(raw_errors))
    normalized = normalize_row(row)
    errors = validate_row(normalized)
    if errors:
        raise ValueError("; ".join(errors))
    for existing in read_jsonl(ledger):
        existing_row = normalize_row(existing)
        existing_errors = raw_row_errors(existing) + validate_row(existing_row)
        if existing_row["task_id"] == normalized["task_id"]:
            if not existing_errors and existing_row == normalized:
                return repair_finalization_sidecars(normalized, ledger, completed_log, notes_dir, dry_run=dry_run)
            raise ValueError(f"task_id already finalized: {normalized['task_id']}")
        if (
                existing_row["status"] in GAP_RETIRING_STATUSES
                and (existing_row["gap_id"], existing_row["slot_id"]) == (
                    normalized["gap_id"], normalized["slot_id"])):
            raise ValueError(
                f"gap/slot already retired: {normalized['gap_id']} {normalized['slot_id']}")
    note_path = notes_dir / f"{normalized['task_id']}.md"
    if not dry_run:
        append_jsonl(ledger, normalized)
        append_jsonl(completed_log, completed_log_row(normalized))
        note_path = write_note(normalized, notes_dir)
    return {
        "row": normalized,
        "ledger": rel_display(ledger),
        "completed_log": rel_display(completed_log),
        "note_path": rel_display(note_path),
        "dry_run": dry_run,
        "ledger_reused": False,
        "sidecars_repaired": False,
    }


def validate_ledger(path: Path) -> list[str]:
    if not path.is_file():
        return [f"{path}: ledger missing"]
    errors: list[str] = []
    retired: set[tuple[str, str]] = set()
    seen_task_ids: set[str] = set()
    for index, raw in enumerate(read_jsonl(path), start=1):
        row = normalize_row(raw)
        row_errors = raw_row_errors(raw) + validate_row(row)
        for error in row_errors:
            errors.append(f"{path}:{index}: {error}")
        task_id = row.get("task_id")
        if isinstance(task_id, str) and task_id:
            if task_id in seen_task_ids:
                errors.append(f"{path}:{index}: duplicate task_id {task_id}")
            seen_task_ids.add(task_id)
        key = (row["gap_id"], row["slot_id"])
        if key in retired:
            errors.append(f"{path}:{index}: finalization row after retired gap/slot {key}")
        if row["status"] in GAP_RETIRING_STATUSES:
            retired.add(key)
    return errors


def summary_counts(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = row.get(key)
        label = str(value).strip() if value is not None else ""
        label = label or "unknown"
        counts[label] = counts.get(label, 0) + 1
    return dict(sorted(counts.items()))


def parse_closed_at(value: Any) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("closed_at must include timezone")
    return parsed.astimezone(dt.timezone.utc)


def closed_at_sort_key(row: dict[str, Any]) -> dt.datetime:
    return parse_closed_at(row.get("closed_at"))


def summarize_ledger(path: Path) -> dict[str, Any]:
    ledger_exists = path.is_file()
    raw_rows = read_jsonl(path)
    valid_rows: list[dict[str, Any]] = []
    invalid: list[dict[str, Any]] = []
    retired_gap_slots: set[tuple[str, str]] = set()
    seen_task_ids: set[str] = set()
    duplicate_gap_slots: list[dict[str, str]] = []
    duplicate_task_ids: list[str] = []
    for index, raw in enumerate(raw_rows, start=1):
        row = normalize_row(raw)
        errors = raw_row_errors(raw) + validate_row(row)
        task_id = row.get("task_id")
        if isinstance(task_id, str) and task_id:
            if task_id in seen_task_ids:
                errors.append(f"duplicate task_id {task_id}")
                duplicate_task_ids.append(task_id)
            seen_task_ids.add(task_id)
        key = (row["gap_id"], row["slot_id"])
        if key in retired_gap_slots:
            errors.append(f"finalization row after retired gap/slot {key}")
            duplicate_gap_slots.append({"gap_id": row["gap_id"], "slot_id": row["slot_id"]})
        if row["status"] in GAP_RETIRING_STATUSES:
            retired_gap_slots.add(key)
        if errors:
            invalid.append({"line": index, "task_id": row.get("task_id"), "errors": errors})
        else:
            valid_rows.append(row)
    latest = None
    if valid_rows:
        latest = max(valid_rows, key=closed_at_sort_key)
    open_followup_rows = [row for row in valid_rows if row.get("open_followups")]
    return {
        "schema": "auditooor.task_finalization_summary.v1",
        "ledger": rel_display(path),
        "ledger_exists": ledger_exists,
        "generated_at": utc_now(),
        "readiness": "missing" if not ledger_exists else ("ready" if not invalid else "invalid"),
        "total_rows": len(raw_rows),
        "valid_rows": len(valid_rows),
        "invalid_rows": len(invalid),
        "closed_gap_slot_count": len({(row["gap_id"], row["slot_id"]) for row in valid_rows}),
        "status_counts": summary_counts(valid_rows, "status"),
        "finalization_row_kind_counts": summary_counts(valid_rows, "finalization_row_kind"),
        "owner_counts": summary_counts(valid_rows, "owner"),
        "docs_updated_rows": sum(1 for row in valid_rows if row.get("docs_updated")),
        "frontdoor_updated_rows": sum(
            1 for row in valid_rows if row.get("readme_updated") or row.get("frontdoor_updated")),
        "outcome_or_calibration_updated_rows": sum(
            1 for row in valid_rows if row.get("outcome_or_calibration_updated")),
        "open_followup_row_count": len(open_followup_rows),
        "open_followup_count": sum(len(row.get("open_followups") or []) for row in valid_rows),
        "knowledge_gap_ref_count": sum(len(row.get("knowledge_gap_refs") or []) for row in valid_rows),
        "memory_update_count": sum(len(row.get("memory_updates") or []) for row in valid_rows),
        "changed_file_count": len({path for row in valid_rows for path in row.get("changed_files", [])}),
        "duplicate_gap_slot_count": len(duplicate_gap_slots),
        "duplicate_gap_slots": duplicate_gap_slots[:20],
        "duplicate_task_id_count": len(duplicate_task_ids),
        "duplicate_task_ids": duplicate_task_ids[:20],
        "latest": {
            "task_id": latest.get("task_id"),
            "gap_id": latest.get("gap_id"),
            "slot_id": latest.get("slot_id"),
            "status": latest.get("status"),
            "closed_at": latest.get("closed_at"),
            "terminal_artifact": latest.get("terminal_artifact"),
            "knowledge_gap_refs": latest.get("knowledge_gap_refs", []),
        } if latest else None,
        "validation_errors": invalid[:20],
    }


def recent_rows(path: Path, limit: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in read_jsonl(path):
        row = normalize_row(raw)
        if raw_row_errors(raw) or validate_row(row):
            continue
        rows.append({
            "task_id": row["task_id"],
            "gap_id": row["gap_id"],
            "slot_id": row["slot_id"],
            "status": row["status"],
            "finalization_row_kind": row["finalization_row_kind"],
            "owner": row["owner"],
            "closed_at": row["closed_at"],
            "terminal_artifact": row["terminal_artifact"],
            "knowledge_gap_refs": row.get("knowledge_gap_refs", []),
            "open_followups": row["open_followups"],
            "blocked_by": row["blocked_by"],
        })
    rows.sort(key=closed_at_sort_key, reverse=True)
    return rows[:limit]


def build_report(path: Path, limit: int = 10) -> dict[str, Any]:
    summary = summarize_ledger(path)
    return {
        "schema": "auditooor.task_finalization_report.v1",
        "ledger": summary["ledger"],
        "generated_at": summary["generated_at"],
        "summary": {
            "readiness": summary["readiness"],
            "ledger_exists": summary["ledger_exists"],
            "total_rows": summary["total_rows"],
            "valid_rows": summary["valid_rows"],
            "invalid_row_count": summary["invalid_rows"],
            "closed_gap_slot_count": summary["closed_gap_slot_count"],
            "by_status": summary["status_counts"],
            "by_kind": summary["finalization_row_kind_counts"],
            "latest_closed_at": summary["latest"]["closed_at"] if summary["latest"] else None,
            "duplicate_gap_slot_count": summary["duplicate_gap_slot_count"],
            "duplicate_task_id_count": summary["duplicate_task_id_count"],
            "open_followup_count": summary["open_followup_count"],
            "open_followup_row_count": summary["open_followup_row_count"],
            "knowledge_gap_ref_count": summary["knowledge_gap_ref_count"],
            "memory_update_count": summary["memory_update_count"],
            "docs_updated_rows": summary["docs_updated_rows"],
            "frontdoor_updated_rows": summary["frontdoor_updated_rows"],
            "outcome_or_calibration_updated_rows": summary["outcome_or_calibration_updated_rows"],
        },
        "rows_recent": recent_rows(path, max(0, limit)),
        "latest": summary["latest"],
        "validation_errors": summary["validation_errors"],
    }


def render_summary(summary: dict[str, Any]) -> str:
    lines = [
        "# Task Finalization Summary",
        "",
        f"- Ledger: `{summary['ledger']}`",
        f"- Readiness: `{summary['readiness']}`",
        f"- Rows: `{summary['valid_rows']}` valid / `{summary['invalid_rows']}` invalid / `{summary['total_rows']}` total",
        f"- Closed gap/slot pairs: `{summary['closed_gap_slot_count']}`",
        f"- Open followups: `{summary['open_followup_count']}` across `{summary['open_followup_row_count']}` row(s)",
        f"- Knowledge gap refs recorded: `{summary['knowledge_gap_ref_count']}`",
        f"- Memory updates recorded: `{summary['memory_update_count']}`",
        "",
        "## Status Counts",
        "",
    ]
    status_counts = summary.get("status_counts") or {}
    if status_counts:
        lines.extend(f"- `{status}`: {count}" for status, count in status_counts.items())
    else:
        lines.append("- _(none)_")
    lines.extend(["", "## Finalization Kinds", ""])
    kind_counts = summary.get("finalization_row_kind_counts") or {}
    if kind_counts:
        lines.extend(f"- `{kind}`: {count}" for kind, count in kind_counts.items())
    else:
        lines.append("- _(none)_")
    latest = summary.get("latest")
    lines.extend(["", "## Latest", ""])
    if latest:
        lines.extend([
            f"- Task: `{latest['task_id']}`",
            f"- Gap/slot: `{latest['gap_id']}` / `{latest['slot_id']}`",
            f"- Status: `{latest['status']}`",
            f"- Closed at: `{latest['closed_at']}`",
            f"- Terminal artifact: `{latest['terminal_artifact']}`",
            f"- Knowledge gap refs: `{', '.join(latest.get('knowledge_gap_refs') or []) or 'none'}`",
        ])
    else:
        lines.append("- _(none)_")
    if summary.get("validation_errors"):
        lines.extend(["", "## Validation Errors", ""])
        for item in summary["validation_errors"]:
            lines.append(f"- line {item['line']} `{item.get('task_id')}`: {'; '.join(item['errors'])}")
    lines.append("")
    return "\n".join(lines)


def render_report(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Task Finalization Report",
        "",
        f"- Ledger: `{report['ledger']}`",
        f"- Readiness: `{summary['readiness']}`",
        f"- Ledger exists: `{str(summary['ledger_exists']).lower()}`",
        f"- Rows: `{summary['valid_rows']}` valid / `{summary['invalid_row_count']}` invalid / `{summary['total_rows']}` total",
        f"- Closed gap/slot pairs: `{summary['closed_gap_slot_count']}`",
        f"- Latest closed at: `{summary['latest_closed_at'] or 'none'}`",
        f"- Open followups: `{summary['open_followup_count']}` across `{summary['open_followup_row_count']}` row(s)",
        f"- Knowledge gap refs recorded: `{summary['knowledge_gap_ref_count']}`",
        "",
        "## Status Counts",
        "",
    ]
    if summary["by_status"]:
        lines.extend(f"- `{status}`: {count}" for status, count in summary["by_status"].items())
    else:
        lines.append("- _(none)_")
    lines.extend(["", "## Finalization Kinds", ""])
    if summary["by_kind"]:
        lines.extend(f"- `{kind}`: {count}" for kind, count in summary["by_kind"].items())
    else:
        lines.append("- _(none)_")
    lines.extend(["", "## Recent Rows", ""])
    if report["rows_recent"]:
        lines.append("| Task | Gap | Slot | Status | Kind | Owner | Closed |")
        lines.append("|---|---|---|---|---|---|---|")
        for row in report["rows_recent"]:
            lines.append(
                f"| `{row['task_id']}` | `{row['gap_id']}` | `{row['slot_id']}` | "
                f"`{row['status']}` | `{row['finalization_row_kind']}` | "
                f"`{row['owner']}` | `{row['closed_at']}` |")
    else:
        lines.append("_No recent rows._")
    if report.get("validation_errors"):
        lines.extend(["", "## Validation Errors", ""])
        for item in report["validation_errors"]:
            lines.append(f"- line {item['line']} `{item.get('task_id')}`: {'; '.join(item['errors'])}")
    lines.append("")
    return "\n".join(lines)


def ledger_index(path: Path) -> set[tuple[str, str, str, str]]:
    by_artifact: set[tuple[str, str, str, str]] = set()
    retired: set[tuple[str, str]] = set()
    seen_task_ids: set[str] = set()
    for row in read_jsonl(path):
        normalized = normalize_row(row)
        task_id = normalized.get("task_id")
        key = (normalized["gap_id"], normalized["slot_id"])
        ledger_level_errors = []
        if isinstance(task_id, str) and task_id:
            if task_id in seen_task_ids:
                ledger_level_errors.append(f"duplicate task_id {task_id}")
            seen_task_ids.add(task_id)
        if key in retired:
            ledger_level_errors.append(f"finalization row after retired gap/slot {key}")
        if normalized["status"] in GAP_RETIRING_STATUSES:
            retired.add(key)
        if raw_row_errors(row) or validate_row(normalized) or ledger_level_errors:
            continue
        gap_id = normalized.get("gap_id")
        slot_id = normalized.get("slot_id")
        status = normalized.get("status")
        artifact = str(normalized.get("terminal_artifact") or "").strip()
        if isinstance(gap_id, str) and isinstance(slot_id, str) and isinstance(status, str) and artifact:
            by_artifact.add((gap_id, slot_id, status, artifact))
    return by_artifact


def manifest_completion_gaps(manifest: Path, ledger: Path) -> list[dict[str, Any]]:
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read dispatch manifest: {manifest}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"dispatch manifest is not a JSON object: {manifest}")
    closed_by_artifact = ledger_index(ledger)
    gaps: list[dict[str, Any]] = []
    rows = list(payload.get("slots") or [])
    rows.extend(payload.get("in_flight_slots") or [])
    for row in rows:
        if not isinstance(row, dict):
            continue
        status = row.get("status")
        gap_id = row.get("gap_id")
        slot_id = row.get("slot_id")
        if status in STATUS_VALUES and isinstance(gap_id, str) and isinstance(slot_id, str):
            artifact = str(row.get("terminal_artifact") or "").strip()
            artifact_proof = artifact_proved(artifact)
            covered = artifact_proof and (gap_id, slot_id, status, artifact) in closed_by_artifact
            if not covered:
                gaps.append({
                    "gap_id": gap_id,
                    "slot_id": slot_id,
                    "status": status,
                    "completion_gap": True,
                    "terminal_artifact": row.get("terminal_artifact"),
                    "proof_gap_reason": (
                        "manifest_terminal_artifact_unproved"
                        if not artifact_proof else
                        "canonical_finalization_missing"
                    ),
                })
    return gaps


def enforce_active_manifest(
    workspace: Path,
    *,
    manifest: Path | None = None,
    ledger: Path | None = None,
) -> dict[str, Any]:
    """Return stable hook/wrapper payload for active manifest finalization coverage."""
    workspace = workspace.resolve()
    manifest_path = (manifest or workspace / "obsidian-vault" / "dispatch" / "next_dispatch_manifest.json").resolve()
    ledger_path = (ledger or workspace / "reports" / "task_finalization.jsonl").resolve()
    if not manifest_path.is_file():
        return {
            "schema": ENFORCE_ACTIVE_MANIFEST_SCHEMA,
            "workspace": str(workspace),
            "manifest": str(manifest_path),
            "ledger": str(ledger_path),
            "status": "no_manifest",
            "completion_gap_count": 0,
            "completion_gaps": [],
            "enforced": False,
            "reason": "active dispatch manifest not found",
        }
    gaps = manifest_completion_gaps(manifest_path, ledger_path)
    return {
        "schema": ENFORCE_ACTIVE_MANIFEST_SCHEMA,
        "workspace": str(workspace),
        "manifest": str(manifest_path),
        "ledger": str(ledger_path),
        "status": "blocked" if gaps else "ok",
        "completion_gap_count": len(gaps),
        "completion_gaps": gaps,
        "enforced": True,
        "reason": "terminal manifest rows require canonical task-finalization ledger closure",
    }


def parse_verification(items: list[str]) -> dict[str, Any]:
    commands = []
    passed = True
    for item in items:
        if "=" in item:
            command, raw_code = item.rsplit("=", 1)
            try:
                exit_code = int(raw_code)
            except ValueError:
                command = item
                exit_code = 1
        else:
            command = item
            exit_code = 0
        commands.append({"command": command.strip(), "exit_code": exit_code})
        if exit_code != 0:
            passed = False
    return {"commands": commands, "passed": passed}


def changed_files_for_commit(commit: str) -> list[str]:
    res = subprocess.run(
        ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", commit],
        cwd=REPO_ROOT, capture_output=True, text=True)
    if res.returncode != 0:
        raise ValueError(res.stderr.strip() or f"cannot inspect commit {commit}")
    return [line.strip() for line in res.stdout.splitlines() if line.strip()]


def validate_pr_range(start_pr: int, end_pr: int) -> None:
    if start_pr < 1 or end_pr < 1:
        raise ValueError("PR range must use positive PR numbers")
    if start_pr > end_pr:
        raise ValueError("start-pr must be less than or equal to end-pr")


def parse_pr_merge_subject(subject: str) -> tuple[int, str, str] | None:
    match = PR_MERGE_RE.match(subject.strip())
    if not match:
        return None
    return int(match.group(1)), match.group(2), match.group(3)


def changed_files_for_merge_commit(commit: str) -> list[str]:
    res = subprocess.run(
        ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", "-m", "--first-parent", commit],
        cwd=REPO_ROOT, capture_output=True, text=True)
    if res.returncode != 0:
        raise ValueError(res.stderr.strip() or f"cannot inspect merge commit {commit}")
    return [line.strip() for line in res.stdout.splitlines() if line.strip()]


def discover_pr_merges(base_ref: str, start_pr: int, end_pr: int) -> list[PrMerge]:
    validate_pr_range(start_pr, end_pr)
    res = subprocess.run(
        ["git", "log", base_ref, "--first-parent", "--merges", "--format=%H%x00%cI%x00%s"],
        cwd=REPO_ROOT, capture_output=True, text=True)
    if res.returncode != 0:
        raise ValueError(res.stderr.strip() or f"cannot inspect first-parent history for {base_ref}")
    merges: dict[int, PrMerge] = {}
    for line in res.stdout.splitlines():
        parts = line.split("\x00", 2)
        if len(parts) != 3:
            continue
        commit, merged_at, subject = (part.strip() for part in parts)
        parsed = parse_pr_merge_subject(subject)
        if parsed is None:
            continue
        pr_number, source_owner, source_branch = parsed
        if start_pr <= pr_number <= end_pr:
            merges[pr_number] = PrMerge(
                pr_number=pr_number,
                merge_commit=commit,
                merged_at=merged_at,
                source_owner=source_owner,
                source_branch=source_branch,
                subject=subject,
                changed_files=tuple(changed_files_for_merge_commit(commit)),
            )
    return [merges[pr] for pr in sorted(merges)]


def parse_pr_number_from_text(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    match = PR_PULL_ARTIFACT_RE.match(text)
    if match:
        return int(match.group(1))
    match = re.match(r"^PR[-_]?([1-9][0-9]*)$", text, re.IGNORECASE)
    if match:
        return int(match.group(1))
    match = PR_TASK_RE.search(text)
    if match:
        return int(match.group(1))
    return None


def pr_number_from_row(row: dict[str, Any], commit_to_pr: dict[str, int]) -> int | None:
    artifact = str(row.get("terminal_artifact") or "").strip()
    pr_number = parse_pr_number_from_text(artifact)
    if pr_number is not None:
        return pr_number
    commit_match = COMMIT_ARTIFACT_RE.match(artifact)
    if commit_match:
        artifact_sha = commit_match.group(1).lower()
        for merge_sha, merge_pr in commit_to_pr.items():
            if merge_sha.lower().startswith(artifact_sha):
                return merge_pr
    commit_match = PR_COMMIT_ARTIFACT_RE.match(artifact)
    if commit_match:
        artifact_sha = commit_match.group(1).lower()
        for merge_sha, merge_pr in commit_to_pr.items():
            if merge_sha.lower().startswith(artifact_sha):
                return merge_pr
    for key in ("gap_id", "task_id"):
        pr_number = parse_pr_number_from_text(row.get(key))
        if pr_number is not None:
            return pr_number
    return None


def collect_pr_ledger_rows(
        ledger: Path,
        commit_to_pr: dict[str, int],
        start_pr: int,
        end_pr: int) -> tuple[dict[int, list[dict[str, Any]]], dict[int, list[dict[str, Any]]]]:
    valid: dict[int, list[dict[str, Any]]] = {}
    invalid: dict[int, list[dict[str, Any]]] = {}
    retired: set[tuple[str, str]] = set()
    for index, raw in enumerate(read_jsonl(ledger), start=1):
        row = normalize_row(raw)
        errors = raw_row_errors(raw) + validate_row(row)
        key = (row["gap_id"], row["slot_id"])
        if key in retired:
            errors.append(f"finalization row after retired gap/slot {key}")
        if row["status"] in GAP_RETIRING_STATUSES:
            retired.add(key)
        pr_number = pr_number_from_row(row, commit_to_pr)
        if pr_number is None or not (start_pr <= pr_number <= end_pr):
            continue
        if errors:
            invalid.setdefault(pr_number, []).append({
                "line": index,
                "task_id": row.get("task_id"),
                "errors": errors,
                "terminal_artifact": row.get("terminal_artifact"),
            })
        else:
            valid.setdefault(pr_number, []).append(row)
    return valid, invalid


def terminal_artifact_for_merge(merge: PrMerge) -> str:
    return f"commit:{merge.merge_commit}"


def accepted_terminal_artifacts_for_pr(merge: PrMerge) -> set[str]:
    return {
        terminal_artifact_for_merge(merge),
        f"https://github.com/Vuk97/auditooor/pull/{merge.pr_number}",
        f"https://github.com/Vuk97/auditooor/pull/{merge.pr_number}/",
        f"https://github.com/Vuk97/auditooor/commit/{merge.merge_commit}",
        f"https://github.com/Vuk97/auditooor/commit/{merge.merge_commit}/",
    }


def build_pr_range_status(
        ledger: Path,
        base_ref: str,
        start_pr: int,
        end_pr: int,
        discovered: list[PrMerge] | None = None) -> dict[str, Any]:
    validate_pr_range(start_pr, end_pr)
    merges = discovered if discovered is not None else discover_pr_merges(base_ref, start_pr, end_pr)
    merge_by_pr = {merge.pr_number: merge for merge in merges}
    commit_to_pr = {merge.merge_commit: merge.pr_number for merge in merges}
    valid_by_pr, invalid_by_pr = collect_pr_ledger_rows(ledger, commit_to_pr, start_pr, end_pr)
    rows: list[dict[str, Any]] = []
    for pr_number in range(start_pr, end_pr + 1):
        merge = merge_by_pr.get(pr_number)
        valid_rows = valid_by_pr.get(pr_number, [])
        invalid_rows = invalid_by_pr.get(pr_number, [])
        expected_artifact = terminal_artifact_for_merge(merge) if merge else None
        accepted_artifacts = accepted_terminal_artifacts_for_pr(merge) if merge else set()
        matching_rows = [
            row for row in valid_rows
            if row.get("status") == "landed"
            and row.get("finalization_row_kind") == "merged_pr"
            and row.get("terminal_artifact") in accepted_artifacts
        ] if expected_artifact else []
        proof = {
            "first_parent_merge": merge is not None,
            "merge_commit_exists": commit_exists(merge.merge_commit) if merge else False,
            "changed_files_non_empty": bool(merge and merge.changed_files),
            "ledger_row_valid": bool(matching_rows),
            "terminal_artifact_matches": bool(matching_rows),
        }
        if merge is None:
            status = "history_missing"
        elif invalid_rows:
            status = "invalid"
        elif matching_rows:
            status = "covered"
        elif valid_rows:
            status = "mismatch"
        else:
            status = "missing"
        rows.append({
            "pr_number": pr_number,
            "status": status,
            "merge_commit": merge.merge_commit if merge else None,
            "merged_at": merge.merged_at if merge else None,
            "source_branch": merge.source_branch if merge else None,
            "expected_terminal_artifact": expected_artifact,
            "changed_files": list(merge.changed_files) if merge else [],
            "ledger_task_ids": [row["task_id"] for row in valid_rows],
            "invalid_rows": invalid_rows,
            "proof": proof,
        })
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    if counts.get("invalid") or counts.get("mismatch") or counts.get("history_missing"):
        readiness = "invalid"
    elif counts.get("missing"):
        readiness = "missing"
    else:
        readiness = "ready"
    return {
        "schema": PR_RANGE_STATUS_SCHEMA,
        "generated_at": utc_now(),
        "ledger": rel_display(ledger),
        "base_ref": base_ref,
        "start_pr": start_pr,
        "end_pr": end_pr,
        "summary": {
            "readiness": readiness,
            "expected_count": end_pr - start_pr + 1,
            "discovered_count": len(merges),
            "covered_count": counts.get("covered", 0),
            "missing_count": counts.get("missing", 0),
            "invalid_count": counts.get("invalid", 0),
            "mismatch_count": counts.get("mismatch", 0),
            "history_missing_count": counts.get("history_missing", 0),
            "status_counts": dict(sorted(counts.items())),
        },
        "rows": rows,
    }


def render_pr_range_status(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# Task Finalization PR Range Status",
        "",
        f"- Ledger: `{payload['ledger']}`",
        f"- Base ref: `{payload['base_ref']}`",
        f"- PR range: `#{payload['start_pr']}` through `#{payload['end_pr']}`",
        f"- Readiness: `{summary['readiness']}`",
        f"- Covered: `{summary['covered_count']}` / `{summary['expected_count']}`",
        f"- Missing: `{summary['missing_count']}`",
        f"- Invalid: `{summary['invalid_count']}`",
        f"- Mismatch: `{summary['mismatch_count']}`",
        f"- History missing: `{summary['history_missing_count']}`",
        "",
        "| PR | Status | Merge Commit | Ledger Tasks |",
        "|---|---|---|---|",
    ]
    for row in payload["rows"]:
        merge_commit = row["merge_commit"][:12] if row["merge_commit"] else "none"
        tasks = ", ".join(f"`{task_id}`" for task_id in row["ledger_task_ids"]) or "none"
        lines.append(f"| `#{row['pr_number']}` | `{row['status']}` | `{merge_commit}` | {tasks} |")
    lines.append("")
    return "\n".join(lines)


def pr_backfill_task_id(merge: PrMerge) -> str:
    return slugify(f"pr{merge.pr_number}-{merge.source_branch}-{merge.merge_commit[:12]}")


def pr_backfill_row(merge: PrMerge, owner: str, base_ref: str, start_pr: int, end_pr: int) -> dict[str, Any]:
    task_id = pr_backfill_task_id(merge)
    diff_command = f"git diff-tree --no-commit-id --name-only -r -m --first-parent {merge.merge_commit}"
    log_command = f"git log {base_ref} --first-parent --merges --format=%H%x00%cI%x00%s"
    return {
        "schema": SCHEMA,
        "task_id": task_id,
        "gap_id": f"PR{merge.pr_number}",
        "slot_id": f"slot-{((merge.pr_number - start_pr) % 5) + 1}",
        "status": "landed",
        "finalization_row_kind": "merged_pr",
        "owner": owner,
        "dispatch_source": f"git:first-parent:{base_ref}#{merge.pr_number}",
        "source_manifest": f"git:{base_ref}:first-parent-pr-range:{start_pr}-{end_pr}",
        "terminal_artifact": terminal_artifact_for_merge(merge),
        "changed_files": list(merge.changed_files),
        "verification": {
            "commands": [
                {"command": f"git cat-file -e {merge.merge_commit}^{{commit}}", "exit_code": 0},
                {"command": diff_command, "exit_code": 0},
                {"command": log_command, "exit_code": 0},
            ],
            "passed": True,
        },
        "open_followups": [],
        "docs_updated": True,
        "readme_updated": False,
        "frontdoor_updated": False,
        "outcome_or_calibration_updated": False,
        "memory_updates": [f"obsidian-vault/tasks/finalized/{task_id}.md"],
        "blocked_by": None,
        "closed_at": merge.merged_at,
    }


def build_pr_range_backfill(
        ledger: Path,
        completed_log: Path,
        notes_dir: Path,
        base_ref: str,
        start_pr: int,
        end_pr: int,
        owner: str,
        dry_run: bool,
        discovered: list[PrMerge] | None = None) -> dict[str, Any]:
    validate_pr_range(start_pr, end_pr)
    status_before = build_pr_range_status(ledger, base_ref, start_pr, end_pr, discovered=discovered)
    blockers = [
        row for row in status_before["rows"]
        if row["status"] in {"invalid", "mismatch", "history_missing"}
        or (
            row["status"] == "missing"
            and (not row["proof"]["merge_commit_exists"] or not row["proof"]["changed_files_non_empty"])
        )
    ]
    if blockers:
        blocked_prs = ", ".join(f"#{row['pr_number']}:{row['status']}" for row in blockers[:12])
        raise ValueError(f"cannot backfill PR range with unresolved blockers: {blocked_prs}")
    merge_by_pr = {merge.pr_number: merge for merge in (
        discovered if discovered is not None else discover_pr_merges(base_ref, start_pr, end_pr))}
    generated_rows: list[dict[str, Any]] = []
    append_results: list[dict[str, Any]] = []
    for status_row in status_before["rows"]:
        if status_row["status"] != "missing":
            continue
        merge = merge_by_pr[status_row["pr_number"]]
        row = pr_backfill_row(merge, owner, base_ref, start_pr, end_pr)
        if dry_run:
            normalized = normalize_row(row)
            errors = validate_row(normalized)
            if errors:
                raise ValueError(f"generated PR #{merge.pr_number} row failed validation: {'; '.join(errors)}")
            generated_rows.append(normalized)
        else:
            result = append_row(row, ledger, completed_log, notes_dir, dry_run=False)
            append_results.append(result)
            generated_rows.append(result["row"])
    payload: dict[str, Any] = {
        "schema": PR_RANGE_BACKFILL_SCHEMA,
        "generated_at": utc_now(),
        "ledger": rel_display(ledger),
        "completed_log": rel_display(completed_log),
        "notes_dir": rel_display(notes_dir),
        "base_ref": base_ref,
        "start_pr": start_pr,
        "end_pr": end_pr,
        "owner": owner,
        "dry_run": dry_run,
        "status_before": status_before["summary"],
        "generated_count": len(generated_rows),
        "appended_count": 0 if dry_run else len(append_results),
        "generated_rows": generated_rows,
        "append_results": append_results,
    }
    if not dry_run:
        payload["status_after"] = build_pr_range_status(
            ledger, base_ref, start_pr, end_pr, discovered=list(merge_by_pr.values()))["summary"]
    return payload


def render_pr_range_backfill(payload: dict[str, Any]) -> str:
    action = "Dry-run generated" if payload["dry_run"] else "Appended"
    lines = [
        "# Task Finalization PR Range Backfill",
        "",
        f"- Ledger: `{payload['ledger']}`",
        f"- Base ref: `{payload['base_ref']}`",
        f"- PR range: `#{payload['start_pr']}` through `#{payload['end_pr']}`",
        f"- Dry run: `{str(payload['dry_run']).lower()}`",
        f"- {action}: `{payload['generated_count']}` row(s)",
        f"- Readiness before: `{payload['status_before']['readiness']}`",
    ]
    if payload.get("status_after"):
        lines.append(f"- Readiness after: `{payload['status_after']['readiness']}`")
    lines.extend(["", "## Rows", ""])
    if payload["generated_rows"]:
        for row in payload["generated_rows"]:
            lines.append(
                f"- `{row['task_id']}` -> `{row['terminal_artifact']}` "
                f"({len(row['changed_files'])} changed file(s))")
    else:
        lines.append("- _(none)_")
    lines.append("")
    return "\n".join(lines)


def write_output(text: str, path: Path | None) -> None:
    if path is None:
        print(text, end="" if text.endswith("\n") else "\n")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--ledger", default=str(DEFAULT_LEDGER))
    parser.add_argument("--vault-dir", default=str(DEFAULT_VAULT))
    parser.add_argument("--completed-log", default=None)
    parser.add_argument("--notes-dir", default=None)


def resolved_paths(args: argparse.Namespace) -> tuple[Path, Path, Path]:
    vault = Path(args.vault_dir).resolve()
    ledger = Path(args.ledger).resolve()
    completed = Path(args.completed_log).resolve() if args.completed_log else (
        vault / "gap-analysis" / "_completed.jsonl")
    notes = Path(args.notes_dir).resolve() if args.notes_dir else (
        vault / "tasks" / "finalized")
    return ledger, completed, notes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_add = sub.add_parser("add", help="append a finalization row from JSON")
    add_common_args(p_add)
    p_add.add_argument("--row", required=True, help="JSON object with finalization fields")
    p_add.add_argument("--dry-run", action="store_true")

    p_validate = sub.add_parser("validate", help="validate task_finalization.jsonl")
    p_validate.add_argument("--ledger", default=str(DEFAULT_LEDGER))

    p_report = sub.add_parser("report", help="render a read-only task finalization report")
    p_report.add_argument("--ledger", default=str(DEFAULT_LEDGER))
    p_report.add_argument("--json", action="store_true")
    p_report.add_argument("--limit", type=int, default=10, help="number of recent rows to include")
    p_report.add_argument("--out", default=None, help="optional file to write instead of stdout")

    p_summary = sub.add_parser("summary", help="summarize task_finalization.jsonl for status/current-state consumers")
    p_summary.add_argument("--ledger", default=str(DEFAULT_LEDGER))
    p_summary.add_argument("--json", action="store_true")
    p_summary.add_argument("--markdown", action="store_true")
    p_summary.add_argument("--limit", type=int, default=10, help="number of recent rows to include")
    p_summary.add_argument("--out", default=None, help="optional file to write instead of stdout")

    p_audit = sub.add_parser("audit-manifest", help="surface terminal manifest rows missing ledger closure")
    p_audit.add_argument("--manifest", required=True)
    p_audit.add_argument("--ledger", default=str(DEFAULT_LEDGER))
    p_audit.add_argument("--json", action="store_true")

    p_enforce = sub.add_parser(
        "enforce-active-manifest",
        help="hook-friendly finalization gate for the active dispatch manifest")
    p_enforce.add_argument("--workspace", default=str(REPO_ROOT))
    p_enforce.add_argument("--manifest", default=None)
    p_enforce.add_argument("--ledger", default=None)
    p_enforce.add_argument("--json", action="store_true")
    p_enforce.add_argument("--out", default=None, help="optional file to write JSON payload")

    p_commit = sub.add_parser("from-commit", help="create a finalization row from a local git commit")
    add_common_args(p_commit)
    p_commit.add_argument("--commit", required=True)
    p_commit.add_argument("--gap-id", required=True)
    p_commit.add_argument("--slot-id", required=True)
    p_commit.add_argument("--owner", required=True)
    p_commit.add_argument("--source-manifest", required=True)
    p_commit.add_argument("--dispatch-source", default="")
    p_commit.add_argument("--finalization-row-kind", default="merged_pr")
    p_commit.add_argument("--verification", action="append", default=[],
                          help="verification command as 'command=exit_code'")
    p_commit.add_argument("--knowledge-gap-ref", action="append", default=[],
                          help="KG-YYYYMMDD-NNN ref consulted by this finalization")
    p_commit.add_argument("--memory-update", action="append", default=[])
    p_commit.add_argument("--followup", action="append", default=[])
    p_commit.add_argument("--docs-updated", action="store_true")
    p_commit.add_argument("--readme-updated", action="store_true")
    p_commit.add_argument("--frontdoor-updated", action="store_true")
    p_commit.add_argument("--outcome-or-calibration-updated", action="store_true")
    p_commit.add_argument("--dry-run", action="store_true")

    p_pr_status = sub.add_parser(
        "pr-range-status",
        aliases=["task-finalization-pr-status"],
        help="report task-finalization coverage for a first-parent PR merge range")
    p_pr_status.add_argument("--ledger", default=str(DEFAULT_LEDGER))
    p_pr_status.add_argument("--base-ref", default="origin/main")
    p_pr_status.add_argument("--start-pr", "--from", dest="start_pr", type=int, default=607)
    p_pr_status.add_argument("--end-pr", "--to", dest="end_pr", type=int, default=638)
    p_pr_status.add_argument("--json", action="store_true")
    p_pr_status.add_argument("--out", default=None, help="optional file to write instead of stdout")

    p_pr_backfill = sub.add_parser(
        "backfill-pr-range",
        aliases=["task-finalization-pr-backfill"],
        help="derive and append landed finalization rows from first-parent PR merge history")
    add_common_args(p_pr_backfill)
    p_pr_backfill.add_argument("--base-ref", default="origin/main")
    p_pr_backfill.add_argument("--start-pr", "--from", dest="start_pr", type=int, default=607)
    p_pr_backfill.add_argument("--end-pr", "--to", dest="end_pr", type=int, default=638)
    p_pr_backfill.add_argument("--owner", default="codex")
    p_pr_backfill.add_argument("--dry-run", action="store_true")
    p_pr_backfill.add_argument("--write", action="store_true", help="append rows; default is dry-run")
    p_pr_backfill.add_argument("--json", action="store_true")
    p_pr_backfill.add_argument("--out", default=None, help="optional file to write instead of stdout")

    args = parser.parse_args(argv)

    try:
        if args.cmd == "add":
            ledger, completed, notes = resolved_paths(args)
            result = append_row(load_json(Path(args.row)), ledger, completed, notes, dry_run=args.dry_run)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0

        if args.cmd == "validate":
            errors = validate_ledger(Path(args.ledger).resolve())
            if errors:
                print("\n".join(errors), file=sys.stderr)
                return 1
            print(f"[task-finalization-ledger] {args.ledger} valid")
            return 0

        if args.cmd == "report":
            report = build_report(Path(args.ledger).resolve(), limit=args.limit)
            if args.json:
                text = json.dumps(report, indent=2, sort_keys=True) + "\n"
            else:
                text = render_report(report)
            write_output(text, Path(args.out).resolve() if args.out else None)
            return 0

        if args.cmd == "summary":
            summary = summarize_ledger(Path(args.ledger).resolve())
            if args.json:
                text = json.dumps(summary, indent=2, sort_keys=True) + "\n"
            else:
                text = render_summary(summary)
            write_output(text, Path(args.out).resolve() if args.out else None)
            return 0

        if args.cmd == "audit-manifest":
            gaps = manifest_completion_gaps(Path(args.manifest).resolve(), Path(args.ledger).resolve())
            payload = {"completion_gap_count": len(gaps), "completion_gaps": gaps}
            if args.json:
                print(json.dumps(payload, indent=2, sort_keys=True))
            else:
                for gap in gaps:
                    print(f"completion-gap {gap['gap_id']} {gap['slot_id']} status={gap['status']}")
                if not gaps:
                    print("[task-finalization-ledger] no completion gaps")
            return 1 if gaps else 0

        if args.cmd == "enforce-active-manifest":
            payload = enforce_active_manifest(
                Path(args.workspace),
                manifest=Path(args.manifest) if args.manifest else None,
                ledger=Path(args.ledger) if args.ledger else None,
            )
            text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
            if args.out:
                write_output(text, Path(args.out).resolve())
            elif args.json:
                print(text, end="")
            else:
                print(
                    "[task-finalization-ledger] "
                    f"{payload['status']} completion_gaps={payload['completion_gap_count']}"
                )
            return 1 if payload["completion_gap_count"] else 0

        if args.cmd == "from-commit":
            ledger, completed, notes = resolved_paths(args)
            commit_sha = resolve_commit(args.commit)
            verification = parse_verification(args.verification)
            row = {
                "schema": SCHEMA,
                "task_id": slugify(f"{args.gap_id}-{args.slot_id}-{commit_sha[:12]}"),
                "gap_id": args.gap_id,
                "slot_id": args.slot_id,
                "status": "landed",
                "finalization_row_kind": args.finalization_row_kind,
                "owner": args.owner,
                "dispatch_source": args.dispatch_source,
                "source_manifest": args.source_manifest,
                "terminal_artifact": f"commit:{commit_sha}",
                "changed_files": changed_files_for_commit(commit_sha),
                "verification": verification,
                "knowledge_gap_refs": args.knowledge_gap_ref,
                "open_followups": args.followup,
                "docs_updated": args.docs_updated,
                "readme_updated": args.readme_updated,
                "frontdoor_updated": args.frontdoor_updated,
                "outcome_or_calibration_updated": args.outcome_or_calibration_updated,
                "memory_updates": args.memory_update,
                "blocked_by": None,
                "closed_at": utc_now(),
            }
            result = append_row(row, ledger, completed, notes, dry_run=args.dry_run)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0

        if args.cmd in {"pr-range-status", "task-finalization-pr-status"}:
            payload = build_pr_range_status(
                Path(args.ledger).resolve(), args.base_ref, args.start_pr, args.end_pr)
            text = (
                json.dumps(payload, indent=2, sort_keys=True) + "\n"
                if args.json else render_pr_range_status(payload)
            )
            write_output(text, Path(args.out).resolve() if args.out else None)
            return 0

        if args.cmd in {"backfill-pr-range", "task-finalization-pr-backfill"}:
            ledger, completed, notes = resolved_paths(args)
            if args.write and args.dry_run:
                raise ValueError("--write and --dry-run are mutually exclusive")
            payload = build_pr_range_backfill(
                ledger,
                completed,
                notes,
                args.base_ref,
                args.start_pr,
                args.end_pr,
                args.owner,
                dry_run=not args.write,
            )
            text = (
                json.dumps(payload, indent=2, sort_keys=True) + "\n"
                if args.json else render_pr_range_backfill(payload)
            )
            write_output(text, Path(args.out).resolve() if args.out else None)
            return 0
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    return 2


if __name__ == "__main__":
    sys.exit(main())
