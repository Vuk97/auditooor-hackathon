#!/usr/bin/env python3
"""knowledge-gap-log.py - canonical memory for unresolved missing truth.

MCL-6 turns "we do not know this yet" into durable memory:

  - append one machine event to reports/knowledge_gaps.jsonl
  - write a vault projection under obsidian-vault/knowledge-gaps/
  - expose open gaps to L4 as future G8 next-loop candidates

The ledger is append-only. Vault notes are projections and are never the source
of truth.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LEDGER = REPO_ROOT / "reports" / "knowledge_gaps.jsonl"
DEFAULT_VAULT = REPO_ROOT / "obsidian-vault"
DEFAULT_NOTES_DIR = DEFAULT_VAULT / "knowledge-gaps"
SCHEMA = "auditooor.knowledge_gap_event.v1"
SCHEMA_V2 = "auditooor.knowledge_gap_event.v2"
ACCEPTED_SCHEMAS = {SCHEMA, SCHEMA_V2}

# v1 lifecycle event types (always allowed under either schema constant).
V1_EVENT_TYPES = {"opened", "resolved", "reopened"}
# v2-only event types: REQUIRE schema=SCHEMA_V2; status remains 'open' for all of them.
V2_ONLY_EVENT_TYPES = {"progressed", "partially_resolved", "blocked_sharper", "narrowed"}
EVENT_TYPES = V1_EVENT_TYPES | V2_ONLY_EVENT_TYPES
# Event types that leave the gap in status='open' (so the gap is still active for natural-key bookkeeping).
OPEN_EVENT_TYPES = {"opened", "reopened"} | V2_ONLY_EVENT_TYPES
# v2-only event-type-specific required fields.
V2_EVENT_REQUIRED_FIELDS = {
    "progressed": ("progress_evidence",),
    "partially_resolved": ("remaining_blocker", "progress_evidence"),
    "blocked_sharper": ("sharper_rerun_command",),
    "narrowed": ("narrowing_supersedes_question",),
}
# All v2-only optional fields the validator must preserve through normalize_row.
V2_OPTIONAL_FIELDS = (
    "progress_evidence",
    "remaining_blocker",
    "sharper_rerun_command",
    "narrowing_supersedes_question",
)
STATUSES = {"open", "resolved"}
AREAS = {
    "docs",
    "fixture",
    "gate",
    "harness",
    "memory",
    "outcome",
    "proof",
    "protocol-semantics",
    "provider-routing",
    "rubric",
    "scope",
    "source",
    "unknown",
}
GAP_TYPES = {
    "harness_root_cause_unknown",
    "insufficient_outcome_sample",
    "missing_context_pack",
    "missing_fixture",
    "missing_live_proof_row",
    "missing_scope_rubric",
    "missing_source_root",
    "provider_routing_under_data",
    "unimplemented_gate",
    "unknown",
    "unknown_protocol_semantics",
}
SEVERITIES = {"low", "medium", "high"}
ESTIMATES = {"low", "med", "high"}

REQUIRED_ROW_FIELDS = (
    "schema",
    "event_id",
    "event_type",
    "gap_id",
    "candidate_gap_id",
    "status",
    "occurred_at",
    "actor",
    "area",
    "gap_type",
    "severity",
    "title",
    "question",
    "description",
    "evidence",
    "remediation",
    "blocked_by_artifacts",
    "downstream_blocked_tasks",
    "source_paths",
    "analyzer_target_paths",
    "yield_estimate",
    "effort_estimate",
    "heuristic_fp_risk",
    "heuristic_fn_risk",
    "resolution_summary",
    "resolution_evidence_paths",
    "terminal_artifact",
    "verification",
    "reopen_reason",
)

GAP_ID_RE = re.compile(r"^KG-[A-Za-z0-9][A-Za-z0-9_.-]{0,60}$")
EVENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,128}$")
TASK_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:#/-]{0,128}$")
ISO_TS_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)
COMMIT_ARTIFACT_RE = re.compile(r"^commit:([0-9a-fA-F]{7,40})(?::.*)?$")
GITHUB_ARTIFACT_RE = re.compile(
    r"^https://github\.com/Vuk97/auditooor/(?:pull/[1-9][0-9]*|commit/[0-9a-fA-F]{7,40})/?$")

ROOT_FILES = {"AGENTS.md", "Makefile", "README.md"}
SAFE_PREFIXES = (
    "docs/",
    "obsidian-vault/dispatch/",
    "obsidian-vault/gap-analysis/",
    "obsidian-vault/knowledge-gaps/",
    "obsidian-vault/limitations/",
    "obsidian-vault/tasks/finalized/",
    "reference/",
    "reports/",
    "templates/",
    "tools/",
)
FORBIDDEN_PATH_PARTS = {
    ".archive",
    ".git",
    ".privacy",
    "_archive",
    "_privacy_quarantine",
    "archive",
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def parse_occurred_at(value: Any) -> dt.datetime:
    text = str(value).strip()
    if not ISO_TS_RE.match(text):
        raise ValueError("occurred_at must be ISO-8601 with explicit timezone")
    parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("occurred_at must include timezone")
    return parsed.astimezone(dt.timezone.utc)


def clean_text(value: Any) -> str:
    text = str(value or "").strip()
    return "".join(" " if ord(ch) < 32 else ch for ch in text)


def markdown_text(value: Any) -> str:
    return clean_text(value).replace("`", "'")


def clean_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    raw = value if isinstance(value, list) else [value]
    out: list[str] = []
    for item in raw:
        text = clean_text(item)
        if text and text not in out:
            out.append(text)
    return out


def parse_verification_arg(value: str) -> dict[str, Any]:
    text = value.strip()
    if not text:
        raise ValueError("verification command cannot be empty")
    command, sep, code_text = text.rpartition("=")
    if not sep:
        raise ValueError("verification must use COMMAND=EXIT_CODE")
    command = command.strip()
    if not command:
        raise ValueError("verification command cannot be empty")
    try:
        exit_code = int(code_text.strip())
    except ValueError as exc:
        raise ValueError("verification exit code must be integer") from exc
    return {"command": command, "exit_code": exit_code}


def normalize_verification(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"commands": [], "passed": False}
    commands: list[dict[str, Any]] = []
    for item in value.get("commands") or []:
        if not isinstance(item, dict):
            continue
        command = clean_text(item.get("command"))
        exit_code = item.get("exit_code")
        if command:
            commands.append({"command": command, "exit_code": exit_code})
    return {"commands": commands, "passed": value.get("passed") is True}


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


def rel_display(path: Path, repo: Path = REPO_ROOT) -> str:
    try:
        return path.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError:
        return str(path)


def normalize_question(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lower())


def natural_key(row: dict[str, Any]) -> tuple[str, str, tuple[str, ...]]:
    return (
        str(row.get("area") or ""),
        normalize_question(str(row.get("question") or "")),
        tuple(sorted(clean_string_list(row.get("blocked_by_artifacts")))),
    )


def commit_exists(sha: str, repo: Path = REPO_ROOT) -> bool:
    import subprocess

    res = subprocess.run(
        ["git", "cat-file", "-e", f"{sha}^{{commit}}"],
        cwd=repo, capture_output=True, text=True)
    return res.returncode == 0


def is_clean_ref_text(text: str) -> bool:
    if not text or any(ord(ch) < 32 for ch in text):
        return False
    if "`" in text or text.startswith("<") or text.endswith(">"):
        return False
    lowered = text.lower()
    return " or " not in lowered and "-or-" not in lowered


def vault_uri_is_safe(text: str) -> bool:
    rel = text.removeprefix("vault://")
    parts = tuple(part for part in Path(rel).parts if part and part != ".")
    if not rel or not parts:
        return False
    return not any(part == ".." or part in FORBIDDEN_PATH_PARTS or part.startswith(".") for part in parts)


def path_is_safe_ref(value: str, repo: Path = REPO_ROOT, *, must_exist: bool = True,
                     allow_vault_uri: bool = False, allow_self_ledger: Path | None = None) -> bool:
    text = clean_text(value)
    if not is_clean_ref_text(text):
        return False
    if allow_vault_uri and text.startswith("vault://"):
        return vault_uri_is_safe(text)
    if allow_self_ledger is not None:
        try:
            path_value = Path(text).expanduser()
            candidate_self = path_value if path_value.is_absolute() else repo / path_value
            if candidate_self.resolve() == allow_self_ledger.resolve():
                return True
        except OSError:
            pass
    if text.startswith("commit:"):
        match = COMMIT_ARTIFACT_RE.match(text)
        return bool(match and commit_exists(match.group(1), repo))
    if text.startswith("https://github.com/Vuk97/auditooor/"):
        return bool(GITHUB_ARTIFACT_RE.match(text))
    if "://" in text or text.startswith("external:"):
        return False
    if text.startswith("/") or text.startswith("~"):
        return False
    parts = tuple(part for part in Path(text).parts if part and part != ".")
    if not parts or any(part == ".." or part.startswith(".") for part in parts):
        return False
    if any(part in FORBIDDEN_PATH_PARTS for part in parts):
        return False
    rel = "/".join(parts)
    if rel not in ROOT_FILES and not any(rel.startswith(prefix) for prefix in SAFE_PREFIXES):
        return False
    artifact_path = (repo / rel).resolve()
    try:
        artifact_path.relative_to(repo.resolve())
    except ValueError:
        return False
    return artifact_path.is_file() if must_exist else True


def artifact_proved(value: Any, repo: Path = REPO_ROOT) -> bool:
    if value is None:
        return False
    return path_is_safe_ref(str(value), repo, must_exist=True, allow_vault_uri=False)


def normalize_row(row: dict[str, Any]) -> dict[str, Any]:
    normalized = {key: row.get(key) for key in REQUIRED_ROW_FIELDS}
    for key in (
        "actor",
        "area",
        "candidate_gap_id",
        "description",
        "effort_estimate",
        "event_id",
        "event_type",
        "evidence",
        "gap_id",
        "gap_type",
        "heuristic_fn_risk",
        "heuristic_fp_risk",
        "question",
        "remediation",
        "reopen_reason",
        "resolution_summary",
        "severity",
        "status",
        "terminal_artifact",
        "title",
        "yield_estimate",
    ):
        normalized[key] = clean_text(normalized.get(key))
    for key in (
        "analyzer_target_paths",
        "blocked_by_artifacts",
        "downstream_blocked_tasks",
        "resolution_evidence_paths",
        "source_paths",
    ):
        normalized[key] = clean_string_list(normalized.get(key))
    normalized["verification"] = normalize_verification(normalized.get("verification"))
    # Preserve v2-only optional fields when present so they survive validate -> append round-trips.
    for key in V2_OPTIONAL_FIELDS:
        if key in row and row[key] is not None and str(row[key]).strip():
            normalized[key] = clean_text(row[key])
    return normalized


def raw_row_errors(row: dict[str, Any]) -> list[str]:
    return [f"{key} is required" for key in REQUIRED_ROW_FIELDS if key not in row]


def raw_type_errors(row: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    string_fields = {
        "schema",
        "event_id",
        "event_type",
        "gap_id",
        "candidate_gap_id",
        "status",
        "occurred_at",
        "actor",
        "area",
        "gap_type",
        "severity",
        "title",
        "question",
        "description",
        "evidence",
        "remediation",
        "yield_estimate",
        "effort_estimate",
        "heuristic_fp_risk",
        "heuristic_fn_risk",
        "resolution_summary",
        "terminal_artifact",
        "reopen_reason",
    }
    list_fields = {
        "analyzer_target_paths",
        "blocked_by_artifacts",
        "downstream_blocked_tasks",
        "resolution_evidence_paths",
        "source_paths",
    }
    for key in string_fields:
        if key in row and not isinstance(row[key], str):
            errors.append(f"{key} must be string")
    for key in list_fields:
        if key in row:
            if not isinstance(row[key], list):
                errors.append(f"{key} must be a list")
            elif any(not isinstance(item, str) for item in row[key]):
                errors.append(f"{key} must contain only strings")
    verification = row.get("verification")
    if "verification" in row and not isinstance(verification, dict):
        errors.append("verification must be an object")
    elif isinstance(verification, dict):
        commands = verification.get("commands")
        if not isinstance(commands, list):
            errors.append("verification.commands must be a list")
        else:
            for index, command_row in enumerate(commands):
                if not isinstance(command_row, dict):
                    errors.append(f"verification.commands[{index}] must be an object")
                else:
                    if not isinstance(command_row.get("command"), str):
                        errors.append(f"verification.commands[{index}].command must be string")
                    if type(command_row.get("exit_code")) is not int:
                        errors.append(f"verification.commands[{index}].exit_code must be integer")
        if not isinstance(verification.get("passed"), bool):
            errors.append("verification.passed must be boolean")
    return errors


def validate_row(row: dict[str, Any], repo: Path = REPO_ROOT, ledger: Path | None = None) -> list[str]:
    errors: list[str] = []
    schema_value = row.get("schema")
    if schema_value not in ACCEPTED_SCHEMAS:
        errors.append(f"schema must be one of {sorted(ACCEPTED_SCHEMAS)}")
    event_type = row.get("event_type")
    if event_type in V2_ONLY_EVENT_TYPES and schema_value != SCHEMA_V2:
        errors.append(f"event_type={event_type} requires schema={SCHEMA_V2}")
    gap_id = row.get("gap_id")
    if not isinstance(gap_id, str) or GAP_ID_RE.match(gap_id) is None:
        errors.append("gap_id must be KG-* slug-safe")
    expected_candidate = f"G8-{gap_id}" if isinstance(gap_id, str) else ""
    if row.get("candidate_gap_id") != expected_candidate:
        errors.append("candidate_gap_id must be G8-<gap_id>")
    if not isinstance(row.get("event_id"), str) or EVENT_ID_RE.match(row["event_id"]) is None:
        errors.append("event_id is required and must be slug-safe")
    if event_type not in EVENT_TYPES:
        errors.append(f"event_type must be one of {sorted(EVENT_TYPES)}")
    if row.get("status") not in STATUSES:
        errors.append(f"status must be one of {sorted(STATUSES)}")
    if event_type in OPEN_EVENT_TYPES and row.get("status") != "open":
        errors.append("opened/reopened/v2-progression rows must have status=open")
    if event_type == "resolved" and row.get("status") != "resolved":
        errors.append("resolved rows must have status=resolved")
    # v2-only event-type-specific required fields.
    for required_field in V2_EVENT_REQUIRED_FIELDS.get(event_type, ()):
        value = row.get(required_field)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{event_type} rows require {required_field}")
    # v2-only progress_evidence path-safety check (when present + path-shaped).
    progress_evidence = row.get("progress_evidence")
    if isinstance(progress_evidence, str) and progress_evidence.strip():
        if not path_is_safe_ref(progress_evidence, repo, must_exist=True,
                                allow_vault_uri=False, allow_self_ledger=ledger):
            errors.append(f"progress_evidence is unsafe or missing: {progress_evidence}")
    if row.get("area") not in AREAS:
        errors.append(f"area must be one of {sorted(AREAS)}")
    if row.get("gap_type") not in GAP_TYPES:
        errors.append(f"gap_type must be one of {sorted(GAP_TYPES)}")
    if row.get("severity") not in SEVERITIES:
        errors.append(f"severity must be one of {sorted(SEVERITIES)}")
    if row.get("yield_estimate") not in ESTIMATES:
        errors.append(f"yield_estimate must be one of {sorted(ESTIMATES)}")
    if row.get("effort_estimate") not in ESTIMATES:
        errors.append(f"effort_estimate must be one of {sorted(ESTIMATES)}")
    for key in ("actor", "title", "question", "description", "evidence", "remediation"):
        if not isinstance(row.get(key), str) or not row[key].strip():
            errors.append(f"{key} is required")
    if row.get("event_type") == "reopened" and not row.get("reopen_reason"):
        errors.append("reopened rows require reopen_reason")
    try:
        parse_occurred_at(row.get("occurred_at"))
    except Exception:
        errors.append("occurred_at must be ISO-8601 with explicit timezone")

    for key in ("blocked_by_artifacts", "source_paths", "analyzer_target_paths", "resolution_evidence_paths"):
        if not isinstance(row.get(key), list) or any(not isinstance(item, str) or not item for item in row[key]):
            errors.append(f"{key} must be a list of non-empty strings")
    for ref in row.get("blocked_by_artifacts") or []:
        if not path_is_safe_ref(ref, repo, must_exist=True, allow_vault_uri=True, allow_self_ledger=ledger):
            errors.append(f"blocked_by_artifacts contains unsafe or missing ref: {ref}")
    for ref in row.get("source_paths") or []:
        if not path_is_safe_ref(ref, repo, must_exist=True, allow_vault_uri=False, allow_self_ledger=ledger):
            errors.append(f"source_paths contains unsafe or missing ref: {ref}")
    for ref in row.get("analyzer_target_paths") or []:
        if not path_is_safe_ref(ref, repo, must_exist=True, allow_vault_uri=False, allow_self_ledger=ledger):
            errors.append(f"analyzer_target_paths contains unsafe or missing ref: {ref}")
    for task_ref in row.get("downstream_blocked_tasks") or []:
        if not isinstance(task_ref, str) or TASK_REF_RE.match(task_ref) is None or "`" in task_ref:
            errors.append(f"downstream_blocked_tasks contains unsafe ref: {task_ref}")

    verification = row.get("verification")
    if not isinstance(verification, dict):
        errors.append("verification must be an object")
    else:
        commands = verification.get("commands")
        if not isinstance(commands, list):
            errors.append("verification.commands must be a list")
        else:
            for index, command_row in enumerate(commands):
                if not isinstance(command_row, dict) or not command_row.get("command"):
                    errors.append(f"verification.commands[{index}] must include command")
                elif type(command_row.get("exit_code")) is not int:
                    errors.append(f"verification.commands[{index}].exit_code must be an integer")
        if not isinstance(verification.get("passed"), bool):
            errors.append("verification.passed must be boolean")

    if row.get("event_type") == "resolved":
        if not row.get("resolution_summary"):
            errors.append("resolved rows require resolution_summary")
        if not row.get("resolution_evidence_paths"):
            errors.append("resolved rows require resolution_evidence_paths")
        for ref in row.get("resolution_evidence_paths") or []:
            if not path_is_safe_ref(ref, repo, must_exist=True, allow_vault_uri=False, allow_self_ledger=ledger):
                errors.append(f"resolution_evidence_paths contains unsafe or missing ref: {ref}")
        if not artifact_proved(row.get("terminal_artifact"), repo):
            errors.append("resolved rows require proved terminal_artifact")
        commands = verification.get("commands") if isinstance(verification, dict) else []
        if not commands:
            errors.append("resolved rows require verification.commands")
        elif any(command.get("exit_code") != 0 for command in commands if isinstance(command, dict)):
            errors.append("resolved verification commands must have exit_code=0")
        if isinstance(verification, dict) and verification.get("passed") is not True:
            errors.append("resolved rows require verification.passed=true")
    else:
        if row.get("resolution_summary"):
            errors.append("open rows must not set resolution_summary")
        if row.get("resolution_evidence_paths"):
            errors.append("open rows must not set resolution_evidence_paths")
        if row.get("terminal_artifact"):
            errors.append("open rows must not set terminal_artifact")
        if verification != {"commands": [], "passed": False}:
            errors.append("open rows must use empty verification")
    return errors


def validate_lifecycle(rows: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    states: dict[str, dict[str, Any]] = {}
    active_keys: dict[tuple[str, str, tuple[str, ...]], str] = {}
    event_ids: set[str] = set()
    for index, row in enumerate(rows, start=1):
        event_id = row.get("event_id")
        gap_id = row.get("gap_id")
        event_type = row.get("event_type")
        if event_id in event_ids:
            errors.append(f"row {index}: duplicate event_id {event_id}")
        event_ids.add(str(event_id))
        previous = states.get(gap_id)
        if previous is not None:
            try:
                if parse_occurred_at(row.get("occurred_at")) < parse_occurred_at(previous.get("occurred_at")):
                    errors.append(f"row {index}: occurred_at moves backward for {gap_id}")
            except ValueError:
                pass
        key = natural_key(row)
        if event_type == "opened":
            if previous is not None:
                errors.append(f"row {index}: opened event for existing gap_id {gap_id}; use reopened")
            holder = active_keys.get(key)
            if holder and holder != gap_id:
                errors.append(f"row {index}: duplicate active knowledge gap natural key held by {holder}")
            active_keys[key] = str(gap_id)
        elif event_type == "resolved":
            if previous is None or previous.get("status") != "open":
                errors.append(f"row {index}: resolved event requires an open gap")
            else:
                active_keys.pop(natural_key(previous), None)
        elif event_type == "reopened":
            if previous is None or previous.get("status") != "resolved":
                errors.append(f"row {index}: reopened event requires a resolved gap")
            holder = active_keys.get(key)
            if holder and holder != gap_id:
                errors.append(f"row {index}: duplicate active knowledge gap natural key held by {holder}")
            active_keys[key] = str(gap_id)
        elif event_type in V2_ONLY_EVENT_TYPES:
            # v2-only progression events: gap must already be open; do NOT touch active_keys
            # (same gap_id remains the active holder of its natural key).
            if previous is None or previous.get("status") != "open":
                errors.append(f"row {index}: {event_type} event requires an open gap")
        states[str(gap_id)] = row
    return errors


def validate_ledger(path: Path, repo: Path = REPO_ROOT) -> list[str]:
    if not path.is_file():
        return [f"{path}: ledger missing"]
    errors: list[str] = []
    normalized_rows: list[dict[str, Any]] = []
    for index, raw in enumerate(read_jsonl(path), start=1):
        row = normalize_row(raw)
        row_errors = raw_row_errors(raw) + raw_type_errors(raw) + validate_row(row, repo=repo, ledger=path)
        for error in row_errors:
            errors.append(f"{path}:{index}: {error}")
        normalized_rows.append(row)
    if not errors:
        errors.extend(f"{path}: {error}" for error in validate_lifecycle(normalized_rows))
    return errors


def latest_states(path: Path, repo: Path = REPO_ROOT) -> dict[str, dict[str, Any]]:
    errors = validate_ledger(path, repo=repo)
    if errors:
        raise ValueError("; ".join(errors))
    states: dict[str, dict[str, Any]] = {}
    for raw in read_jsonl(path):
        row = normalize_row(raw)
        states[row["gap_id"]] = row
    return states


def next_gap_id(rows: list[dict[str, Any]], now: str | None = None) -> str:
    stamp = (now or utc_now())[:10].replace("-", "")
    prefix = f"KG-{stamp}-"
    highest = 0
    for row in rows:
        gap_id = str(row.get("gap_id") or "")
        if gap_id.startswith(prefix):
            suffix = gap_id.removeprefix(prefix)
            if suffix.isdigit():
                highest = max(highest, int(suffix))
    return f"{prefix}{highest + 1:03d}"


def event_id_for(gap_id: str, event_type: str, occurred_at: str) -> str:
    stamp = occurred_at.replace("+00:00", "Z").replace(":", "").replace("-", "")
    stamp = re.sub(r"[^A-Za-z0-9TZ.]", "", stamp)
    return f"{gap_id}:{event_type}:{stamp}"


def build_open_row(args: argparse.Namespace, ledger: Path, repo: Path) -> dict[str, Any]:
    occurred_at = args.occurred_at or utc_now()
    existing = read_jsonl(ledger)
    gap_id = args.gap_id or next_gap_id(existing, occurred_at)
    row = {
        "schema": SCHEMA,
        "event_id": args.event_id or event_id_for(gap_id, "opened", occurred_at),
        "event_type": "opened",
        "gap_id": gap_id,
        "candidate_gap_id": f"G8-{gap_id}",
        "status": "open",
        "occurred_at": occurred_at,
        "actor": args.actor,
        "area": args.area,
        "gap_type": args.gap_type,
        "severity": args.severity,
        "title": args.title or args.question[:80],
        "question": args.question,
        "description": args.description,
        "evidence": args.evidence,
        "remediation": args.remediation,
        "blocked_by_artifacts": args.blocked_by or [],
        "downstream_blocked_tasks": args.downstream_task or [],
        "source_paths": args.source_path or [rel_display(ledger, repo)],
        "analyzer_target_paths": args.target_path or [],
        "yield_estimate": args.yield_estimate,
        "effort_estimate": args.effort_estimate,
        "heuristic_fp_risk": args.fp_risk,
        "heuristic_fn_risk": args.fn_risk,
        "resolution_summary": "",
        "resolution_evidence_paths": [],
        "terminal_artifact": "",
        "verification": {"commands": [], "passed": False},
        "reopen_reason": "",
    }
    return normalize_row(row)


def build_resolve_row(args: argparse.Namespace, ledger: Path, repo: Path) -> dict[str, Any]:
    states = latest_states(ledger, repo=repo)
    current = states.get(args.gap_id)
    if current is None:
        raise ValueError(f"unknown gap_id: {args.gap_id}")
    if current["status"] != "open":
        raise ValueError(f"gap_id is not open: {args.gap_id}")
    occurred_at = args.occurred_at or utc_now()
    commands = [parse_verification_arg(item) for item in args.verification]
    row = dict(current)
    row.update({
        "event_id": args.event_id or event_id_for(args.gap_id, "resolved", occurred_at),
        "event_type": "resolved",
        "status": "resolved",
        "occurred_at": occurred_at,
        "actor": args.actor,
        "resolution_summary": args.summary,
        "resolution_evidence_paths": args.evidence_path,
        "terminal_artifact": args.terminal_artifact,
        "verification": {"commands": commands, "passed": bool(commands) and all(c["exit_code"] == 0 for c in commands)},
        "reopen_reason": "",
    })
    return normalize_row(row)


def build_reopen_row(args: argparse.Namespace, ledger: Path, repo: Path) -> dict[str, Any]:
    states = latest_states(ledger, repo=repo)
    current = states.get(args.gap_id)
    if current is None:
        raise ValueError(f"unknown gap_id: {args.gap_id}")
    if current["status"] != "resolved":
        raise ValueError(f"gap_id is not resolved: {args.gap_id}")
    occurred_at = args.occurred_at or utc_now()
    row = dict(current)
    row.update({
        "event_id": args.event_id or event_id_for(args.gap_id, "reopened", occurred_at),
        "event_type": "reopened",
        "status": "open",
        "occurred_at": occurred_at,
        "actor": args.actor,
        "evidence": args.evidence or current["evidence"],
        "remediation": args.remediation or current["remediation"],
        "resolution_summary": "",
        "resolution_evidence_paths": [],
        "terminal_artifact": "",
        "verification": {"commands": [], "passed": False},
        "reopen_reason": args.reason,
    })
    return normalize_row(row)


def build_progression_row(args: argparse.Namespace, ledger: Path, repo: Path) -> dict[str, Any]:
    """Build a v2-only progression event (progressed / partially_resolved / blocked_sharper / narrowed).

    The gap must already exist and be in status='open'. The event keeps the gap open and writes
    the event-type-specific payload field (progress_evidence / remaining_blocker / sharper_rerun_command /
    narrowing_supersedes_question). schema is bumped to SCHEMA_V2 on the new event row.
    """
    states = latest_states(ledger, repo=repo)
    current = states.get(args.gap_id)
    if current is None:
        raise ValueError(f"unknown gap_id: {args.gap_id}")
    if current["status"] != "open":
        raise ValueError(f"gap_id is not open: {args.gap_id}")
    if args.event_type not in V2_ONLY_EVENT_TYPES:
        raise ValueError(f"event_type must be one of {sorted(V2_ONLY_EVENT_TYPES)}")
    occurred_at = args.occurred_at or utc_now()
    row = dict(current)
    row.update({
        "schema": SCHEMA_V2,
        "event_id": args.event_id or event_id_for(args.gap_id, args.event_type, occurred_at),
        "event_type": args.event_type,
        "status": "open",
        "occurred_at": occurred_at,
        "actor": args.actor,
        "resolution_summary": "",
        "resolution_evidence_paths": [],
        "terminal_artifact": "",
        "verification": {"commands": [], "passed": False},
        "reopen_reason": "",
    })
    # Drop any v2 optional fields carried over from `current`; only set the ones this event_type requires.
    for key in V2_OPTIONAL_FIELDS:
        row.pop(key, None)
    if args.progress_evidence:
        row["progress_evidence"] = args.progress_evidence
    if args.remaining_blocker:
        row["remaining_blocker"] = args.remaining_blocker
    if args.sharper_rerun_command:
        row["sharper_rerun_command"] = args.sharper_rerun_command
    if args.narrowing_supersedes_question:
        row["narrowing_supersedes_question"] = args.narrowing_supersedes_question
    return normalize_row(row)


def append_event(row: dict[str, Any], ledger: Path, notes_dir: Path,
                 repo: Path = REPO_ROOT, dry_run: bool = False) -> dict[str, Any]:
    existing_errors = validate_ledger(ledger, repo=repo) if ledger.exists() else []
    if existing_errors:
        raise ValueError("; ".join(existing_errors))
    raw_errors = raw_row_errors(row) + raw_type_errors(row)
    normalized = normalize_row(row)
    row_errors = raw_errors + validate_row(normalized, repo=repo, ledger=ledger)
    if row_errors:
        raise ValueError("; ".join(row_errors))
    combined = [normalize_row(raw) for raw in read_jsonl(ledger)] + [normalized]
    lifecycle_errors = validate_lifecycle(combined)
    if lifecycle_errors:
        raise ValueError("; ".join(lifecycle_errors))
    if not dry_run:
        append_jsonl(ledger, normalized)
        rebuild_projections(ledger, notes_dir, repo=repo)
    return {
        "row": normalized,
        "ledger": rel_display(ledger, repo),
        "note_path": rel_display(notes_dir / f"{normalized['gap_id']}.md", repo),
        "dry_run": dry_run,
    }


def yaml_scalar(value: Any) -> str:
    return json.dumps(clean_text(value))


def note_text(row: dict[str, Any], history: list[dict[str, Any]]) -> str:
    lines = [
        "---",
        'category: "knowledge-gap"',
        f'gap_id: {yaml_scalar(row["gap_id"])}',
        f'candidate_gap_id: {yaml_scalar(row["candidate_gap_id"])}',
        f'status: {yaml_scalar(row["status"])}',
        f'area: {yaml_scalar(row["area"])}',
        f'gap_type: {yaml_scalar(row["gap_type"])}',
        f'severity: {yaml_scalar(row["severity"])}',
        f'occurred_at: {yaml_scalar(row["occurred_at"])}',
        f'schema: {yaml_scalar(SCHEMA)}',
        "tags:",
        "  - memory/knowledge-gap",
        "---",
        "",
        f"# Knowledge Gap - {markdown_text(row['title'])}",
        "",
        "## Question",
        "",
        markdown_text(row["question"]),
        "",
        "## Status",
        "",
        f"- Gap ID: `{row['gap_id']}`",
        f"- Candidate gap ID: `{row['candidate_gap_id']}`",
        f"- Status: `{row['status']}`",
        f"- Area: `{row['area']}`",
        f"- Type: `{row['gap_type']}`",
        f"- Severity: `{row['severity']}`",
        f"- Yield/Effort: `{row['yield_estimate']}` / `{row['effort_estimate']}`",
        "",
        "## Description",
        "",
        markdown_text(row["description"]),
        "",
        "## Evidence",
        "",
        markdown_text(row["evidence"]),
        "",
        "## Remediation",
        "",
        markdown_text(row["remediation"]),
        "",
        "## Blocked By",
        "",
    ]
    lines.extend(f"- `{item}`" for item in row["blocked_by_artifacts"]) if row["blocked_by_artifacts"] else lines.append("- _(none)_")
    lines.extend(["", "## Downstream Blocked Tasks", ""])
    lines.extend(f"- `{item}`" for item in row["downstream_blocked_tasks"]) if row["downstream_blocked_tasks"] else lines.append("- _(none)_")
    lines.extend(["", "## Analyzer Paths", ""])
    lines.append("Source paths:")
    lines.extend(f"- `{item}`" for item in row["source_paths"]) if row["source_paths"] else lines.append("- _(none)_")
    lines.append("")
    lines.append("Target paths:")
    lines.extend(f"- `{item}`" for item in row["analyzer_target_paths"]) if row["analyzer_target_paths"] else lines.append("- _(none)_")
    if row["status"] == "resolved":
        lines.extend(["", "## Resolution", "", markdown_text(row["resolution_summary"]), ""])
        lines.append(f"- Terminal artifact: `{row['terminal_artifact']}`")
        for item in row["resolution_evidence_paths"]:
            lines.append(f"- Evidence: `{item}`")
        for command in row["verification"]["commands"]:
            lines.append(f"- `{command['command']}` -> `{command['exit_code']}`")
    if row.get("reopen_reason"):
        lines.extend(["", "## Reopen Reason", "", markdown_text(row["reopen_reason"])])
    lines.extend(["", "## Heuristic Risks", ""])
    lines.append(f"- FP risk: {markdown_text(row['heuristic_fp_risk']) or '_(none)_'}")
    lines.append(f"- FN risk: {markdown_text(row['heuristic_fn_risk']) or '_(none)_'}")
    lines.extend(["", "## History", ""])
    for item in history:
        lines.append(f"- `{item['occurred_at']}` `{item['event_type']}` by `{item['actor']}`")
    lines.append("")
    return "\n".join(lines)


def index_text(states: dict[str, dict[str, Any]]) -> str:
    rows = sorted(states.values(), key=lambda row: (row["status"] != "open", row["gap_id"]))
    lines = [
        "---",
        'category: "knowledge-gap-index"',
        f'generated_at: {yaml_scalar(utc_now())}',
        f'schema: {yaml_scalar(SCHEMA)}',
        "tags:",
        "  - memory/knowledge-gap",
        "---",
        "",
        "# Knowledge Gaps",
        "",
        "`reports/knowledge_gaps.jsonl` is canonical. These notes are projections.",
        "",
        "| Gap ID | Status | Area | Type | Severity | Title |",
        "|---|---|---|---|---|---|",
    ]
    if not rows:
        lines.append("| _(none)_ |  |  |  |  |  |")
    for row in rows:
        lines.append(
            f"| `{row['gap_id']}` | `{row['status']}` | `{row['area']}` | "
            f"`{row['gap_type']}` | `{row['severity']}` | {markdown_text(row['title'])} |")
    lines.append("")
    return "\n".join(lines)


def rebuild_projections(ledger: Path, notes_dir: Path, repo: Path = REPO_ROOT,
                        dry_run: bool = False) -> dict[str, Any]:
    states = latest_states(ledger, repo=repo)
    histories: dict[str, list[dict[str, Any]]] = {}
    for raw in read_jsonl(ledger):
        row = normalize_row(raw)
        histories.setdefault(row["gap_id"], []).append(row)
    note_paths = [notes_dir / f"{gap_id}.md" for gap_id in states]
    index_path = notes_dir / "INDEX.md"
    if not dry_run:
        notes_dir.mkdir(parents=True, exist_ok=True)
        for gap_id, row in states.items():
            (notes_dir / f"{gap_id}.md").write_text(note_text(row, histories[gap_id]), encoding="utf-8")
        index_path.write_text(index_text(states), encoding="utf-8")
    return {
        "ledger": rel_display(ledger, repo),
        "notes_dir": rel_display(notes_dir, repo),
        "index_path": rel_display(index_path, repo),
        "note_count": len(note_paths),
        "open_count": sum(1 for row in states.values() if row["status"] == "open"),
        "resolved_count": sum(1 for row in states.values() if row["status"] == "resolved"),
        "dry_run": dry_run,
    }


def summarize_ledger(ledger: Path, repo: Path = REPO_ROOT) -> dict[str, Any]:
    ledger_exists = ledger.is_file()
    raw_rows = read_jsonl(ledger)
    errors = validate_ledger(ledger, repo=repo) if ledger_exists else [f"{ledger}: ledger missing"]
    states: dict[str, dict[str, Any]] = {}
    if not errors:
        states = latest_states(ledger, repo=repo)
    open_rows = [row for row in states.values() if row["status"] == "open"]
    resolved_rows = [row for row in states.values() if row["status"] == "resolved"]
    return {
        "schema": "auditooor.knowledge_gap_summary.v1",
        "ledger": rel_display(ledger, repo),
        "ledger_exists": ledger_exists,
        "generated_at": utc_now(),
        "readiness": "missing" if not ledger_exists else ("ready" if not errors else "invalid"),
        "total_events": len(raw_rows),
        "gap_count": len(states),
        "open_count": len(open_rows),
        "resolved_count": len(resolved_rows),
        "open_gap_ids": [row["gap_id"] for row in sorted(open_rows, key=lambda item: item["gap_id"])],
        "validation_error_count": len(errors),
        "validation_errors": errors[:20],
    }


def list_rows(ledger: Path, repo: Path, status: str) -> list[dict[str, Any]]:
    states = latest_states(ledger, repo=repo)
    rows = sorted(states.values(), key=lambda row: (row["status"] != "open", row["gap_id"]))
    if status != "all":
        rows = [row for row in rows if row["status"] == status]
    return rows


def print_rows_markdown(rows: list[dict[str, Any]]) -> None:
    if not rows:
        print("_No knowledge gaps matched._")
        return
    print("| Gap ID | Status | Area | Type | Severity | Title |")
    print("|---|---|---|---|---|---|")
    for row in rows:
        print(
            f"| `{row['gap_id']}` | `{row['status']}` | `{row['area']}` | "
            f"`{row['gap_type']}` | `{row['severity']}` | {markdown_text(row['title'])} |")


def add_common_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--ledger", default=str(DEFAULT_LEDGER))
    ap.add_argument("--repo", default=str(REPO_ROOT))
    ap.add_argument("--notes-dir", default=str(DEFAULT_NOTES_DIR))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    add = sub.add_parser("add", aliases=["open"], help="append an opened knowledge-gap event")
    add_common_args(add)
    add.add_argument("--gap-id")
    add.add_argument("--event-id")
    add.add_argument("--occurred-at")
    add.add_argument("--actor", default="codex")
    add.add_argument("--area", choices=sorted(AREAS), default="unknown")
    add.add_argument("--gap-type", choices=sorted(GAP_TYPES), default="unknown")
    add.add_argument("--severity", choices=sorted(SEVERITIES), default="medium")
    add.add_argument("--title", default="")
    add.add_argument("--question", required=True)
    add.add_argument("--description", required=True)
    add.add_argument("--evidence", required=True)
    add.add_argument("--remediation", required=True)
    add.add_argument("--blocked-by", action="append", default=[])
    add.add_argument("--downstream-task", action="append", default=[])
    add.add_argument("--source-path", action="append", default=[])
    add.add_argument("--target-path", action="append", default=[])
    add.add_argument("--yield-estimate", choices=sorted(ESTIMATES), default="med")
    add.add_argument("--effort-estimate", choices=sorted(ESTIMATES), default="med")
    add.add_argument("--fp-risk", default="")
    add.add_argument("--fn-risk", default="")
    add.add_argument("--dry-run", action="store_true")
    add.add_argument("--json", action="store_true")

    resolve = sub.add_parser("resolve", help="append a resolved knowledge-gap event")
    add_common_args(resolve)
    resolve.add_argument("--gap-id", required=True)
    resolve.add_argument("--event-id")
    resolve.add_argument("--occurred-at")
    resolve.add_argument("--actor", default="codex")
    resolve.add_argument("--summary", required=True)
    resolve.add_argument("--evidence-path", action="append", required=True)
    resolve.add_argument("--terminal-artifact", required=True)
    resolve.add_argument("--verification", action="append", required=True)
    resolve.add_argument("--dry-run", action="store_true")
    resolve.add_argument("--json", action="store_true")

    reopen = sub.add_parser("reopen", help="append a reopened knowledge-gap event")
    add_common_args(reopen)
    reopen.add_argument("--gap-id", required=True)
    reopen.add_argument("--event-id")
    reopen.add_argument("--occurred-at")
    reopen.add_argument("--actor", default="codex")
    reopen.add_argument("--reason", required=True)
    reopen.add_argument("--evidence", default="")
    reopen.add_argument("--remediation", default="")
    reopen.add_argument("--dry-run", action="store_true")
    reopen.add_argument("--json", action="store_true")

    progress = sub.add_parser(
        "progress",
        help="append a v2-only progression event (progressed / partially_resolved / blocked_sharper / narrowed)",
    )
    add_common_args(progress)
    progress.add_argument("--gap-id", required=True)
    progress.add_argument("--event-id")
    progress.add_argument("--occurred-at")
    progress.add_argument("--actor", default="codex")
    progress.add_argument("--event-type", required=True, choices=sorted(V2_ONLY_EVENT_TYPES))
    progress.add_argument("--progress-evidence", default="",
                          help="path or commit:<sha> capturing the forward motion (REQUIRED for progressed/partially_resolved)")
    progress.add_argument("--remaining-blocker", default="",
                          help="REQUIRED for partially_resolved")
    progress.add_argument("--sharper-rerun-command", default="",
                          help="REQUIRED for blocked_sharper")
    progress.add_argument("--narrowing-supersedes-question", default="",
                          help="REQUIRED for narrowed")
    progress.add_argument("--dry-run", action="store_true")
    progress.add_argument("--json", action="store_true")

    list_cmd = sub.add_parser("list", help="list latest knowledge-gap states")
    add_common_args(list_cmd)
    list_cmd.add_argument("--status", choices=["open", "resolved", "all"], default="open")
    list_cmd.add_argument("--json", action="store_true")

    summary = sub.add_parser("summary", help="print ledger summary")
    add_common_args(summary)
    summary.add_argument("--json", action="store_true")

    validate = sub.add_parser("validate", help="validate the canonical ledger")
    add_common_args(validate)

    rebuild = sub.add_parser("rebuild-projections", help="rebuild vault projection notes from ledger")
    add_common_args(rebuild)
    rebuild.add_argument("--dry-run", action="store_true")
    rebuild.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    ledger = Path(args.ledger)
    repo = Path(args.repo)
    notes_dir = Path(args.notes_dir)

    try:
        if args.command in {"add", "open"}:
            result = append_event(build_open_row(args, ledger, repo), ledger, notes_dir, repo=repo, dry_run=args.dry_run)
            print(json.dumps(result, indent=2, sort_keys=True) if args.json else result["row"]["gap_id"])
            return 0
        if args.command == "resolve":
            result = append_event(build_resolve_row(args, ledger, repo), ledger, notes_dir, repo=repo, dry_run=args.dry_run)
            print(json.dumps(result, indent=2, sort_keys=True) if args.json else result["row"]["gap_id"])
            return 0
        if args.command == "reopen":
            result = append_event(build_reopen_row(args, ledger, repo), ledger, notes_dir, repo=repo, dry_run=args.dry_run)
            print(json.dumps(result, indent=2, sort_keys=True) if args.json else result["row"]["gap_id"])
            return 0
        if args.command == "progress":
            result = append_event(build_progression_row(args, ledger, repo), ledger, notes_dir, repo=repo, dry_run=args.dry_run)
            print(json.dumps(result, indent=2, sort_keys=True) if args.json else result["row"]["gap_id"])
            return 0
        if args.command == "list":
            rows = list_rows(ledger, repo, args.status)
            print(json.dumps(rows, indent=2, sort_keys=True) if args.json else "", end="")
            if not args.json:
                print_rows_markdown(rows)
            return 0
        if args.command == "summary":
            payload = summarize_ledger(ledger, repo=repo)
            if args.json:
                print(json.dumps(payload, indent=2, sort_keys=True))
            else:
                print(f"readiness: {payload['readiness']}")
                print(f"events: {payload['total_events']}")
                print(f"open: {payload['open_count']}")
                print(f"resolved: {payload['resolved_count']}")
            return 0 if payload["readiness"] == "ready" else 1
        if args.command == "validate":
            errors = validate_ledger(ledger, repo=repo)
            if errors:
                for error in errors:
                    print(error, file=sys.stderr)
                return 1
            print(f"{rel_display(ledger, repo)}: ok")
            return 0
        if args.command == "rebuild-projections":
            result = rebuild_projections(ledger, notes_dir, repo=repo, dry_run=args.dry_run)
            print(json.dumps(result, indent=2, sort_keys=True) if args.json else f"{result['note_count']} notes")
            return 0
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
