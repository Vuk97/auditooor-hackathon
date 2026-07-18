#!/usr/bin/env python3
"""V3 source-first prerequisite gate.

Checks that a workspace has the operator truth files and pinned GitHub source
targets needed before deep/proof work. In post phase it also verifies the
commit lifecycle ledger recorded matching target rows for pinned GitHub targets.

Stdlib-only. Offline-safe.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


SCHEMA = "auditooor.v3_source_first_prereq_gate.v1"

OPERATOR_TRUTH_FILES = (
    "SCOPE.md",
    "OOS_PASTED.md",
    "SEVERITY.md",
    "SEVERITY_CAPS.md",
    "RUBRIC_COVERAGE.md",
    "scope.json",
    "targets.tsv",
)

LEDGER_REL = ".auditooor/commit_lifecycle_ledger.json"
WAIVER_REL = ".auditooor/source_first_waivers.json"
DEFAULT_JSON = ".auditooor/v3_source_first_prereq_gate.json"
DEFAULT_MD = ".auditooor/v3_source_first_prereq_gate.md"

PIN_RE = re.compile(r"^[0-9a-fA-F]{40}$")
GITHUB_OWNER_REPO_RE = re.compile(
    r"(?i)(?:^|github\.com[:/])([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?(?:[#/?@].*)?$"
)
WAIVER_TYPES = {"github_pin_waiver", "source_first_pin_waiver"}
PLACEHOLDER_MARKERS = (
    "<operator edit>",
    "copy from bounty platform",
    "do not rely on memory",
    "no oos bullets parsed",
    "no severity caps parsed",
    "paste the bounty",
    "placeholder",
    "tbd",
    "todo",
)
MIN_TRUTH_BYTES = 24
LOCAL_TARGET_PREFIXES = {
    ".",
    "..",
    "audit",
    "app",
    "apps",
    "contracts",
    "contracts-v2",
    "crates",
    "external",
    "lib",
    "module",
    "modules",
    "packages",
    "pallet",
    "pallets",
    "protocol",
    "runtime",
    "src",
    "vendor",
}


@dataclass
class TargetRow:
    source: str
    raw_target: str
    repo: str
    is_github: bool
    pin: str
    language: str = ""
    local_name: str = ""
    waived: bool = False
    waiver_id: str = ""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _is_40hex(value: Any) -> bool:
    return isinstance(value, str) and bool(PIN_RE.fullmatch(value.strip()))


def _first_40hex(*values: Any) -> str:
    for value in values:
        if value is None:
            continue
        direct = str(value).strip()
        if _is_40hex(direct):
            return direct.lower()
    return ""


def _normalize_repo(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if not text:
        return ""
    if "@" in text and not text.startswith("git@"):
        maybe_repo, maybe_ref = text.rsplit("@", 1)
        if maybe_ref.strip():
            text = maybe_repo
    text = text.removeprefix("git+")
    if text.startswith("git@github.com:"):
        text = "github.com/" + text.split(":", 1)[1]
    parsed = urlparse(text)
    if parsed.netloc:
        host = parsed.netloc.lower()
        path = parsed.path.strip("/")
        if host == "github.com" and path:
            parts = path.split("/")
            if len(parts) >= 2:
                return f"{parts[0]}/{parts[1].removesuffix('.git')}".lower()
    match = GITHUB_OWNER_REPO_RE.search(text)
    if match:
        return match.group(1).removesuffix(".git").lower()
    parts = text.strip("/").split("/")
    if len(parts) == 2 and all(parts):
        return f"{parts[0]}/{parts[1].removesuffix('.git')}".lower()
    return ""


def _target_display_repo(value: str) -> str:
    repo = _normalize_repo(value)
    if repo:
        return repo
    text = value.strip()
    if text.startswith("git@github.com:"):
        text = text.split(":", 1)[1]
    elif "github.com/" in text:
        text = text.split("github.com/", 1)[1]
    text = text.split("?", 1)[0].split("#", 1)[0].strip("/")
    parts = text.split("/")
    if len(parts) >= 2 and parts[0] and parts[1]:
        return f"{parts[0]}/{parts[1].removesuffix('.git')}".lower()
    return ""


def _is_github(value: Any, pin: str = "") -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip().lower()
    if "github.com" in text or text.startswith("git@github.com:"):
        return True
    if text.startswith(("/", "./", "../")):
        return False
    parts = text.strip("/").split("/")
    if len(parts) != 2 or parts[0] in LOCAL_TARGET_PREFIXES:
        return False
    return bool(_normalize_repo(text))


def _split_inline_pin(value: str) -> tuple[str, str]:
    if "@" not in value or value.startswith("git@"):
        return value, ""
    repo, ref = value.rsplit("@", 1)
    if ref.strip():
        return repo, ref.strip().lower()
    return value, ""


def _read_json(path: Path) -> tuple[Any, str]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), ""
    except FileNotFoundError:
        return None, "missing"
    except json.JSONDecodeError as exc:
        return None, f"invalid json: {exc}"
    except OSError as exc:
        return None, f"read error: {exc}"


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _looks_placeholder(text: str) -> bool:
    stripped = text.strip()
    if len(stripped) < MIN_TRUTH_BYTES:
        return True
    lowered = stripped.lower()
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def _looks_placeholder_value(text: str) -> bool:
    lowered = text.strip().lower()
    return not lowered or any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def _truth_file_state(workspace: Path, rel: str) -> dict[str, Any]:
    path = workspace / rel
    present = path.is_file()
    text = _read_text(path) if present else ""
    placeholder = present and _looks_placeholder(text)
    populated = present and bool(text.strip()) and not placeholder
    return {
        "path": rel,
        "present": present,
        "bytes": path.stat().st_size if present else 0,
        "placeholder": placeholder,
        "populated": populated,
    }


def _scope_global_pin(data: dict[str, Any]) -> str:
    raw_values = (
        data.get("audit_pin_sha"),
        data.get("pin"),
        data.get("commit"),
        data.get("sha"),
        data.get("ref"),
    )
    return _first_40hex(*raw_values) or next(
        (str(value).strip() for value in raw_values if isinstance(value, str) and value.strip()),
        "",
    )


def _scope_target_value(entry: dict[str, Any]) -> str:
    for key in (
        "repo_url",
        "github_url",
        "url",
        "repo",
        "target_repo",
        "owner_repo",
        "target",
        "name",
    ):
        value = entry.get(key)
        if isinstance(value, str) and value.strip() and not _looks_placeholder_value(value):
            return value.strip()
    return ""


def _scope_target_pin(entry: dict[str, Any], global_pin: str) -> str:
    raw_values = (
        entry.get("audit_pin_sha"),
        entry.get("pin"),
        entry.get("commit"),
        entry.get("sha"),
        entry.get("ref"),
        entry.get("pinned_commit"),
        entry.get("commit_sha"),
    )
    return _first_40hex(*raw_values) or next(
        (str(value).strip() for value in raw_values if isinstance(value, str) and value.strip()),
        "",
    ) or global_pin


def load_scope_targets(workspace: Path) -> tuple[list[TargetRow], list[str]]:
    path = workspace / "scope.json"
    data, error = _read_json(path)
    if error:
        return [], [f"scope.json {error}"]
    if not isinstance(data, dict):
        return [], ["scope.json must be a JSON object"]

    rows: list[TargetRow] = []
    warnings: list[str] = []
    global_pin = _scope_global_pin(data)

    list_keys = ("target_repos", "targets", "repositories", "repos", "github_targets")
    for key in list_keys:
        value = data.get(key)
        if not isinstance(value, list):
            continue
        for idx, entry in enumerate(value):
            source = f"scope.json:{key}[{idx}]"
            if isinstance(entry, str):
                raw, inline_pin = _split_inline_pin(entry.strip())
                pin = inline_pin or global_pin
                rows.append(
                    TargetRow(
                        source=source,
                        raw_target=raw,
                        repo=_target_display_repo(raw),
                        is_github=_is_github(raw, pin),
                        pin=pin.lower() if pin else "",
                    )
                )
            elif isinstance(entry, dict):
                raw = _scope_target_value(entry)
                if not raw:
                    warnings.append(f"{source} has no repo/url/target field")
                    continue
                pin = _scope_target_pin(entry, global_pin).lower()
                rows.append(
                    TargetRow(
                        source=source,
                        raw_target=raw,
                        repo=_target_display_repo(raw),
                        is_github=_is_github(raw, pin),
                        pin=pin,
                        language=str(entry.get("language") or entry.get("lang") or "").strip().lower(),
                        local_name=str(entry.get("local_name") or entry.get("name") or ""),
                    )
                )

    raw_single = _scope_target_value(data)
    if raw_single and not rows:
        pin = _scope_target_pin(data, global_pin).lower()
        rows.append(
            TargetRow(
                source="scope.json",
                raw_target=raw_single,
                repo=_target_display_repo(raw_single),
                is_github=_is_github(raw_single, pin),
                pin=pin,
                language=str(data.get("language") or data.get("lang") or "").strip().lower(),
            )
        )
    return rows, warnings


def load_targets_tsv(workspace: Path) -> tuple[list[TargetRow], list[str]]:
    path = workspace / "targets.tsv"
    rows: list[TargetRow] = []
    warnings: list[str] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except FileNotFoundError:
        return [], []
    except OSError as exc:
        return [], [f"targets.tsv read error: {exc}"]

    for line_no, line in enumerate(lines, start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = next(csv.reader([line], delimiter="\t"))
        parts = [part.strip() for part in parts]
        raw = parts[0] if parts else ""
        if not raw:
            continue
        ref = parts[1] if len(parts) > 1 else ""
        local_name = parts[2] if len(parts) > 2 else ""
        inline_raw, inline_pin = _split_inline_pin(raw)
        pin = inline_pin or (ref.strip() if ref else "")
        rows.append(
            TargetRow(
                source=f"targets.tsv:{line_no}",
                raw_target=inline_raw,
                repo=_target_display_repo(inline_raw),
                is_github=_is_github(inline_raw, pin),
                pin=pin.lower(),
                language=parts[3].lower() if len(parts) > 3 else "",
                local_name=local_name,
            )
        )
    return rows, warnings


def _load_waivers(workspace: Path) -> tuple[list[dict[str, Any]], list[str]]:
    path = workspace / WAIVER_REL
    if not path.exists():
        return [], []
    data, error = _read_json(path)
    if error:
        return [], [f"{WAIVER_REL} {error}"]
    if isinstance(data, list):
        entries = data
    elif isinstance(data, dict):
        entries = data.get("waivers", [])
    else:
        return [], [f"{WAIVER_REL} must be an object or list"]
    waivers: list[dict[str, Any]] = []
    warnings: list[str] = []
    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            warnings.append(f"{WAIVER_REL}:waivers[{idx}] is not an object")
            continue
        waiver_type = str(entry.get("type") or entry.get("waiver_type") or "")
        if waiver_type not in WAIVER_TYPES:
            warnings.append(f"{WAIVER_REL}:waivers[{idx}] has unsupported type {waiver_type!r}")
            continue
        if entry.get("active") is False:
            continue
        reason = str(entry.get("reason") or entry.get("justification") or "").strip()
        has_target = any(
            isinstance(entry.get(key), str) and entry.get(key, "").strip()
            for key in ("repo", "target", "repo_url", "github", "owner_repo")
        )
        if not reason or not has_target:
            warnings.append(
                f"{WAIVER_REL}:waivers[{idx}] missing required reason or target binding"
            )
            continue
        waivers.append(entry)
    return waivers, warnings


def _waiver_matches(row: TargetRow, waiver: dict[str, Any]) -> bool:
    fields = (
        waiver.get("repo"),
        waiver.get("target"),
        waiver.get("repo_url"),
        waiver.get("github"),
        waiver.get("owner_repo"),
    )
    waiver_repos = {_normalize_repo(value) for value in fields if isinstance(value, str)}
    waiver_raw = {str(value).strip() for value in fields if isinstance(value, str)}
    if row.repo and row.repo in waiver_repos:
        return True
    return bool(row.raw_target and row.raw_target in waiver_raw)


def apply_pin_waivers(rows: list[TargetRow], workspace: Path) -> tuple[list[TargetRow], list[str]]:
    waivers, warnings = _load_waivers(workspace)
    for row in rows:
        if not row.is_github or (row.pin and _is_40hex(row.pin)):
            continue
        for idx, waiver in enumerate(waivers):
            if _waiver_matches(row, waiver):
                row.waived = True
                row.waiver_id = str(waiver.get("id") or f"waiver[{idx}]")
                break
    return rows, warnings


def _status_is_bad(row: dict[str, Any]) -> bool:
    if row.get("dry_run") is True or row.get("failed") is True:
        return True
    if row.get("success") is False or row.get("ok") is False:
        return True
    for key in ("status", "state", "result", "outcome"):
        value = row.get(key)
        if isinstance(value, str):
            lower = re.sub(r"[\s-]+", "_", value.strip().lower())
            if lower in {"dry_run", "failed", "fail", "error", "blocked", "not_run", "missing"}:
                return True
    return False


def _report_path(workspace: Path, row: dict[str, Any]) -> Path | None:
    raw = str(row.get("output_path") or row.get("report_path") or row.get("path") or "").strip()
    if not raw:
        return None
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = workspace / path
    return path


def _int_value(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _has_commit_window_evidence(report: dict[str, Any]) -> bool:
    for key in ("commits", "shaped_commits", "shaped_commits_index", "candidate_findings", "commit_rows", "rows"):
        value = report.get(key)
        if isinstance(value, list):
            if not value:
                continue
            for item in value:
                if not isinstance(item, dict):
                    continue
                sha = str(item.get("sha") or item.get("commit") or item.get("commit_sha") or "").strip()
                url = str(item.get("url") or item.get("commit_url") or "").strip()
                subject = str(item.get("subject") or item.get("summary") or item.get("message") or "").strip()
                if re.fullmatch(r"[0-9a-fA-F]{7,40}", sha) and (
                    subject or "github.com/" in url
                ):
                    return True
            continue
    for key in ("window_newest_sha", "window_oldest_sha", "window_oldest_sha_60", "head_sha", "head_main_at_l24"):
        value = str(report.get(key) or "").strip()
        if PIN_RE.fullmatch(value):
            return True
    return _has_canonical_empty_window_evidence(report)


def _has_canonical_empty_window_evidence(report: dict[str, Any]) -> bool:
    schema_ok = report.get("schema") in {
        "auditooor.git_commits_mining.v1",
        "auditooor.git_commits_mining.v1.2-solidity",
    }
    if not schema_ok:
        return False
    if not str(report.get("upstream_repo") or "").strip():
        return False
    if not str(report.get("audit_pin_sha") or "").strip():
        return False
    if not str(report.get("generated_at") or report.get("generated_at_utc") or "").strip():
        return False
    if not str(report.get("since_date") or report.get("window") or report.get("direction") or "").strip():
        return False
    if not isinstance(report.get("commits"), list) or not isinstance(report.get("shaped_commits_index"), list):
        return False
    if not isinstance(report.get("fallback_used"), bool):
        return False
    if not isinstance(report.get("security_fix_count"), int):
        return False
    try:
        return int(report.get("commits_scanned", -1)) >= 0
    except (TypeError, ValueError):
        return False


def _has_legacy_commit_window_evidence(report: dict[str, Any]) -> bool:
    for key in (
        "commits",
        "shaped_commits",
        "shaped_commits_index",
        "candidate_findings",
        "commit_rows",
        "rows",
    ):
        value = report.get(key)
        if isinstance(value, list) and value:
            return True
    for key in (
        "window_newest_sha",
        "window_oldest_sha",
        "window_oldest_sha_60",
        "head_sha",
        "head_main_at_l24",
    ):
        if isinstance(report.get(key), str) and report[key].strip():
            return True
    if _int_value(report.get("commits_scanned_in_window")) > 0:
        return True
    if _int_value(report.get("commits_scanned_extended_window")) > 0:
        return True
    return False


def _report_scan_count(report: dict[str, Any]) -> int:
    return max(
        _int_value(report.get("commits_scanned")),
        _int_value(report.get("commits_scanned_in_window")),
        _int_value(report.get("commits_scanned_extended_window")),
    )


def _ledger_row_has_mining_evidence(workspace: Path, row: dict[str, Any], target: TargetRow) -> tuple[bool, list[str], dict[str, Any]]:
    blockers: list[str] = []
    report_path = _report_path(workspace, row)
    detail = {
        "repo": target.repo,
        "pin": target.pin,
        "status": row.get("status") or row.get("state") or row.get("result") or row.get("outcome") or "",
        "output_path": str(report_path) if report_path else "",
        "commits_scanned": _int_value(row.get("commits_scanned")),
    }
    if not report_path or not report_path.is_file():
        blockers.append(f"{LEDGER_REL} report missing for {target.repo}@{target.pin}")
        return False, blockers, detail
    report, error = _read_json(report_path)
    if error or not isinstance(report, dict):
        blockers.append(f"{LEDGER_REL} report unreadable for {target.repo}@{target.pin}")
        return False, blockers, detail
    if report.get("schema") not in {
        "auditooor.git_commits_mining.v1",
        "auditooor.git_commits_mining.v1.2-solidity",
    }:
        blockers.append(f"{LEDGER_REL} report schema missing for {target.repo}@{target.pin}")
    if not str(report.get("generated_at") or report.get("generated_at_utc") or "").strip():
        blockers.append(f"{LEDGER_REL} report timestamp missing for {target.repo}@{target.pin}")
    upstream_repo = _target_display_repo(str(report.get("upstream_repo") or ""))
    if not upstream_repo:
        blockers.append(f"{LEDGER_REL} report upstream repo missing for {target.repo}@{target.pin}")
    elif upstream_repo != target.repo:
        blockers.append(f"{LEDGER_REL} report upstream repo mismatch for {target.repo}@{target.pin}")
    report_pin = _first_40hex(report.get("audit_pin_sha"))
    if not report_pin or report_pin.lower() != target.pin.lower():
        blockers.append(f"{LEDGER_REL} report pin mismatch for {target.repo}@{target.pin}")
    commits_scanned = _report_scan_count(report)
    detail["commits_scanned"] = commits_scanned
    detail["report_generated_at"] = str(report.get("generated_at") or "")
    if commits_scanned <= 0 and not _has_canonical_empty_window_evidence(report):
        blockers.append(f"{LEDGER_REL} report has no commit evidence for {target.repo}@{target.pin}")
    if not _has_commit_window_evidence(report):
        blockers.append(f"{LEDGER_REL} report lacks commit/window evidence for {target.repo}@{target.pin}")
    return not blockers, blockers, detail


def _row_repo(row: dict[str, Any]) -> str:
    for key in ("repo", "target_repo", "owner_repo", "repo_url", "target", "github"):
        repo = _normalize_repo(row.get(key))
        if repo:
            return repo
    return ""


def _row_pin(row: dict[str, Any]) -> str:
    return _first_40hex(
        row.get("pin"),
        row.get("audit_pin_sha"),
        row.get("commit"),
        row.get("sha"),
        row.get("commit_sha"),
        row.get("ref"),
    )


def _ledger_rows(ledger: dict[str, Any], key: str) -> list[dict[str, Any]]:
    rows = ledger.get(key)
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict)]


def _post_ledger_checks(workspace: Path, pinned_targets: list[TargetRow]) -> tuple[list[str], dict[str, Any]]:
    blockers: list[str] = []
    ledger_path = workspace / LEDGER_REL
    ledger, error = _read_json(ledger_path)
    detail: dict[str, Any] = {
        "path": LEDGER_REL,
        "present": ledger_path.is_file(),
        "target_rows_count": 0,
        "matched_targets": [],
        "bad_rows": [],
    }
    if error:
        blockers.append(f"{LEDGER_REL} {error}")
        return blockers, detail
    if not isinstance(ledger, dict):
        blockers.append(f"{LEDGER_REL} must be a JSON object")
        return blockers, detail

    target_rows = _ledger_rows(ledger, "target_rows")
    all_rows = target_rows + _ledger_rows(ledger, "rows")
    detail["target_rows_count"] = len(target_rows)
    if not target_rows and pinned_targets:
        blockers.append(f"{LEDGER_REL} has no target_rows")

    bad_rows: list[dict[str, Any]] = []
    for idx, row in enumerate(all_rows):
        if _status_is_bad(row):
            bad_rows.append(
                {
                    "index": idx,
                    "repo": _row_repo(row),
                    "pin": _row_pin(row),
                    "status": row.get("status") or row.get("state") or row.get("result") or row.get("outcome") or "",
                    "dry_run": row.get("dry_run") is True,
                    "failed": row.get("failed") is True,
                }
            )
    if bad_rows:
        detail["bad_rows"] = bad_rows
        blockers.append(f"{LEDGER_REL} contains failed or dry-run rows")

    for target in pinned_targets:
        same_repo_pin = [
            row
            for row in target_rows
            if (_row_repo(row), _row_pin(row).lower()) == (target.repo, target.pin.lower())
        ]
        if target.language:
            matches = [
                row
                for row in same_repo_pin
                if not str(row.get("language") or "").strip()
                or str(row.get("language") or "").strip().lower() == target.language
            ]
        else:
            matches = same_repo_pin
        if not matches:
            if same_repo_pin:
                blockers.append(
                    f"{LEDGER_REL} language mismatch for {target.repo}@{target.pin}"
                )
                continue
            blockers.append(
                f"{LEDGER_REL} missing target_rows match for {target.repo}@{target.pin}"
            )
            continue
        ok = False
        for row in matches:
            row_ok, row_blockers, row_detail = _ledger_row_has_mining_evidence(workspace, row, target)
            detail["matched_targets"].append(row_detail)
            blockers.extend(row_blockers)
            ok = ok or row_ok
        if not ok:
            blockers.append(f"{LEDGER_REL} has no usable mining evidence for {target.repo}@{target.pin}")
    return blockers, detail


def run_gate(workspace: Path, phase: str, strict: bool = False) -> dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    blockers: list[str] = []
    warnings: list[str] = []

    if not workspace.is_dir():
        blockers.append(f"workspace does not exist or is not a directory: {workspace}")
        return {
            "schema": SCHEMA,
            "generated_at_utc": _utc_now(),
            "workspace": str(workspace),
            "phase": phase,
            "strict": strict,
            "status": "fail",
            "blockers": blockers,
            "warnings": warnings,
            "required_files": [],
            "github_targets": [],
            "post_ledger": {},
        }

    required_files = []
    for rel in OPERATOR_TRUTH_FILES:
        state = _truth_file_state(workspace, rel)
        required_files.append(state)
        if not state["present"]:
            blockers.append(f"missing required file: {rel}")
        elif rel.endswith(".md") and not state["populated"]:
            blockers.append(f"operator truth file is empty or placeholder: {rel}")

    scope_rows, scope_warnings = load_scope_targets(workspace)
    tsv_rows, tsv_warnings = load_targets_tsv(workspace)
    scope_errors = [
        item for item in scope_warnings if item.startswith("scope.json ")
        or item.startswith("scope.json must")
    ]
    blockers.extend(scope_errors)
    warnings.extend(item for item in scope_warnings if item not in scope_errors)
    warnings.extend(tsv_warnings)

    all_rows = scope_rows + tsv_rows
    if not all_rows:
        blockers.append("no source targets parsed from scope.json or targets.tsv")
    all_rows, waiver_warnings = apply_pin_waivers(all_rows, workspace)
    warnings.extend(waiver_warnings)
    github_rows = [row for row in all_rows if row.is_github]

    for row in github_rows:
        if not row.pin and not row.waived:
            label = row.repo or row.raw_target
            blockers.append(f"unpinned GitHub target: {label} ({row.source})")
        elif row.pin and not _is_40hex(row.pin) and not row.waived:
            label = row.repo or row.raw_target
            blockers.append(f"GitHub target pin is not a 40-hex commit: {label}@{row.pin} ({row.source})")

    pinned_by_repo: dict[tuple[str, str], TargetRow] = {}
    for row in github_rows:
        if row.pin and _is_40hex(row.pin) and row.repo:
            pinned_by_repo[(row.repo, row.pin.lower())] = row

    post_ledger: dict[str, Any] = {}
    if phase == "post":
        post_blockers, post_ledger = _post_ledger_checks(
            workspace, list(pinned_by_repo.values())
        )
        blockers.extend(post_blockers)

    return {
        "schema": SCHEMA,
        "generated_at_utc": _utc_now(),
        "workspace": str(workspace),
        "phase": phase,
        "strict": strict,
        "status": "fail" if blockers else "pass",
        "blockers": blockers,
        "warnings": warnings,
        "required_files": required_files,
        "github_targets": [asdict(row) for row in github_rows],
        "post_ledger": post_ledger,
        "proof_boundary": (
            "This gate verifies source-first prerequisites only; it does not prove "
            "exploitability, impact, originality, or submission readiness."
        ),
    }


def render_markdown(payload: dict[str, Any]) -> str:
    status = str(payload.get("status", "")).upper()
    lines = [
        "# V3 Source-First Prereq Gate",
        "",
        f"- Schema: `{payload.get('schema')}`",
        f"- Workspace: `{payload.get('workspace')}`",
        f"- Phase: `{payload.get('phase')}`",
        f"- Strict: `{payload.get('strict')}`",
        f"- Status: **{status}**",
        "",
        "## Blockers",
    ]
    blockers = payload.get("blockers") or []
    if blockers:
        lines.extend(f"- {item}" for item in blockers)
    else:
        lines.append("- none")
    lines.extend(["", "## GitHub Targets"])
    targets = payload.get("github_targets") or []
    if targets:
        for target in targets:
            pin = target.get("pin") or "missing"
            waiver = f" waived={target.get('waiver_id')}" if target.get("waived") else ""
            lines.append(
                f"- `{target.get('repo') or target.get('raw_target')}` pin=`{pin}` source=`{target.get('source')}`{waiver}"
            )
    else:
        lines.append("- none")
    warnings = payload.get("warnings") or []
    if warnings:
        lines.extend(["", "## Warnings"])
        lines.extend(f"- {item}" for item in warnings)
    lines.append("")
    return "\n".join(lines)


def _default_out(workspace: Path, rel: str) -> Path:
    return workspace.expanduser().resolve() / rel


def write_sidecars(payload: dict[str, Any], out_json: Path, out_md: Path) -> None:
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(payload), encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--phase", choices=("pre", "post"), default="pre")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--print-json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    payload = run_gate(args.workspace, phase=args.phase, strict=args.strict)
    workspace = args.workspace.expanduser().resolve()
    out_json = args.out_json or _default_out(workspace, DEFAULT_JSON)
    out_md = args.out_md or _default_out(workspace, DEFAULT_MD)

    if workspace.is_dir() or args.out_json or args.out_md:
        write_sidecars(payload, out_json, out_md)

    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(
            "[v3-source-first-prereq-gate] "
            f"phase={payload['phase']} status={payload['status']} "
            f"blockers={len(payload['blockers'])} out={out_json}"
        )

    if args.strict and payload["blockers"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
