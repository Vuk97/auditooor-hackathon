#!/usr/bin/env python3
"""Fail closed on incomplete V3 source-mined exploit rows.

This gate is deliberately row-level. The roadmap/static gates can say that the
tooling exists, while a real audit still leaves the strongest source-mined
candidates stranded in notes or manifests. This script reads the source-mined
exploit queue plus local judgment/proof artifacts and reports whether each
surviving row has the minimum contract needed before more PoC work:

- source artifacts are complete;
- one exact local proof command is present and safe enough to run locally;
- impact contract facts are locked or mapped;
- OOS traps and negative controls are explicit;
- High/Critical rows have a clean candidate-judgment packet; and
- harness execution state is either runnable or explicitly blocked with inputs.

It is advisory without --strict and exits non-zero with --strict when blockers
exist.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shlex
import sys
from collections import Counter
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.v3_source_first_row_gate.v1"
HIGH_PLUS = {"high", "critical"}
MEDIUM_PLUS = {"medium", "high", "critical"}
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
FILEABLE_MIN_RANK = 2

# HACKERMAN_V3 opposed-trace proof gate (proof-side).
#
# A HIGH+ Direct-loss / freeze / theft row cannot pass the row gate while its
# impact contract carries an unopposed trace - no enumerated protocol-owned
# defenses, or an opposed_trace_coverage that is not ``covered``, or negative
# controls that lack both a "defender wins" and a "defender absent" variant.
# Empirical anchor: Spark LEAD1 - the chain-watcher bug was real but the proof
# omitted the lower-timelock refund / watchtower defenses, so Direct Loss was
# unproven (attacker-vs-empty-world).
HIGH_PLUS_IMPACT_KEYWORDS = (
    "direct loss",
    "loss of funds",
    "loss of user funds",
    "permanent freeze",
    "permanent freezing",
    "freezing of funds",
    "frozen funds",
    "insolvency",
    "insolvent",
    "undercollateral",
    "bad debt",
    "theft",
    "steal",
    "stolen",
    "drain",
    "drained",
    "unauthorized withdrawal",
    "unauthorized withdraw",
    "unauthorised withdrawal",
    "unauthorized transfer",
)
# A "defender wins" negative-control variant proves the protocol defense, when
# present, neutralizes the attacker. A "defender absent" variant isolates the
# bug. The proof needs both so the opposed trace is not a one-sided narrative.
DEFENDER_WINS_TOKENS = (
    "defender wins",
    "defense wins",
    "defence wins",
    "defender succeeds",
    "defense succeeds",
    "guard wins",
    "defender catches",
    "defense catches",
    "defender neutralizes",
    "defender neutralises",
    "watchtower catches",
    "refund succeeds",
    "challenge succeeds",
    "race won by protocol",
)
DEFENDER_ABSENT_TOKENS = (
    "defender absent",
    "defense absent",
    "defence absent",
    "defender disabled",
    "defense disabled",
    "guard absent",
    "guard disabled",
    "without the defense",
    "without the defender",
    "no defender",
    "defense removed",
    "defender removed",
    "vulnerable precondition removed",
)

TERMINAL_STATES = {
    "killed",
    "disproved",
    "false_positive",
    "not_candidate",
    "not_a_bug",
    "duplicate",
    "oos",
    "out_of_scope",
    "rejected",
    "terminal",
    "terminal_no_submission",
    "negative",
}
ADVISORY_STATES = {
    "advisory",
    "advisory_only",
    "source_read_only",
    "metadata_overlap_only_unproven",
}
IMPACT_READY_STATES = {
    "complete",
    "completed",
    "locked",
    "mapped",
    "pass",
    "ready",
    "ready_for_poc",
    "ready_for_proof",
    "linked",
    "not_required",
}
HARNESS_READY_STATES = {
    "ready_executable_binding",
    "ready",
    "runnable",
    "executed",
    "passed",
    "proved",
}
HARNESS_BLOCKED_STATES = {
    "blocked_missing_inputs",
    "blocked_vague_plan",
    "blocked_disallowed_command",
    "blocked_harness",
}
LOCAL_EXECUTABLES = {
    "bash",
    "cargo",
    "forge",
    "go",
    "make",
    "python",
    "python3",
    "pytest",
    "rg",
    "sh",
    "zsh",
}
NETWORK_TOKENS = (
    "curl ",
    "wget ",
    "git clone",
    "gh ",
    "http://",
    "https://",
)
VAGUE_COMMAND_TOKENS = (
    " tbd",
    " todo",
    " needs_human",
    "review ",
    "inspect ",
    "manual",
    "should ",
    "must ",
)
MISSING_VALUES = {
    "",
    "<operator edit>",
    "<todo>",
    "n/a",
    "na",
    "missing",
    "none",
    "not_assessed",
    "null",
    "operator edit",
    "placeholder",
    "tbd",
    "todo",
    "unknown",
}
PLACEHOLDER_MARKERS = (
    "<operator edit>",
    "copy from bounty platform",
    "manual fill required",
    "placeholder",
    "tbd",
    "todo",
)
PIN_40_HEX_RE = re.compile(r"^[0-9a-fA-F]{40}$")
FILE_LINE_RE = re.compile(r"[A-Za-z0-9_./\\-]+\.[A-Za-z]{1,8}:\d+")
REACHABILITY_POSITIVE_RE = re.compile(
    r"reachability[_\s]+trace|"
    r"dispatched (?:via|from|at|in)\s+\S|"
    r"registered (?:at|in|via)\s+\S|"
    r"handler (?:registered|installed|wired)\s+at\s+\S|"
    r"called from (?:genesis|production|default)[^\n]{0,80}|"
    r"activated (?:at|from|by) genesis[^\n]{0,80}|"
    r"reachable (?:from|in|under)[^\n]{0,60}|"
    r"dispatch\s+site\s*:\s*\S|"
    r"entrypoint\s*:\s*\S|"
    r"call[_ ]?site\s*:\s*\S",
    re.IGNORECASE,
)
REACHABILITY_UNREACHABLE_RE = re.compile(
    r"(?:overridden|overwritten|replaced|superseded|dead code|unreachable|"
    r"not (?:dispatched|registered|activated|reached|called|used) in production|"
    r"disabled (?:in|by|at|from) (?:production|genesis|default|Berlin|London|Shanghai|Cancun|Prague)|"
    r"never (?:called|reached|dispatched|activated) (?:in|under|from) (?:production|default|genesis)|"
    r"(?:Berlin|London|Shanghai|Cancun|Prague|EIP-?2929|enable\w+) (?:overrides?|replaces?|overwrites?|supersedes?)|"
    r"fork (?:override|overrides|disables?|replaces?)\b|"
    r"feature (?:flag|gate) (?:off|disabled|not enabled)\b|"
    r"(?:not|never) (?:active|enabled|in effect) (?:in|under|from) (?:production|default|genesis)|"
    r"only (?:active|enabled|used|dispatched) (?:in|under|for)\s+\S+\s+(?:mode|fork|chain|config)|"
    r"legacy[- _](?:code|path|handler|fn)[^\n]{0,60}(?:not|never)[^\n]{0,60}(?:active|used|called|dispatched)|"
    r"code[- _]present[^\n]{0,60}(?:unreachable|not dispatched|overridden)|"
    r"present (?:but|yet|however) (?:not|never) (?:called|dispatched|activated|reached))",
    re.IGNORECASE,
)
REACHABILITY_TRACE_FIELDS = (
    "reachability_trace",
    "production_reachability",
    "reachability",
    "reachable_from",
    "dispatch_site",
    "registration_site",
    "entrypoint",
    "entry_point",
    "production_entrypoint",
    "call_site",
    "callsite",
)
REACHABILITY_SITE_FIELDS = (
    "dispatch_site",
    "registration_site",
    "entrypoint",
    "entry_point",
    "production_entrypoint",
    "call_site",
    "callsite",
    "reachable_from",
)
REACHABILITY_REF_FIELDS = (
    "source_refs",
    "evidence_refs",
    "source_citations",
    "reachability_refs",
    "reachability_citations",
)
REACHABILITY_EXPLICIT_REF_FIELDS = (
    "reachability_refs",
    "reachability_citations",
)
REACHABILITY_REBUTTAL_FIELDS = (
    "reachability_rebuttal",
    "reachability_bounded_rebuttal",
    "reachability_exception",
)
REACHABILITY_REBUTTAL_REASON_RE = re.compile(
    r"\b(?:source-backed exception|bounded exception|typed exception|"
    r"not (?:reachable|dispatchable|dispatched|registered|activated|called) in production|"
    r"dispatch (?:not required|blocked|disabled)|"
    r"registration (?:not required|blocked|disabled)|"
    r"feature (?:flag|gate) disabled|test[- ]only|constructor[- ]only|dead code)\b",
    re.IGNORECASE,
)
REACHABILITY_REBUTTAL_PLACEHOLDER_RE = re.compile(
    r"\b(?:manual review|pending|placeholder|operator edit|needs review|not assessed|tbd|todo|unknown|n/a)\b",
    re.IGNORECASE,
)
GITHUB_OWNER_REPO_RE = re.compile(
    r"(?i)(?:^|github\.com[:/])([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?(?:[#/?@].*)?$"
)
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


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _norm(value: Any, *, limit: int = 500) -> str:
    if isinstance(value, (list, tuple, set)):
        value = "; ".join(_norm(v, limit=limit) for v in value if _norm(v, limit=limit))
    elif isinstance(value, dict):
        value = json.dumps(value, sort_keys=True)
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text[:limit]


def _is_present(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, (list, tuple, set)):
        return any(_is_present(item) for item in value)
    if isinstance(value, dict):
        return bool(value)
    text = _norm(value).lower()
    if not text or text in MISSING_VALUES:
        return False
    return not any(marker in text for marker in PLACEHOLDER_MARKERS)


def _first(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if _is_present(value):
            return _norm(value)
    return ""


def _candidate_id(row: dict[str, Any]) -> str:
    return _first(row, "lead_id", "candidate_id", "row_id", "id", "title") or "candidate"


def _title(row: dict[str, Any]) -> str:
    return _first(row, "title", "root_cause_hypothesis", "attack_class") or _candidate_id(row)


def _severity(row: dict[str, Any]) -> str:
    raw = _first(row, "likely_severity", "claimed_severity", "severity", "severity_tier").lower()
    for severity in ("critical", "high", "medium", "low", "info"):
        if severity in raw:
            return severity
    return "unknown"


def _severity_rank(row: dict[str, Any]) -> int:
    return SEVERITY_RANK.get(_severity(row), 0)


def _stable_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", _norm(value).lower())


def _repo_url_to_owner_repo(repo_url: str) -> str:
    value = repo_url.strip()
    if "@" in value and not value.startswith("git@"):
        maybe_repo, maybe_ref = value.rsplit("@", 1)
        if maybe_ref.strip():
            value = maybe_repo
    value = value.removesuffix(".git")
    if value.startswith("git@github.com:"):
        value = value.split(":", 1)[1]
    elif "github.com/" in value:
        value = value.split("github.com/", 1)[1]
    else:
        match = GITHUB_OWNER_REPO_RE.search(value)
        if match:
            value = match.group(1)
        else:
            parts = value.strip("/").split("/")
            if len(parts) == 2 and all(parts) and parts[0].lower() not in LOCAL_TARGET_PREFIXES:
                value = f"{parts[0]}/{parts[1]}"
            else:
                raise ValueError(f"not a GitHub owner/repo URL: {repo_url!r}")
    value = value.split("?", 1)[0].split("#", 1)[0].strip("/")
    parts = value.split("/")
    if len(parts) < 2 or not parts[0] or not parts[1]:
        raise ValueError(f"not a GitHub owner/repo URL: {repo_url!r}")
    return f"{parts[0]}/{parts[1].removesuffix('.git')}"


def _first_40hex(*values: Any) -> str:
    for value in values:
        text = _norm(value, limit=120)
        if PIN_40_HEX_RE.fullmatch(text):
            return text.lower()
    return ""


def _scope_target_value(row: dict[str, Any]) -> str:
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
        value = row.get(key)
        if _is_present(value):
            return _norm(value, limit=500)
    return ""


def _scope_target_pin(row: dict[str, Any], global_pin: str) -> str:
    raw_values = (
        row.get("audit_pin_sha"),
        row.get("pin"),
        row.get("commit"),
        row.get("sha"),
        row.get("ref"),
        row.get("pinned_commit"),
        row.get("commit_sha"),
    )
    return _first_40hex(*raw_values) or next(
        (str(value).strip() for value in raw_values if isinstance(value, str) and value.strip()),
        "",
    ) or global_pin


def _split_inline_pin(value: str) -> tuple[str, str]:
    if "@" not in value or value.startswith("git@"):
        return value, ""
    repo, ref = value.rsplit("@", 1)
    if ref.strip():
        return repo, ref.strip().lower()
    return value, ""


def _is_github_target(raw: str, pin: str) -> bool:
    text = raw.strip().lower()
    if "github.com" in text or text.startswith("git@github.com:"):
        return True
    if text.startswith(("/", "./", "../")):
        return False
    parts = text.strip("/").split("/")
    return len(parts) == 2 and parts[0] not in LOCAL_TARGET_PREFIXES


def _target_from_scope_entry(entry: Any, source: str, global_pin: str = "") -> dict[str, str] | None:
    language = ""
    if isinstance(entry, str):
        raw, inline_pin = _split_inline_pin(entry.strip())
        pin = inline_pin or global_pin
    elif isinstance(entry, dict):
        raw = _scope_target_value(entry)
        pin = _scope_target_pin(entry, global_pin)
        language = _norm(entry.get("language") or entry.get("lang"), limit=40).lower()
    else:
        return None
    if not raw or not _is_github_target(raw, pin):
        return None
    try:
        owner_repo = _repo_url_to_owner_repo(raw)
    except ValueError:
        return None
    return {
        "repo_url": raw,
        "owner_repo": owner_repo,
        "pin": pin,
        "language": language,
        "source": source,
    }


def _load_pinned_github_targets(workspace: Path) -> list[dict[str, str]]:
    targets: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    def add_target(target: dict[str, str] | None) -> None:
        if not target:
            return
        key = (target["owner_repo"].lower(), target["pin"].lower(), target.get("language", ""))
        if key in seen:
            return
        seen.add(key)
        targets.append(target)

    scope_path = workspace / "scope.json"
    if scope_path.exists():
        try:
            payload = json.loads(scope_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            payload = {}
        if isinstance(payload, dict):
            global_pin = _scope_target_pin(payload, "")
            scope_target_count_before = len(targets)
            for key in ("target_repos", "targets", "repositories", "repos", "github_targets"):
                rows = payload.get(key)
                if isinstance(rows, list):
                    for idx, row in enumerate(rows):
                        add_target(_target_from_scope_entry(row, f"scope.json:{key}[{idx}]", global_pin))
            raw_single = _scope_target_value(payload)
            if raw_single and len(targets) == scope_target_count_before:
                add_target(_target_from_scope_entry(payload, "scope.json", global_pin))

    tsv_path = workspace / "targets.tsv"
    if tsv_path.exists():
        for raw in tsv_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            cols = [col.strip() for col in raw.split("\t")]
            raw_target, inline_pin = _split_inline_pin(cols[0])
            pin = inline_pin or (cols[1] if len(cols) >= 2 else "")
            if not _is_github_target(raw_target, pin):
                continue
            try:
                owner_repo = _repo_url_to_owner_repo(raw_target)
            except ValueError:
                continue
            add_target(
                {
                    "repo_url": raw_target,
                    "owner_repo": owner_repo,
                    "pin": pin,
                    "language": cols[3].lower() if len(cols) >= 4 and cols[3] else "",
                    "source": f"targets.tsv:{raw.splitlines()[0][:40]}",
                }
            )

    return targets


def _commit_report_path(workspace: Path, row: dict[str, Any]) -> Path | None:
    raw = _norm(row.get("output_path") or row.get("report_path") or row.get("path"), limit=1000)
    if not raw:
        return None
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = workspace / path
    return path


def _read_commit_report(workspace: Path, row: dict[str, Any]) -> tuple[Path | None, dict[str, Any] | None]:
    path = _commit_report_path(workspace, row)
    if path is None or not path.is_file():
        return path, None
    payload = _read_json(path)
    return path, payload if isinstance(payload, dict) else None


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
        if PIN_40_HEX_RE.fullmatch(value):
            return True
    return _has_canonical_empty_window_evidence(report)


def _has_canonical_empty_window_evidence(report: dict[str, Any]) -> bool:
    schema_ok = report.get("schema") in {
        "auditooor.git_commits_mining.v1",
        "auditooor.git_commits_mining.v1.2-solidity",
    }
    if not schema_ok:
        return False
    if not _is_present(report.get("upstream_repo")):
        return False
    if not _is_present(report.get("audit_pin_sha")):
        return False
    if not _is_present(report.get("generated_at") or report.get("generated_at_utc")):
        return False
    if not _is_present(report.get("since_date") or report.get("window") or report.get("direction")):
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
        value = report.get(key)
        if isinstance(value, str) and value.strip():
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


def _commit_mining_status(workspace: Path) -> tuple[dict[str, Any], list[str]]:
    ledger_path = workspace / ".auditooor" / "commit_lifecycle_ledger.json"
    targets = _load_pinned_github_targets(workspace)
    artifact: dict[str, Any] = {
        "path": str(ledger_path),
        "exists": ledger_path.is_file(),
        "pinned_github_targets": len(targets),
        "ledger_target_rows": 0,
        "matching_target_rows": 0,
        "invalid_pin_targets": [],
        "evidence_rows": [],
        "blockers": [],
    }
    blockers: list[str] = []

    if not targets:
        artifact["status"] = "advisory_no_pinned_github_targets"
        return artifact, []

    invalid_targets = [target for target in targets if not PIN_40_HEX_RE.fullmatch(target["pin"])]
    if invalid_targets:
        blockers.append("commit_mining_pin_mismatch")
        artifact["invalid_pin_targets"] = [
            {
                "owner_repo": target["owner_repo"],
                "pin": target["pin"][:80],
                "language": target.get("language", ""),
            }
            for target in invalid_targets[:20]
        ]

    ledger = _read_json(ledger_path) if ledger_path.is_file() else None
    if not isinstance(ledger, dict):
        blockers.append("commit_mining_missing")
        artifact["status"] = "fail"
        artifact["blockers"] = sorted(set(blockers))
        return artifact, artifact["blockers"]

    target_rows = ledger.get("target_rows")
    if not isinstance(target_rows, list):
        target_rows = []
    target_rows = [row for row in target_rows if isinstance(row, dict)]
    artifact["ledger_target_rows"] = len(target_rows)
    if not target_rows:
        blockers.append("commit_mining_missing")

    matched_rows: list[dict[str, Any]] = []
    valid_targets = [target for target in targets if PIN_40_HEX_RE.fullmatch(target["pin"])]
    for target in valid_targets:
        same_repo_rows = [
            row
            for row in target_rows
            if _norm(row.get("owner_repo")).lower() == target["owner_repo"].lower()
        ]
        same_pin_rows = [
            row
            for row in same_repo_rows
            if _norm(row.get("pin"), limit=120).lower() == target["pin"].lower()
        ]
        if target.get("language"):
            matching_rows = [
                row
                for row in same_pin_rows
                if not _is_present(row.get("language"))
                or _norm(row.get("language"), limit=40).lower() == target["language"]
            ]
        else:
            matching_rows = same_pin_rows

        if not matching_rows:
            if same_pin_rows:
                blockers.append("commit_mining_language_mismatch")
            else:
                blockers.append("commit_mining_pin_mismatch" if same_repo_rows else "commit_mining_missing")
            continue

        matched_rows.extend(matching_rows)
        for row in matching_rows:
            report_path, report = _read_commit_report(workspace, row)
            status = _norm(row.get("status"), limit=80).lower()
            if status in {"failed", "fail", "error", "dry_run", "dry-run", "not_run", "missing"}:
                blockers.append("commit_mining_failed")
            if report is None:
                blockers.append("commit_mining_missing")
            else:
                if report.get("schema") not in {
                    "auditooor.git_commits_mining.v1",
                    "auditooor.git_commits_mining.v1.2-solidity",
                }:
                    blockers.append("commit_mining_report_schema_missing")
                if not _is_present(report.get("generated_at") or report.get("generated_at_utc")):
                    blockers.append("commit_mining_report_timestamp_missing")
                upstream_repo = ""
                try:
                    upstream_repo = _repo_url_to_owner_repo(_norm(report.get("upstream_repo"), limit=500)).lower()
                except ValueError:
                    upstream_repo = ""
                if not upstream_repo:
                    blockers.append("commit_mining_report_upstream_repo_missing")
                elif upstream_repo != target["owner_repo"].lower():
                    blockers.append("commit_mining_report_upstream_repo_mismatch")
                report_pin = _norm(report.get("audit_pin_sha"), limit=120)
                if not report_pin or report_pin.lower() != target["pin"].lower():
                    blockers.append("commit_mining_pin_mismatch")
                if not _has_commit_window_evidence(report):
                    blockers.append("commit_mining_report_lacks_commit_evidence")
            commits_scanned = _report_scan_count(report) if report is not None else 0
            if commits_scanned <= 0 and not (
                report is not None and _has_canonical_empty_window_evidence(report)
            ):
                blockers.append("commit_mining_empty")
            artifact["evidence_rows"].append(
                {
                    "owner_repo": target["owner_repo"],
                    "pin": target["pin"],
                    "language": _norm(row.get("language"), limit=40),
                    "status": status,
                    "commits_scanned": commits_scanned,
                    "report_path": str(report_path) if report_path else "",
                    "report_exists": report is not None,
                }
            )

    artifact["matching_target_rows"] = len(matched_rows)
    artifact["status"] = "pass" if not blockers else "fail"
    artifact["blockers"] = sorted(set(blockers))
    return artifact, artifact["blockers"]


def _rows_from_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("queue", "rows", "packets", "candidates", "leads", "items", "command_rows"):
        rows = payload.get(key)
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    return []


def _row_text(row: dict[str, Any]) -> str:
    parts = [
        _candidate_id(row),
        _title(row),
        _first(row, "proof_status", "quality_gate_status", "status", "packet_state", "execution_contract_claim"),
        _first(row, "next_action", "recommended_next_step"),
    ]
    blockers = row.get("blockers")
    if isinstance(blockers, list):
        parts.extend(_norm(item) for item in blockers)
    return " ".join(parts).lower()


def _status_token(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", _norm(value, limit=160).lower()).strip("_")


def _is_terminal(row: dict[str, Any]) -> bool:
    if row.get("row_is_advisory") is True or row.get("advisory_only") is True:
        return True
    status_keys = (
        "proof_status",
        "quality_gate_status",
        "status",
        "packet_state",
        "scope_status",
        "verdict",
        "execution_contract_claim",
    )
    for key in status_keys:
        token = _status_token(row.get(key))
        if token in TERMINAL_STATES or token in ADVISORY_STATES:
            return True
    return False


def _load_queue(workspace: Path, queue_path: Path | None) -> tuple[Path, dict[str, Any] | None, list[dict[str, Any]]]:
    path = queue_path or workspace / ".auditooor" / "exploit_queue.source_mined.json"
    if not path.is_file() and queue_path is None:
        path = workspace / ".auditooor" / "exploit_queue.json"
    payload = _read_json(path) if path.is_file() else None
    return path, payload if isinstance(payload, dict) else None, _rows_from_payload(payload)


def _load_artifact_rows(path: Path) -> list[dict[str, Any]]:
    return _rows_from_payload(_read_json(path) if path.is_file() else None)


def _index_rows(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        keys = {
            _stable_key(row.get("lead_id")),
            _stable_key(row.get("candidate_id")),
            _stable_key(row.get("row_id")),
            _stable_key(row.get("id")),
            _stable_key(row.get("packet_id")),
            _stable_key(row.get("title")),
        }
        for key in keys:
            if key and key not in out:
                out[key] = row
    return out


def _lookup(index: dict[str, dict[str, Any]], row: dict[str, Any]) -> dict[str, Any] | None:
    for value in (
        row.get("lead_id"),
        row.get("candidate_id"),
        row.get("row_id"),
        row.get("id"),
        row.get("title"),
    ):
        hit = index.get(_stable_key(value))
        if hit is not None:
            return hit
    return None


def _prior_audit_dupe_index(payload: Any) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    if not isinstance(payload, dict):
        return {"exists": False, "status": "missing"}, {}
    rows = payload.get("drafts")
    if not isinstance(rows, list):
        rows = payload.get("rows")
    if not isinstance(rows, list):
        rows = []
    artifact = {
        "exists": True,
        "schema": payload.get("schema"),
        "mode": payload.get("mode", "draft"),
        "verdict_summary": payload.get("verdict_summary"),
        "gate_pass": payload.get("gate_pass"),
        "prior_audit_count": payload.get("prior_audit_count", 0),
        "rows": len(rows),
    }
    return artifact, _index_rows([row for row in rows if isinstance(row, dict)])


def _prior_audit_dupe_blockers(
    row: dict[str, Any],
    dupe_artifact: dict[str, Any],
    dupe_result: dict[str, Any] | None,
) -> tuple[list[str], dict[str, Any]]:
    if _severity(row) not in MEDIUM_PLUS:
        return [], {}
    if not dupe_artifact.get("exists"):
        return [], {}
    if _norm(dupe_artifact.get("verdict_summary")).lower() == "no-prior-audits":
        return [], {"status": "no_prior_audits"}
    if not dupe_artifact.get("prior_audit_count"):
        return [], {"status": "no_prior_audits"}
    if dupe_result is None:
        return ["prior_audit_dupe:missing_row"], {"status": "missing_row"}
    verdict = _norm(dupe_result.get("verdict"), limit=120).lower() or "unknown"
    status = "pass" if dupe_result.get("gate_pass") is True else "fail"
    summary = {
        "status": status,
        "verdict": verdict,
        "gate_pass": dupe_result.get("gate_pass"),
        "reason": _norm(dupe_result.get("reason"), limit=300),
    }
    if dupe_result.get("gate_pass") is False:
        return [f"prior_audit_dupe:{verdict}"], summary
    return [], summary


def _impact_contract_rows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        for key in ("contracts", "rows", "impact_contracts"):
            rows = payload.get(key)
            if isinstance(rows, list):
                return [row for row in rows if isinstance(row, dict)]
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    return []


def _load_impact_contracts(path: Path) -> tuple[bool, dict[str, dict[str, Any]]]:
    if not path.is_file():
        return False, {}
    payload = _read_json(path)
    rows = _impact_contract_rows(payload)
    index: dict[str, dict[str, Any]] = {}
    for row in rows:
        for key in (
            row.get("impact_contract_id"),
            row.get("candidate_id"),
            row.get("lead_id"),
            row.get("row_id"),
            row.get("id"),
            row.get("title"),
        ):
            stable = _stable_key(key)
            if stable and stable not in index:
                index[stable] = row
    return True, index


def _impact_contract_for(row: dict[str, Any], index: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    for value in (
        row.get("impact_contract_id"),
        row.get("lead_id"),
        row.get("candidate_id"),
        row.get("row_id"),
        row.get("id"),
        row.get("title"),
    ):
        hit = index.get(_stable_key(value))
        if hit is not None:
            return hit
    return None


def _safe_local_command(command: str) -> tuple[bool, list[str]]:
    text = command.strip()
    blockers: list[str] = []
    if not text:
        return False, ["missing_proof_command"]
    if text.startswith("#"):
        return False, ["proof_command_is_comment"]
    lowered = f" {text.lower()} "
    if any(token in lowered for token in NETWORK_TOKENS):
        blockers.append("proof_command_uses_network")
    if any(token in lowered for token in VAGUE_COMMAND_TOKENS):
        blockers.append("proof_command_is_vague")
    try:
        tokens = shlex.split(text)
    except ValueError:
        return False, ["proof_command_unparseable"]
    while tokens and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[0]):
        tokens.pop(0)
    if not tokens:
        blockers.append("missing_proof_command")
    else:
        executable = tokens[0]
        if (
            executable not in LOCAL_EXECUTABLES
            and not executable.startswith(("./", "../", "/"))
            and not executable.endswith((".py", ".sh"))
        ):
            blockers.append(f"unsupported_proof_executable:{executable}")
    return not blockers, blockers


def _source_artifacts_complete(row: dict[str, Any]) -> bool:
    if row.get("source_artifacts_complete") is True:
        return True
    if row.get("source_artifact_gaps") or row.get("source_artifact_gap_count"):
        return False
    source_refs = row.get("source_refs")
    source_artifacts = row.get("source_artifacts")
    proof_path = _first(row, "proof_path", "proof_artifact", "proof_artifact_path", "poc_path", "test_path")
    return _is_present(source_refs) and (_is_present(source_artifacts) or _is_present(proof_path))


def _values_for_keys(row: dict[str, Any] | None, keys: tuple[str, ...]) -> list[Any]:
    if not row:
        return []
    return [row.get(key) for key in keys if _is_present(row.get(key))]


def _reachability_text(row: dict[str, Any], contract: dict[str, Any] | None) -> str:
    values = _values_for_keys(row, REACHABILITY_TRACE_FIELDS)
    values.extend(_values_for_keys(contract, REACHABILITY_TRACE_FIELDS))
    values.extend(_values_for_keys(row, REACHABILITY_REBUTTAL_FIELDS))
    values.extend(_values_for_keys(contract, REACHABILITY_REBUTTAL_FIELDS))
    return _norm(values, limit=5000)


def _reachability_has_site(row: dict[str, Any], contract: dict[str, Any] | None) -> bool:
    return bool(
        _values_for_keys(row, REACHABILITY_SITE_FIELDS)
        or _values_for_keys(contract, REACHABILITY_SITE_FIELDS)
    )


def _reachability_has_citation(row: dict[str, Any], contract: dict[str, Any] | None, text: str) -> bool:
    if FILE_LINE_RE.search(text):
        return True
    refs = _values_for_keys(row, REACHABILITY_REF_FIELDS)
    refs.extend(_values_for_keys(contract, REACHABILITY_REF_FIELDS))
    return any(FILE_LINE_RE.search(_norm(ref, limit=1000)) for ref in refs)


def _reachability_has_explicit_citation(
    row: dict[str, Any], contract: dict[str, Any] | None, text: str
) -> bool:
    if FILE_LINE_RE.search(text):
        return True
    refs = _values_for_keys(row, REACHABILITY_EXPLICIT_REF_FIELDS)
    refs.extend(_values_for_keys(contract, REACHABILITY_EXPLICIT_REF_FIELDS))
    return any(FILE_LINE_RE.search(_norm(ref, limit=1000)) for ref in refs)


def _reachability_has_bounded_rebuttal(row: dict[str, Any], contract: dict[str, Any] | None) -> bool:
    for value in _values_for_keys(row, REACHABILITY_REBUTTAL_FIELDS) + _values_for_keys(
        contract, REACHABILITY_REBUTTAL_FIELDS
    ):
        text = _norm(value, limit=1000)
        lowered = text.lower()
        if (
            20 <= len(text) <= 400
            and lowered not in {"true", "false"}
            and not REACHABILITY_REBUTTAL_PLACEHOLDER_RE.search(text)
            and REACHABILITY_REBUTTAL_REASON_RE.search(text)
            and _reachability_has_explicit_citation(row, contract, text)
        ):
            return True
    return False


def _reachability_ready(row: dict[str, Any], contract: dict[str, Any] | None) -> tuple[str, list[str]]:
    if _severity_rank(row) < FILEABLE_MIN_RANK:
        return "not_required", []

    text = _reachability_text(row, contract)
    if text and REACHABILITY_UNREACHABLE_RE.search(text):
        return "unreachable", ["reachability_unreachable"]

    if not text:
        return "missing", ["reachability_missing_trace"]

    has_positive_trace = bool(REACHABILITY_POSITIVE_RE.search(text))
    has_site = _reachability_has_site(row, contract)
    has_citation = _reachability_has_citation(row, contract, text)
    has_rebuttal = _reachability_has_bounded_rebuttal(row, contract)
    if (has_citation and (has_positive_trace or has_site)) or has_rebuttal:
        return "ready", []
    return "missing", ["reachability_missing_trace"]


def _has_oos_traps(row: dict[str, Any], contract: dict[str, Any] | None) -> bool:
    values = [
        row.get("oos_traps"),
        row.get("oos_trap"),
        row.get("oos_guard"),
        row.get("scope_traps"),
        row.get("scope_status"),
        row.get("likely_triager_objection"),
    ]
    if contract:
        values.extend(
            [
                contract.get("oos_traps"),
                contract.get("oos_trap"),
                contract.get("oos_guard"),
                contract.get("scope_traps"),
                contract.get("scope_status"),
            ]
        )
    return any(_is_present(value) for value in values)


def _has_negative_control(row: dict[str, Any], contract: dict[str, Any] | None) -> bool:
    values = [
        row.get("negative_control"),
        row.get("negative_controls"),
        row.get("falsification_requirements"),
        row.get("kill_conditions"),
        row.get("required_control"),
        row.get("stop_condition"),
        row.get("clean_control"),
    ]
    if contract:
        values.extend(
            [
                contract.get("negative_control"),
                contract.get("negative_controls"),
                contract.get("kill_conditions"),
                contract.get("stop_condition"),
                contract.get("clean_control"),
            ]
        )
    return any(_is_present(value) for value in values)


def _is_high_plus(row: dict[str, Any], contract: dict[str, Any] | None) -> bool:
    """True when the row / contract carries a HIGH+ fund-loss-class impact."""
    if _severity(row) in HIGH_PLUS:
        return True
    parts: list[str] = []
    for key in ("selected_impact", "listed_impact_selected", "impact_path", "title"):
        parts.append(_norm(row.get(key)))
    if contract:
        for key in ("selected_impact", "listed_impact_selected", "severity", "severity_tier"):
            parts.append(_norm(contract.get(key)))
        if _severity(contract) in HIGH_PLUS:
            return True
    hay = " ".join(parts).lower()
    return any(keyword in hay for keyword in HIGH_PLUS_IMPACT_KEYWORDS)


def _negative_control_text(row: dict[str, Any], contract: dict[str, Any] | None) -> str:
    """Flatten all negative-control / falsification text for variant scanning."""
    values: list[Any] = [
        row.get("negative_control"),
        row.get("negative_controls"),
        row.get("falsification_requirements"),
        row.get("kill_conditions"),
        row.get("required_control"),
        row.get("stop_condition"),
        row.get("clean_control"),
        row.get("defender_wins_control"),
        row.get("defender_absent_control"),
    ]
    if contract:
        values.extend(
            [
                contract.get("negative_control"),
                contract.get("negative_controls"),
                contract.get("kill_conditions"),
                contract.get("stop_condition"),
                contract.get("clean_control"),
            ]
        )
    return _norm(values, limit=4000).lower()


def _opposed_trace_blockers(row: dict[str, Any], contract: dict[str, Any] | None) -> list[str]:
    """Fail closed when a HIGH+ row has an unopposed-trace impact contract.

    Emits typed blockers so the operator sees exactly why the row is blocked:

    - ``unopposed_trace_high_plus`` - HIGH+ with no enumerated protocol defenses
      or with ``opposed_trace_required`` set and coverage not ``covered``;
    - ``opposed_trace_missing_defender_wins_control`` /
      ``opposed_trace_missing_defender_absent_control`` - the negative controls
      lack the "defender wins" / "defender absent" variant the opposed trace
      needs.
    """
    if not _is_high_plus(row, contract):
        return []

    blockers: list[str] = []
    # The contract is the proof object for the opposed-trace fields. If the
    # HIGH+ row has no impact contract at all, the missing-impact-contract
    # blocker (already raised by _impact_contract_ready) covers it.
    if not contract:
        return ["unopposed_trace_high_plus"]

    required = contract.get("opposed_trace_required")
    coverage = _norm(contract.get("opposed_trace_coverage")).lower()
    defenses = contract.get("protocol_defenses_enumerated")
    defenses_present = isinstance(defenses, list) and any(
        _norm(item) for item in defenses
    )

    # Empty enumerated defenses on a HIGH+ row is an unopposed trace.
    if not defenses_present:
        blockers.append("unopposed_trace_high_plus")
    # opposed_trace_required and coverage not covered is an unopposed trace.
    elif required is True and coverage != "covered":
        blockers.append("unopposed_trace_high_plus")

    # Negative-control variant coverage: when defenses are enumerated the proof
    # must show both a defender-wins and a defender-absent control variant.
    if defenses_present:
        control_text = _negative_control_text(row, contract)
        if not any(token in control_text for token in DEFENDER_WINS_TOKENS):
            blockers.append("opposed_trace_missing_defender_wins_control")
        if not any(token in control_text for token in DEFENDER_ABSENT_TOKENS):
            blockers.append("opposed_trace_missing_defender_absent_control")

    return list(dict.fromkeys(blockers))


def _opposed_trace_warnings(row: dict[str, Any], contract: dict[str, Any] | None) -> list[str]:
    """Advisory (non-blocking) opposed-trace warnings for a non-HIGH+ row.

    HACKERMAN_V3 tiered model: the opposed-trace question is asked at every
    severity, but below HIGH+ a missing opposed trace is an ADVISORY, not a
    hard blocker. A non-HIGH+ row with an unopposed-trace impact contract emits
    ``advisory_unopposed_trace`` so the reviewer sees it, while the row still
    passes the gate.
    """
    if _is_high_plus(row, contract):
        # HIGH+ rows are covered by the hard blocker path, not the advisory.
        return []
    if not contract:
        return []
    warnings: list[str] = []
    # The source-mined contract emits an explicit advisory list; honor it when
    # present, otherwise derive the advisory from the coverage field directly.
    advisories = contract.get("contract_advisories")
    if isinstance(advisories, list) and any(_norm(item) for item in advisories):
        warnings.append("advisory_unopposed_trace")
        return list(dict.fromkeys(warnings))
    coverage = _norm(contract.get("opposed_trace_coverage")).lower()
    defenses = contract.get("protocol_defenses_enumerated")
    defenses_present = isinstance(defenses, list) and any(_norm(item) for item in defenses)
    # Only treat a freeze/loss-class non-HIGH+ contract as advisory-worthy.
    selected = _norm(contract.get("selected_impact") or contract.get("listed_impact_selected")).lower()
    freeze_loss = any(
        token in selected
        for token in ("freeze", "frozen", "freezing", "loss", "theft", "drain", "stolen", "insolven")
    )
    if freeze_loss and (not defenses_present or coverage == "missing"):
        warnings.append("advisory_unopposed_trace")
    return list(dict.fromkeys(warnings))


def _impact_contract_ready(row: dict[str, Any], contract: dict[str, Any] | None) -> tuple[bool, list[str]]:
    blockers: list[str] = []
    status = _first(row, "impact_contract_status").lower()
    gaps = row.get("impact_contract_gaps")
    if status == "not_required" and not gaps:
        return True, []
    if not contract:
        blockers.append("missing_impact_contract")
        return False, blockers

    contract_status = _first(contract, "status", "impact_contract_status", "submission_posture").lower()
    if contract_status and contract_status not in IMPACT_READY_STATES and "not_submit" not in contract_status:
        blockers.append(f"impact_contract_status:{contract_status}")
    for key in ("selected_impact", "exact_impact_row"):
        if not _is_present(contract.get(key)):
            blockers.append(f"impact_contract_missing:{key}")
    for key in ("attacker", "attacker_actor", "attacker_role"):
        if _is_present(contract.get(key)):
            break
    else:
        blockers.append("impact_contract_missing:attacker")
    for key in ("victim", "victim_actor", "victim_role"):
        if _is_present(contract.get(key)):
            break
    else:
        blockers.append("impact_contract_missing:victim")
    for key in ("asset_at_risk", "asset", "asset_category"):
        if _is_present(contract.get(key)):
            break
    else:
        blockers.append("impact_contract_missing:asset")
    return not blockers, blockers


def _judgment_ready(row: dict[str, Any], packet: dict[str, Any] | None) -> tuple[bool, list[str]]:
    if _severity(row) not in HIGH_PLUS:
        return True, []
    if not packet:
        return False, ["missing_candidate_judgment_packet"]
    state = _first(packet, "packet_state").lower()
    blockers = packet.get("promotion_blockers") or []
    if state == "ready_for_poc_planning" and not blockers:
        return True, []
    out = [f"candidate_judgment_state:{state or 'unknown'}"]
    out.extend(f"candidate_judgment_blocker:{_norm(blocker, limit=100)}" for blocker in blockers[:5])
    return False, out


def _harness_ready(row: dict[str, Any], harness: dict[str, Any] | None) -> tuple[str, list[str]]:
    if not harness:
        return "missing", ["missing_harness_execution_row"]
    status = _first(harness, "status", "execution_contract_claim").lower()
    blockers = [_norm(item, limit=120) for item in harness.get("blockers") or [] if _norm(item)]
    if status in HARNESS_READY_STATES:
        return "ready", []
    if status in HARNESS_BLOCKED_STATES or blockers:
        return "blocked", [f"harness_{item}" for item in blockers[:5]] or [f"harness_status:{status}"]
    return "unknown", [f"harness_status:{status or 'unknown'}"]


def evaluate_row(
    row: dict[str, Any],
    *,
    impact_contract: dict[str, Any] | None,
    judgment_packet: dict[str, Any] | None,
    harness_row: dict[str, Any] | None,
    prior_audit_dupe_artifact: dict[str, Any] | None = None,
    prior_audit_dupe_result: dict[str, Any] | None = None,
    commit_mining_blockers: list[str] | None = None,
) -> dict[str, Any]:
    blockers: list[str] = []
    warnings: list[str] = []

    if not _source_artifacts_complete(row):
        blockers.append("source_artifacts_incomplete")

    dupe_artifact = prior_audit_dupe_artifact or {"exists": False, "status": "missing"}
    dupe_blockers, dupe_summary = _prior_audit_dupe_blockers(row, dupe_artifact, prior_audit_dupe_result)
    blockers.extend(dupe_blockers)

    command = _first(row, "proof_command", "next_command", "harness_command", "gating_test")
    command_ok, command_blockers = _safe_local_command(command)
    if not command_ok:
        blockers.extend(command_blockers)

    reachability_status, reachability_blockers = _reachability_ready(row, impact_contract)
    blockers.extend(reachability_blockers)

    impact_ready, impact_blockers = _impact_contract_ready(row, impact_contract)
    if not impact_ready:
        blockers.extend(impact_blockers)

    # HACKERMAN_V3 opposed-trace proof gate (tiered): HIGH+ Direct-loss rows
    # fail closed unless every protocol-owned defense is enumerated and the
    # proof beats it. Below HIGH+, a missing opposed trace is an advisory
    # warning (non-blocking) so the reviewer still sees it.
    blockers.extend(_opposed_trace_blockers(row, impact_contract))
    warnings.extend(_opposed_trace_warnings(row, impact_contract))

    if not _has_oos_traps(row, impact_contract):
        blockers.append("missing_oos_traps")
    if not _has_negative_control(row, impact_contract):
        blockers.append("missing_negative_control")

    judgment_ready, judgment_blockers = _judgment_ready(row, judgment_packet)
    if not judgment_ready:
        blockers.extend(judgment_blockers)

    harness_status, harness_blockers = _harness_ready(row, harness_row)
    if harness_status == "missing":
        warnings.extend(harness_blockers)
    elif harness_status != "ready":
        blockers.extend(harness_blockers)

    if commit_mining_blockers:
        blockers.extend(commit_mining_blockers)

    return {
        "lead_id": _candidate_id(row),
        "title": _title(row),
        "severity": _severity(row),
        "status": "pass" if not blockers else "fail",
        "blockers": list(dict.fromkeys(blockers)),
        "warnings": list(dict.fromkeys(warnings)),
        "source_artifacts_complete": _source_artifacts_complete(row),
        "impact_contract_present": impact_contract is not None,
        "candidate_judgment_present": judgment_packet is not None,
        "prior_audit_dupe": dupe_summary,
        "reachability_status": reachability_status,
        "harness_status": harness_status,
        "next_command": command,
    }


def build_gate(
    workspace: Path,
    *,
    queue_path: Path | None = None,
    judgment_path: Path | None = None,
    harness_path: Path | None = None,
    impact_contracts_path: Path | None = None,
    prior_audit_dupe_path: Path | None = None,
    max_rows: int = 200,
) -> dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    queue_path, queue_payload, queue_rows = _load_queue(workspace, queue_path)
    judgment_path = judgment_path or workspace / ".auditooor" / "prove_top_leads_candidate_judgment_packet.json"
    if not judgment_path.is_file():
        fallback = workspace / ".auditooor" / "candidate_judgment_packet.json"
        if fallback.is_file():
            judgment_path = fallback
    harness_path = harness_path or workspace / ".auditooor" / "harness_execution_queue_from_exploit_queue.json"
    impact_contracts_path = impact_contracts_path or workspace / ".auditooor" / "impact_contracts.json"
    prior_audit_dupe_path = prior_audit_dupe_path or workspace / ".auditooor" / "source_first_prior_audit_dupe_gate.json"

    packets = _load_artifact_rows(judgment_path)
    harness_rows = _load_artifact_rows(harness_path)
    impact_exists, impact_index = _load_impact_contracts(impact_contracts_path)
    packet_index = _index_rows(packets)
    harness_index = _index_rows(harness_rows)
    prior_dupe_payload = _read_json(prior_audit_dupe_path) if prior_audit_dupe_path.is_file() else None
    prior_dupe_artifact, prior_dupe_index = _prior_audit_dupe_index(prior_dupe_payload)
    prior_dupe_artifact["path"] = str(prior_audit_dupe_path)
    commit_mining_artifact, commit_mining_blockers = _commit_mining_status(workspace)

    considered: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for row in queue_rows[:max_rows]:
        if _is_terminal(row):
            skipped.append(
                {
                    "lead_id": _candidate_id(row),
                    "title": _title(row),
                    "reason": "terminal_or_advisory",
                }
            )
            continue
        considered.append(
            evaluate_row(
                row,
                impact_contract=_impact_contract_for(row, impact_index),
                judgment_packet=_lookup(packet_index, row),
                harness_row=_lookup(harness_index, row),
                prior_audit_dupe_artifact=prior_dupe_artifact,
                prior_audit_dupe_result=_lookup(prior_dupe_index, row),
            )
        )

    global_blockers = commit_mining_blockers
    blocker_counts = Counter(
        blocker for row in considered for blocker in row.get("blockers", [])
    )
    blocker_counts.update(global_blockers)
    fail_count = sum(1 for row in considered if row["status"] == "fail")
    payload = {
        "schema": SCHEMA,
        "generated_at_utc": _utc_now(),
        "workspace": str(workspace),
        "status": "pass" if fail_count == 0 and not global_blockers else "fail",
        "summary": {
            "queue_rows_seen": len(queue_rows),
            "rows_considered": len(considered),
            "rows_skipped": len(skipped),
            "rows_failed": fail_count,
            "rows_passed": sum(1 for row in considered if row["status"] == "pass"),
            "global_blockers": list(dict.fromkeys(global_blockers)),
            "blocker_counts": dict(sorted(blocker_counts.items())),
        },
        "artifacts": {
            "queue": {"path": str(queue_path), "exists": queue_path.is_file(), "schema": (queue_payload or {}).get("schema")},
            "candidate_judgment_packet": {"path": str(judgment_path), "exists": judgment_path.is_file(), "rows": len(packets)},
            "harness_execution_queue": {"path": str(harness_path), "exists": harness_path.is_file(), "rows": len(harness_rows)},
            "impact_contracts": {"path": str(impact_contracts_path), "exists": impact_exists, "rows": len(impact_index)},
            "prior_audit_dupe": prior_dupe_artifact,
            "commit_mining": commit_mining_artifact,
        },
        "rows": considered,
        "skipped_rows": skipped[:50],
        "proof_boundary": (
            "This gate only checks that source-first candidates have local row contracts before proof spend. "
            "It does not prove exploitability, assign severity, provide final platform duplicate/OOS clearance, "
            "or make a report submission-ready."
        ),
    }
    return payload


def render_md(payload: dict[str, Any]) -> str:
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    lines = [
        "# V3 Source-First Row Gate",
        "",
        f"- Status: `{payload.get('status')}`",
        f"- Rows considered: `{summary.get('rows_considered', 0)}`",
        f"- Rows failed: `{summary.get('rows_failed', 0)}`",
        f"- Rows skipped: `{summary.get('rows_skipped', 0)}`",
        "",
        "## Blockers",
    ]
    counts = summary.get("blocker_counts") if isinstance(summary.get("blocker_counts"), dict) else {}
    if not counts:
        lines.append("- none")
    else:
        for blocker, count in counts.items():
            lines.append(f"- `{blocker}`: {count}")
    global_blockers = summary.get("global_blockers")
    lines.extend(["", "## Global Blockers"])
    if isinstance(global_blockers, list) and global_blockers:
        for blocker in global_blockers:
            lines.append(f"- `{blocker}`")
    else:
        lines.append("- none")
    lines.extend(["", "## Rows"])
    rows = payload.get("rows") if isinstance(payload.get("rows"), list) else []
    if not rows:
        lines.append("- none")
    for row in rows:
        lines.append(f"### {row.get('lead_id')} - {row.get('title')}")
        lines.append(f"- Status: `{row.get('status')}`")
        lines.append(f"- Severity: `{row.get('severity')}`")
        if row.get("blockers"):
            lines.append("- Blockers: " + ", ".join(f"`{item}`" for item in row["blockers"]))
        if row.get("warnings"):
            lines.append("- Warnings: " + ", ".join(f"`{item}`" for item in row["warnings"]))
        if row.get("next_command"):
            lines.append(f"- Next command: `{row.get('next_command')}`")
    return "\n".join(lines).rstrip() + "\n"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--queue", type=Path, help="Override exploit queue path")
    parser.add_argument("--candidate-judgment", type=Path, help="Override candidate judgment packet path")
    parser.add_argument("--harness-queue", type=Path, help="Override harness execution queue path")
    parser.add_argument("--impact-contracts", type=Path, help="Override impact contracts path")
    parser.add_argument("--prior-audit-dupe", type=Path, help="Override prior-audit dupe gate artifact path")
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--max-rows", type=int, default=200)
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    workspace = args.workspace.expanduser().resolve()
    payload = build_gate(
        workspace,
        queue_path=args.queue.expanduser().resolve() if args.queue else None,
        judgment_path=args.candidate_judgment.expanduser().resolve() if args.candidate_judgment else None,
        harness_path=args.harness_queue.expanduser().resolve() if args.harness_queue else None,
        impact_contracts_path=args.impact_contracts.expanduser().resolve() if args.impact_contracts else None,
        prior_audit_dupe_path=args.prior_audit_dupe.expanduser().resolve() if args.prior_audit_dupe else None,
        max_rows=args.max_rows,
    )
    out_json = args.out_json.expanduser().resolve() if args.out_json else workspace / ".auditooor" / "v3_source_first_row_gate.json"
    out_md = args.out_md.expanduser().resolve() if args.out_md else workspace / ".auditooor" / "v3_source_first_row_gate.md"
    payload["out_json"] = str(out_json)
    payload["out_md"] = str(out_md)
    _write_json(out_json, payload)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(render_md(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"[v3-source-first-row-gate] status={payload['status']} rows_failed={payload['summary']['rows_failed']} out={out_json}")
    if args.strict and payload["status"] != "pass":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
