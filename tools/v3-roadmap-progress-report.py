#!/usr/bin/env python3
"""Conservative HACKERMAN V3 full-roadmap progress reporter.

This tool is read-only and offline. It inspects local implementation and
sidecar evidence, then reports roadmap completion as broad ranges instead of
false precision. Provider KEEP rows are treated as unverified until local
verification artifacts prove otherwise.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "auditooor.v3_roadmap_progress_report.v1"

STATUS_MET = "met"
STATUS_PARTIAL = "partial"
STATUS_UNMET = "unmet"
STATUS_UNKNOWN = "unknown"

BLOCKING_CATEGORY_IDS = (
    "pillar_p1_invariants",
    "pillar_p2_causal_chains",
    "pillar_p3_antipattern_catalog",
    "pillar_p4_triager_model",
    "pillar_p5_live_target_intel",
    "field_validation",
    "source_miners",
    "sidecar_coverage",
    "provider_campaign_completeness",
    "provider_keep_verification",
    "lesson_gates",
    "real_hunt_validation",
)

PILLAR_TARGETS = {
    "p1_invariants_mvp": 500,
    "p2_causal_chains_mvp": 100,
    "p3_antipatterns_mvp_min": 130,
}

P5_ACCEPTED_SOURCEPROOF_TOOL_VERSION = "0.4.1-mvp3-accepted-p1-sourceproof"

P2_CANONICAL_QUALITY_REQUIREMENTS = (
    "verification_tier != unknown",
    "preconditions non-empty",
    "preconditions exclude placeholder tbd/todo",
    "defense must not be fallback/placeholder",
)

P3_COMMAND_PLAN_QUERY_TYPES = frozenset({"ast", "semgrep", "tree-sitter"})

NAMED_TOOLS: dict[str, tuple[str, ...]] = {
    "provider_fanout": (
        "tools/v3-provider-fanout-queue.py",
        "tools/v3-provider-fanout-runner.py",
        "tools/v3-provider-fanout-closeout.py",
        "tools/v3-provider-campaign-completeness-gate.py",
    ),
    "provider_local_verification": (
        "tools/v3-provider-local-verification-queue.py",
        "tools/v3-provider-local-verify.py",
    ),
    "workflow_and_field_validation": (
        "tools/audit-workflow-coverage-map.py",
        "tools/field-validation-report.py",
        "tools/v3-provider-learning-compiler.py",
        "tools/lesson-source-inventory.py",
    ),
    "mining_and_source_intel": (
        "tools/mining-coverage-dashboard.py",
        "tools/hackerman-sidecar-coverage-report.py",
        "tools/hackerman-etl-from-audit-firm-public-reports.py",
        "tools/hackerman-etl-from-zk-auditor-reports.py",
        "tools/hackerman-etl-from-immunefi-dashboard.py",
    ),
}

MAKE_TARGETS = (
    "audit-workflow-coverage-map",
    "mining-coverage-dashboard",
    "hackerman-sidecar-coverage-report",
    "field-validation-report",
    "provider-fanout-discipline-check",
    "v3-provider-campaign-completeness-gate",
    "lesson-source-inventory",
    "lesson-enforcement-inventory",
    "agent-artifact-lesson-candidates",
)

SOURCE_MINER_TOOL_RE = re.compile(
    r"(etl|miner|mining|external-intel|solodit|immunefi|audit-firm|zk-auditor|post-mortem)",
    re.IGNORECASE,
)
KEEP_RE = re.compile(r"\bKEEP_FOR_LOCAL_VERIFICATION\b")


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return rows
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def _rel(path: Path, root: Path, workspace: Path | None = None) -> str:
    return _display_path(path.as_posix(), root, workspace)


def _display_path(value: str, root: Path, workspace: Path | None = None) -> str:
    """Return a useful non-absolute path for values owned by root/workspace."""
    if not value:
        return value
    path = Path(value).expanduser()
    if not path.is_absolute():
        return value
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path
    if workspace is not None:
        try:
            rel = resolved.relative_to(workspace.resolve())
            return "<workspace>" if rel.as_posix() == "." else f"<workspace>/{rel.as_posix()}"
        except ValueError:
            pass
    try:
        rel = resolved.relative_to(root.resolve())
        return "." if rel.as_posix() == "." else rel.as_posix()
    except ValueError:
        return value


def _sanitize_pathlike_string(value: str, root: Path, workspace: Path | None = None) -> str:
    if not value.startswith(("/", "~")):
        return value
    return _display_path(value, root, workspace)


def _sanitize_nested_paths(value: Any, root: Path, workspace: Path | None = None) -> Any:
    if isinstance(value, dict):
        return {key: _sanitize_nested_paths(child, root, workspace) for key, child in value.items()}
    if isinstance(value, list):
        return [_sanitize_nested_paths(child, root, workspace) for child in value]
    if isinstance(value, str):
        return _sanitize_pathlike_string(value, root, workspace)
    return value


def _sanitize_command(value: str, root: Path, workspace: Path | None = None) -> str:
    """Hide local workspace roots in suggested commands without changing flags."""
    sanitized = value
    replacements: list[tuple[str, str]] = []
    for base, label in ((workspace, "<workspace>"), (root, "<workspace>")):
        if base is None:
            continue
        replacements.append((str(base.expanduser().absolute()), label))
        try:
            resolved = str(base.resolve())
        except OSError:
            resolved = str(base)
        replacements.append((resolved, label))
    # Longest paths first prevents replacing a repo prefix before a nested
    # workspace gets a chance to become <workspace>.
    for raw, label in sorted(set(replacements), key=lambda item: len(item[0]), reverse=True):
        sanitized = sanitized.replace(raw, label)
    return sanitized


def _sanitize_guidance(value: Any, root: Path, workspace: Path | None = None) -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, child in value.items():
            if key == "next_commands" and isinstance(child, list):
                sanitized[key] = [
                    _sanitize_command(command, root, workspace) if isinstance(command, str) else command
                    for command in child
                ]
            else:
                sanitized[key] = _sanitize_guidance(child, root, workspace)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_guidance(child, root, workspace) for child in value]
    if isinstance(value, str):
        return _sanitize_pathlike_string(value, root, workspace)
    return value


def _is_target_header(line: str) -> bool:
    if not line or line.startswith(("\t", " ", "#", ".")):
        return False
    if ":=" in line or "?=" in line or "+=" in line:
        return False
    return re.match(r"^[A-Za-z0-9_.%/@$() -]+:(?:\s|$)", line) is not None


def _parse_make_targets(makefile: Path) -> set[str]:
    try:
        lines = makefile.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return set()
    targets: set[str] = set()
    for line in lines:
        if not _is_target_header(line):
            continue
        header = line.split(":", 1)[0]
        targets.update(part for part in header.split() if part)
    return targets


def _flatten(value: Any) -> Iterable[Any]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from _flatten(child)
    elif isinstance(value, list):
        for child in value:
            yield from _flatten(child)
    else:
        yield value


def _count_keep_rows(paths: Iterable[Path]) -> tuple[int, int]:
    files = 0
    rows = 0
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        count = len(KEEP_RE.findall(text))
        if count:
            files += 1
            rows += count
    return files, rows


def _candidate_provider_paths(root: Path, workspace: Path | None = None) -> list[Path]:
    paths: list[Path] = []
    if workspace is not None:
        bases = (
            workspace / "agent_outputs",
            workspace / "provider_outputs",
            workspace / ".auditooor" / "provider_fanout",
        )
        auditooor_dirs = (workspace / ".auditooor",)
    else:
        bases = (root / "agent_outputs", root / "provider_outputs", root / ".auditooor" / "provider_fanout")
        auditooor_dirs = (root / ".auditooor",)
    for base in bases:
        if not base.is_dir():
            continue
        paths.extend(p for p in base.rglob("*") if p.is_file() and p.suffix in {".json", ".jsonl", ".txt", ".md"})
    for auditooor_dir in auditooor_dirs:
        if not auditooor_dir.is_dir():
            continue
        for base in auditooor_dir.glob("v3_provider_fanout_*"):
            if base.is_dir():
                paths.extend(p for p in base.rglob("*") if p.is_file() and p.suffix in {".json", ".jsonl", ".txt", ".md"})
    return sorted(paths, key=lambda p: str(p))


def _count_dispatch_rows(root: Path) -> dict[str, Any]:
    dispatch_paths: list[Path] = []
    for base in (root / "agent_outputs", root / ".audit_logs"):
        if base.is_dir():
            dispatch_paths.extend(base.glob("**/llm_dispatch_*.json"))
    by_provider: Counter[str] = Counter()
    outcomes: Counter[str] = Counter()
    for path in dispatch_paths:
        data = _read_json(path)
        if not isinstance(data, dict):
            continue
        by_provider[str(data.get("provider") or "unknown")] += 1
        outcome = str(data.get("outcome") or data.get("status") or "unknown")
        outcome = re.sub(r"^(error: http-\d{3}):.*$", r"\1", outcome)
        outcome = re.sub(r"^(fallback: transport-error):.*$", r"\1", outcome)
        outcomes[outcome] += 1

    budget_rows = _read_jsonl(root / "tools" / "calibration" / "llm_budget_log.jsonl")
    budget_by_provider: Counter[str] = Counter()
    for row in budget_rows:
        budget_by_provider[str(row.get("provider") or "unknown")] += 1

    return {
        "dispatch_files": len(dispatch_paths),
        "dispatch_by_provider": dict(sorted(by_provider.items())),
        "dispatch_outcomes": dict(sorted(outcomes.items())),
        "budget_log_rows": len(budget_rows),
        "budget_by_provider": dict(sorted(budget_by_provider.items())),
        "source_refs": [],
    }


def _latest_existing(candidates: Iterable[Path]) -> Path | None:
    existing = [path for path in candidates if path.is_file()]
    if not existing:
        return None
    return max(existing, key=lambda p: p.stat().st_mtime)


def _first_existing(candidates: Iterable[Path]) -> Path | None:
    for path in candidates:
        if path.is_file():
            return path
    return None


def _mtime_or_zero(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _verification_artifact_refs(
    paths: Sequence[Path],
    parsed_result_paths: Sequence[Path],
    root: Path,
    workspace: Path | None = None,
) -> list[str]:
    parsed = {path.resolve() for path in parsed_result_paths}

    def sort_key(path: Path) -> tuple[int, float, str]:
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        # Parsed result files carry the actual verification rows, so surface
        # them before companion queues and older provider outputs.
        return (0 if resolved in parsed else 1, -_mtime_or_zero(path), str(path))

    return [_rel(path, root, workspace) for path in sorted(paths, key=sort_key)[:8]]


def _resolve_artifact_path(value: Any, root: Path, workspace: Path | None = None) -> Path | None:
    if not isinstance(value, str) or not value.strip():
        return None
    if workspace is not None and value == "<workspace>":
        return workspace
    if workspace is not None and value.startswith("<workspace>/"):
        return workspace / value.removeprefix("<workspace>/")
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = root / path
    return path


def _selected_provider_local_verification_paths(
    root: Path,
    provider_campaign: dict[str, Any] | None = None,
    workspace: Path | None = None,
) -> list[Path]:
    artifacts: dict[str, Any] = {}
    if isinstance(provider_campaign, dict) and isinstance(provider_campaign.get("artifacts"), dict):
        artifacts = provider_campaign["artifacts"]
    if artifacts:
        selected = _resolve_artifact_path(artifacts.get("local_verification"), root, workspace)
        if selected is not None and selected.is_file():
            return [selected]
    path = _latest_existing(_provider_campaign_gate_paths(root, workspace))
    if path is None:
        return []
    data = _read_json(path)
    if not isinstance(data, dict):
        return []
    artifacts = data.get("artifacts") if isinstance(data.get("artifacts"), dict) else {}
    selected = _resolve_artifact_path(artifacts.get("local_verification"), root, workspace)
    if selected is not None and selected.is_file():
        return [selected]
    return []


def _local_verification_summary(paths: Sequence[Path]) -> dict[str, Any]:
    status_counts: Counter[str] = Counter()
    terminal_rows = 0
    source_collection_required = 0
    terminal_judgment_required = 0
    unresolved_rows = 0
    backfill_result_rows = 0
    parsed_result_paths: list[Path] = []
    for path in paths:
        data = _read_json(path)
        if not isinstance(data, dict) or data.get("schema") != "auditooor.v3_provider_local_verification_result.v1":
            continue
        parsed_result_paths.append(path)
        is_backfill_result = path.name == "provider_keep_verification_backfill_result.json"
        for row in data.get("rows") or []:
            if not isinstance(row, dict):
                continue
            verification_status = str(row.get("verification_status") or "unknown")
            status_counts[verification_status] += 1
            if is_backfill_result:
                backfill_result_rows += 1
            if row.get("terminal_outcome"):
                terminal_rows += 1
            row_source_required = bool(row.get("source_collection_required")) or verification_status == "needs_more_source"
            row_terminal_required = bool(row.get("terminal_judgment_required"))
            if row_source_required:
                source_collection_required += 1
            if row_terminal_required:
                terminal_judgment_required += 1
            if verification_status in {"pending", "needs_more_source", "blocked"} or row_source_required or row_terminal_required:
                unresolved_rows += 1
    return {
        "status_counts": status_counts,
        "terminal_rows": terminal_rows,
        "source_collection_required": source_collection_required,
        "terminal_judgment_required": terminal_judgment_required,
        "unresolved_rows": unresolved_rows,
        "backfill_result_rows": backfill_result_rows,
        "parsed_result_paths": parsed_result_paths,
    }


def _historical_local_verification_evidence(
    paths: Sequence[Path],
    root: Path,
    workspace: Path | None = None,
) -> dict[str, Any]:
    summary = _local_verification_summary(paths)
    return {
        "artifact_count": len(paths),
        "parsed_artifact_count": len(summary["parsed_result_paths"]),
        "row_count": sum(summary["status_counts"].values()),
        "verification_status_counts": dict(sorted(summary["status_counts"].items())),
        "source_collection_required_rows": summary["source_collection_required"],
        "terminal_judgment_required_rows": summary["terminal_judgment_required"],
        "unresolved_rows": summary["unresolved_rows"],
        "source_refs": _verification_artifact_refs(paths, summary["parsed_result_paths"], root, workspace),
        "claim_guard": (
            "Historical provider verification artifacts are advisory only; the current campaign-selected "
            "local_verification artifact is authoritative for blocking progress."
        ),
    }


def _workflow_map_paths(root: Path) -> list[Path]:
    return [
        root / ".auditooor" / "audit_workflow_coverage_map.json",
        root / "reports" / "audit_workflow_coverage_map.json",
        root / "reports" / "audit_workflow_coverage_map.current.json",
    ]


def _mining_dashboard_paths(root: Path) -> list[Path]:
    return [
        root / ".auditooor" / "mining_coverage_dashboard.json",
        root / "reports" / "mining_coverage_dashboard.json",
    ]


def _sidecar_coverage_paths(root: Path) -> list[Path]:
    return [
        root / ".auditooor" / "hackerman_sidecar_coverage_report.json",
        root / "reports" / "hackerman_sidecar_coverage_report.json",
    ]


def _field_validation_paths(root: Path, workspace: Path | None) -> list[Path]:
    paths = [
        root / ".auditooor" / "field_validation_report.json",
        root / "reports" / "field_validation_report.json",
    ]
    if workspace is not None:
        paths.insert(0, workspace / ".auditooor" / "field_validation_report.json")
    return paths


def _status_evidence(status: str, reason: str, refs: Iterable[str] = ()) -> dict[str, Any]:
    return {"status": status, "reason": reason, "source_refs": list(refs)}


def _named_tool_evidence(root: Path) -> dict[str, Any]:
    groups: dict[str, Any] = {}
    present_total = 0
    expected_total = 0
    for group, rels in NAMED_TOOLS.items():
        expected_total += len(rels)
        present = [rel for rel in rels if (root / rel).is_file()]
        present_total += len(present)
        groups[group] = {"present": present, "missing": [rel for rel in rels if rel not in present]}
    status = STATUS_MET if present_total == expected_total else STATUS_PARTIAL if present_total else STATUS_UNMET
    return {
        "status": status,
        "present": present_total,
        "expected": expected_total,
        "groups": groups,
    }


def _makefile_evidence(root: Path) -> dict[str, Any]:
    makefile = root / "Makefile"
    targets = _parse_make_targets(makefile)
    present = [target for target in MAKE_TARGETS if target in targets]
    missing = [target for target in MAKE_TARGETS if target not in targets]
    status = STATUS_MET if len(present) == len(MAKE_TARGETS) else STATUS_PARTIAL if present else STATUS_UNMET
    return {
        "status": status,
        "present": present,
        "missing": missing,
        "source_refs": [_rel(makefile, root)] if makefile.is_file() else [],
    }


def _workflow_coverage_evidence(root: Path) -> dict[str, Any]:
    path = _latest_existing(_workflow_map_paths(root))
    if path is None:
        return _status_evidence(STATUS_UNKNOWN, "no workflow coverage map output found")
    data = _read_json(path)
    if not isinstance(data, dict):
        return _status_evidence(STATUS_UNKNOWN, "workflow coverage map is unreadable", [_rel(path, root)])
    counts: Counter[str] = Counter()
    for item in _flatten(data.get("workflows", [])):
        if isinstance(item, str) and item in {"present", "unknown", "missing"}:
            counts[item] += 1
    present = counts.get("present", 0)
    missing = counts.get("missing", 0)
    unknown = counts.get("unknown", 0)
    if present and missing == 0 and unknown <= present:
        status = STATUS_MET
    elif present:
        status = STATUS_PARTIAL
    else:
        status = STATUS_UNMET
    return {
        "status": status,
        "reason": f"{present} present, {unknown} unknown, {missing} missing concept-workflow cells",
        "counts": dict(sorted(counts.items())),
        "source_refs": [_rel(path, root)],
    }


def _mining_dashboard_evidence(root: Path) -> dict[str, Any]:
    path = _latest_existing(_mining_dashboard_paths(root))
    if path is None:
        return _status_evidence(STATUS_UNKNOWN, "no mining coverage dashboard output found")
    data = _read_json(path)
    if not isinstance(data, dict):
        return _status_evidence(STATUS_UNKNOWN, "mining dashboard is unreadable", [_rel(path, root)])
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    total = int(summary.get("total_sources") or 0)
    fresh = int(summary.get("fresh") or 0)
    queued = int(summary.get("queued") or 0)
    stale = int(summary.get("stale") or 0)
    missing = int(summary.get("missing") or 0)
    backlog = int(summary.get("backlog") or 0)
    handled = fresh + queued
    if total and fresh == total and queued == 0 and stale == 0 and missing == 0 and backlog == 0:
        status = STATUS_MET
    elif total and handled > 0:
        status = STATUS_PARTIAL
    else:
        status = STATUS_UNMET
    return {
        "status": status,
        "reason": f"{fresh}/{total} fresh sources; queued={queued}, stale={stale}, missing={missing}, backlog={backlog}",
        "summary": summary,
        "source_refs": [_rel(path, root)],
    }


def _source_miner_evidence(root: Path, mining_evidence: dict[str, Any]) -> dict[str, Any]:
    tool_paths = [
        _rel(path, root)
        for path in sorted((root / "tools").glob("*.py"))
        if SOURCE_MINER_TOOL_RE.search(path.name)
    ] if (root / "tools").is_dir() else []
    mining_status = mining_evidence.get("status")
    backlog_report = _latest_report_file(root, "source_miner_backlog_actions*.json")
    backlog_payload = _read_json(backlog_report) if backlog_report is not None else None
    backlog_count = 0
    next_action_rows: list[dict[str, Any]] = []
    if isinstance(backlog_payload, dict):
        backlog_count = int(backlog_payload.get("active_backlog_count") or 0)
        next_action_rows = [
            _sanitize_nested_paths(row, root)
            for row in backlog_payload.get("next_action_rows") or []
            if isinstance(row, dict)
        ]
    if mining_status == STATUS_MET and len(tool_paths) >= 5:
        status = STATUS_MET
    elif tool_paths or mining_status in {STATUS_MET, STATUS_PARTIAL}:
        status = STATUS_PARTIAL
    else:
        status = STATUS_UNMET
    if backlog_count > 0:
        status = STATUS_PARTIAL
    reason = f"{len(tool_paths)} source/mining-like tool entrypoints found; mining dashboard status={mining_status}"
    if backlog_report is not None and isinstance(backlog_payload, dict):
        reason += f"; backlog_actions_active={backlog_count}"
    return {
        "status": status,
        "reason": reason,
        "tool_count": len(tool_paths),
        "active_backlog_count": backlog_count,
        "next_action_rows": next_action_rows[:20],
        "source_refs": tool_paths[:12] + mining_evidence.get("source_refs", []) + (
            [_rel(backlog_report, root)] if backlog_report is not None else []
        ),
    }


def _sidecar_coverage_evidence(root: Path) -> dict[str, Any]:
    path = _latest_existing(_sidecar_coverage_paths(root))
    if path is None:
        return _status_evidence(STATUS_UNMET, "no Hackerman sidecar coverage report found")
    data = _read_json(path)
    if not isinstance(data, dict):
        return _status_evidence(STATUS_UNKNOWN, "sidecar coverage report is unreadable", [_rel(path, root)])
    blockers = [str(value) for value in data.get("blockers") or []]
    sidecars = data.get("sidecars") if isinstance(data.get("sidecars"), list) else []
    coverage_values = [
        float(row.get("canonical_file_coverage_ratio") or 0.0)
        for row in sidecars
        if isinstance(row, dict) and row.get("exists")
    ]
    min_coverage = min(coverage_values) if coverage_values else 0.0
    corpus = data.get("corpus") if isinstance(data.get("corpus"), dict) else {}
    active_records = int(corpus.get("active_records") or 0)
    record_files = int(corpus.get("record_files_seen") or 0)
    if not sidecars:
        status = STATUS_UNMET
    elif blockers:
        status = STATUS_PARTIAL
    else:
        status = STATUS_MET
    return {
        "status": status,
        "reason": (
            f"{len(blockers)} sidecar coverage blockers; min canonical file coverage="
            f"{min_coverage:.3f}; active_records={active_records}; record_files={record_files}"
        ),
        "blockers": blockers,
        "min_canonical_file_coverage_ratio": round(min_coverage, 6),
        "sidecar_statuses": {
            str(row.get("name")): str(row.get("status"))
            for row in sidecars
            if isinstance(row, dict)
        },
        "source_refs": [_rel(path, root)],
    }


def _provider_keep_evidence(
    root: Path,
    provider_campaign: dict[str, Any] | None = None,
    workspace: Path | None = None,
) -> dict[str, Any]:
    provider_paths = _candidate_provider_paths(root, workspace)
    keep_files, keep_rows = _count_keep_rows(provider_paths)
    historical_verification_paths = [
        path for path in provider_paths
        if "local" in path.name.lower() and "verification" in path.name.lower() and path.suffix in {".json", ".jsonl"}
    ]
    backfill_root = workspace if workspace is not None else root
    backfill_result_paths = [backfill_root / ".auditooor" / "provider_keep_verification_backfill_result.json"]
    backfill_result_paths.extend(path for path in provider_paths if path.name == "provider_keep_verification_backfill_result.json")
    for path in sorted(set(backfill_result_paths), key=lambda p: str(p)):
        if path.is_file() and path not in historical_verification_paths:
            historical_verification_paths.append(path)
    selected_paths = _selected_provider_local_verification_paths(root, provider_campaign, workspace)
    verification_paths = selected_paths[:] if selected_paths else historical_verification_paths[:]
    if not selected_paths:
        for path in sorted(set(backfill_result_paths), key=lambda p: str(p)):
            if path.is_file() and path not in verification_paths:
                verification_paths.append(path)
    historical_evidence = _historical_local_verification_evidence(historical_verification_paths, root, workspace)
    backfill_packet_pending_rows = 0
    backfill_packet_total_rows = 0
    selected_ref_path = selected_paths[0] if selected_paths else None
    closure_packet_queue = _provider_closure_packet_queue_evidence(root, selected_ref_path, workspace)
    backfill_paths = [backfill_root / ".auditooor" / "provider_keep_verification_backfill.json"]
    backfill_paths.extend(path for path in provider_paths if path.name == "provider_keep_verification_backfill.json")
    for path in sorted(set(backfill_paths), key=lambda p: str(p)):
        if not path.is_file():
            continue
        data = _read_json(path)
        if isinstance(data, dict):
            backfill_packet_total_rows += len([p for p in data.get("packets") or [] if isinstance(p, dict)])
    summary = _local_verification_summary(verification_paths)
    status_counts: Counter[str] = summary["status_counts"]
    terminal_rows = int(summary["terminal_rows"])
    source_collection_required = int(summary["source_collection_required"])
    terminal_judgment_required = int(summary["terminal_judgment_required"])
    unresolved_rows = int(summary["unresolved_rows"])
    backfill_result_rows = int(summary["backfill_result_rows"])
    parsed_result_paths: list[Path] = summary["parsed_result_paths"]
    if not selected_paths and backfill_packet_total_rows and backfill_result_rows == 0:
        backfill_packet_pending_rows += backfill_packet_total_rows

    if parsed_result_paths or backfill_packet_pending_rows or backfill_packet_total_rows:
        unresolved = unresolved_rows + backfill_packet_pending_rows
        if keep_rows == 0 and sum(status_counts.values()) == 0:
            status = STATUS_UNKNOWN
            reason = "local-verification result artifacts exist but contain no provider rows"
        elif unresolved == 0 and (terminal_rows or status_counts.get("verified", 0) or status_counts.get("no_action", 0)):
            status = STATUS_MET
            reason = "local-verification result artifacts contain no pending/source/terminal-judgment rows"
        else:
            status = STATUS_PARTIAL
            reason = (
                "provider local-verification results still require closure: "
                f"status_counts={dict(sorted(status_counts.items()))}, "
                f"source_collection_required={source_collection_required}, "
                f"terminal_judgment_required={terminal_judgment_required}, "
                f"backfill_packet_pending={backfill_packet_pending_rows}, "
                f"unresolved_rows={unresolved}"
            )
        return {
            "status": status,
            "reason": reason,
            "keep_files": keep_files,
            "keep_mentions": keep_rows,
            "selected_local_verification_artifacts": [_rel(path, root, workspace) for path in selected_paths],
            "local_verification_artifacts": _verification_artifact_refs(
                verification_paths,
                parsed_result_paths,
                root,
                workspace,
            ),
            "verification_status_counts": dict(sorted(status_counts.items())),
            "terminal_outcome_rows": terminal_rows,
            "source_collection_required_rows": source_collection_required,
            "terminal_judgment_required_rows": terminal_judgment_required,
            "unresolved_rows": unresolved,
            "backfill_packet_pending_rows": backfill_packet_pending_rows,
            "backfill_packet_total_rows": backfill_packet_total_rows,
            "backfill_result_rows": backfill_result_rows,
            "closure_packet_queue": closure_packet_queue,
            "historical_local_verification_artifacts": historical_evidence,
        }

    verified_terms = 0
    pending_terms = 0
    for path in verification_paths:
        text = path.read_text(encoding="utf-8", errors="replace").lower()
        verified_terms += len(re.findall(r"\b(verified|terminal_outcome|proved|disproved|killed)\b", text))
        pending_terms += len(re.findall(r"\b(pending|needs_source_inspection|needs_local_verification)\b", text))
    if keep_rows == 0 and not verification_paths:
        status = STATUS_UNKNOWN
        reason = "no provider KEEP rows or local-verification artifacts found"
    elif keep_rows and verified_terms == 0:
        status = STATUS_UNMET
        reason = f"{keep_rows} KEEP_FOR_LOCAL_VERIFICATION mentions found without terminal local-verification evidence"
    elif verified_terms > 0 and pending_terms == 0:
        status = STATUS_MET
        reason = f"local-verification artifacts contain terminal verification signals for provider KEEP work"
    else:
        status = STATUS_PARTIAL
        reason = f"local-verification artifacts exist but still include pending verification signals"
    return {
        "status": status,
        "reason": reason,
        "keep_files": keep_files,
        "keep_mentions": keep_rows,
        "selected_local_verification_artifacts": [_rel(path, root, workspace) for path in selected_paths],
        "local_verification_artifacts": [_rel(path, root, workspace) for path in verification_paths[:8]],
        "closure_packet_queue": closure_packet_queue,
        "historical_local_verification_artifacts": historical_evidence,
    }


def _provider_closure_packet_queue_evidence(
    root: Path,
    selected_local_verification: Path | None = None,
    workspace: Path | None = None,
) -> dict[str, Any]:
    queue_root = workspace if workspace is not None else root
    candidates = [
        queue_root / ".auditooor" / "provider_closure_packet_queue.json",
        queue_root / ".auditooor" / "provider_source_collection_queue.json",
    ]
    provider_root = queue_root / ".auditooor" / "provider_fanout"
    if provider_root.is_dir():
        candidates.extend(provider_root.glob("**/provider_closure_packet_queue.json"))
        candidates.extend(provider_root.glob("**/provider_source_collection_queue.json"))
    path = _latest_existing(candidates)
    if path is None:
        return {"present": False}
    data = _read_json(path)
    if not isinstance(data, dict):
        return {"present": False, "source_refs": [_rel(path, root, workspace)], "reason": "closure packet queue is unreadable"}
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    source_rows = int(summary.get("source_rows") or 0)
    deduped_items = int(summary.get("deduped_items") or 0)
    terminal_rows = int(summary.get("terminal_judgment_rows") or 0)
    terminal_items = int(summary.get("terminal_judgment_items") or 0)
    queue_mtime = _mtime_or_zero(path)
    selected_mtime = _mtime_or_zero(selected_local_verification) if selected_local_verification is not None else 0.0
    stale = bool(selected_local_verification is not None and selected_mtime and queue_mtime and queue_mtime < selected_mtime)
    return {
        "present": True,
        "schema": data.get("schema"),
        "source_rows": source_rows,
        "deduped_items": deduped_items,
        "terminal_judgment_rows": terminal_rows,
        "terminal_judgment_items": terminal_items,
        "by_family": summary.get("by_family") if isinstance(summary.get("by_family"), dict) else {},
        "by_terminal_family": (
            summary.get("by_terminal_family")
            if isinstance(summary.get("by_terminal_family"), dict)
            else {}
        ),
        "source_refs": [_rel(path, root, workspace)],
        "stale": stale,
        "queue_mtime": queue_mtime,
        "selected_local_verification_ref": (
            _rel(selected_local_verification, root, workspace)
            if selected_local_verification is not None
            else ""
        ),
        "selected_local_verification_mtime": selected_mtime,
        "claim_guard": (
            "Remediation routing evidence only; unresolved provider rows stay unresolved "
            "until a local-verification result records terminal outcomes."
        ),
    }


def _provider_campaign_gate_paths(root: Path, workspace: Path | None) -> list[Path]:
    if workspace is not None:
        paths = [
            workspace / ".auditooor" / "v3_provider_campaign_completeness_gate.json",
            workspace / "reports" / "v3_provider_campaign_completeness_gate.json",
        ]
        provider_root = workspace / ".auditooor" / "provider_fanout"
        if provider_root.is_dir():
            paths.extend(provider_root.glob("**/v3_provider_campaign_completeness_gate.json"))
    else:
        paths = [
            root / ".auditooor" / "v3_provider_campaign_completeness_gate.json",
            root / "reports" / "v3_provider_campaign_completeness_gate.json",
        ]
        provider_root = root / ".auditooor" / "provider_fanout"
        if provider_root.is_dir():
            paths.extend(provider_root.glob("**/v3_provider_campaign_completeness_gate.json"))
    return paths


def _active_blocker_rows(root: Path, blocker_ids: set[str]) -> list[dict[str, Any]]:
    ledger = root / "reports" / "v3_blocker_ledger" / "blocker_ledger.json"
    data = _read_json(ledger)
    if not isinstance(data, dict):
        return []
    rows: list[dict[str, Any]] = []
    for row in data.get("blockers") or []:
        if not isinstance(row, dict):
            continue
        blocker_id = str(row.get("blocker_id") or row.get("id") or "")
        if blocker_id not in blocker_ids:
            continue
        status = str(row.get("status") or "")
        if status.startswith("closed"):
            continue
        rows.append(
            {
                "blocker_id": blocker_id,
                "status": status,
                "external_state_required": bool(row.get("external_state_required")),
                "next_action": row.get("next_action") or "",
            }
        )
    return rows


def _blocker_ledger_summary(root: Path, workspace: Path | None) -> dict[str, Any]:
    ledger = root / "reports" / "v3_blocker_ledger" / "blocker_ledger.json"
    data = _read_json(ledger)
    if not isinstance(data, dict):
        return {
            "status": "missing",
            "tracked_total": 0,
            "open_count": 0,
            "closed_count": 0,
            "external_state_required_open_count": 0,
            "local_actionable_open_count": 0,
            "source_refs": [],
        }

    rows = [row for row in data.get("blockers") or [] if isinstance(row, dict)]
    open_rows = []
    closed_rows = []
    for row in rows:
        status = str(row.get("status") or "")
        if status.startswith("closed"):
            closed_rows.append(row)
        else:
            open_rows.append(row)
    external_open = [row for row in open_rows if bool(row.get("external_state_required"))]
    local_open = [row for row in open_rows if not bool(row.get("external_state_required"))]

    return {
        "status": "present",
        "ledger_schema": data.get("schema", ""),
        "tracked_total": len(rows),
        "declared_blocker_count": data.get("blocker_count"),
        "open_count": len(open_rows),
        "declared_open_blocker_count": data.get("open_blocker_count"),
        "closed_count": len(closed_rows),
        "declared_closed_row_count": data.get("closed_row_count"),
        "external_state_required_open_count": len(external_open),
        "declared_external_state_required_open_count": data.get("external_state_required_open_count"),
        "local_actionable_open_count": len(local_open),
        "declared_local_actionable_open_count": data.get("local_actionable_open_count"),
        "open_blocker_ids": [
            str(row.get("blocker_id") or row.get("id") or "")
            for row in open_rows
            if row.get("blocker_id") or row.get("id")
        ],
        "local_actionable_open_ids": [
            str(row.get("blocker_id") or row.get("id") or "")
            for row in local_open
            if row.get("blocker_id") or row.get("id")
        ],
        "source_refs": [_rel(ledger, root, workspace)],
    }


def _provider_campaign_evidence(root: Path, workspace: Path | None) -> dict[str, Any]:
    path = _latest_existing(_provider_campaign_gate_paths(root, workspace))
    if path is None:
        return _status_evidence(STATUS_UNKNOWN, "no provider campaign completeness gate output found")
    data = _read_json(path)
    if not isinstance(data, dict):
        return _status_evidence(
            STATUS_UNKNOWN,
            "provider campaign completeness gate is unreadable",
            [_rel(path, root, workspace)],
        )
    gate_status = str(data.get("status") or data.get("verdict") or "unknown")
    artifacts = data.get("artifacts") if isinstance(data.get("artifacts"), dict) else {}
    selection = data.get("selection") if isinstance(data.get("selection"), dict) else {}
    blockers = [row for row in data.get("blockers") or [] if isinstance(row, dict)]
    warnings = [row for row in data.get("warnings") or [] if isinstance(row, dict)]
    non_blocking_warning_codes = {"broader_verification_results_excluded"}
    blocking_warnings = [
        row
        for row in warnings
        if str(row.get("code") or row.get("kind") or "") not in non_blocking_warning_codes
    ]
    expected_counts = data.get("expected_counts") if isinstance(data.get("expected_counts"), dict) else {}
    observed_counts = data.get("observed_counts") if isinstance(data.get("observed_counts"), dict) else {}
    status_counts = data.get("status_counts") if isinstance(data.get("status_counts"), dict) else {}
    active_provider_blockers = _active_blocker_rows(root, {"BLK-V3-PROVIDER-LIVE-DEPENDENCY-NOT-RESTORED"})
    unresolved_statuses = {"pending", "queued", "in_progress", "needs_more_source", "blocked"}
    unresolved_rows = 0
    for key, value in status_counts.items():
        if str(key).lower() in unresolved_statuses and isinstance(value, (int, float)):
            unresolved_rows += int(value)
    has_expected_counts = bool(expected_counts)
    has_observed_counts = bool(observed_counts)
    count_debt = has_expected_counts and not has_observed_counts

    gate_closed = (
        gate_status == "pass"
        and not blockers
        and not blocking_warnings
        and unresolved_rows == 0
        and not count_debt
    )
    if gate_closed:
        status = STATUS_MET
        reason = (
            "provider campaign completeness gate passed with no blockers, blocking warnings, unresolved rows, "
            "or count debt; known warnings are advisory"
        )
    elif gate_status == "fail" or blockers or blocking_warnings or unresolved_rows > 0 or count_debt:
        status = STATUS_PARTIAL
        reason = (
            "provider campaign completeness gate not fully closed: "
            f"status={gate_status}, blockers={len(blockers)}, blocking_warnings={len(blocking_warnings)}, "
            f"advisory_warnings={len(warnings) - len(blocking_warnings)}, "
            f"unresolved_rows={unresolved_rows}, expected_counts={int(has_expected_counts)}, "
            f"observed_counts={int(has_observed_counts)}"
        )
    else:
        status = STATUS_UNKNOWN
        reason = f"provider campaign completeness gate status={gate_status}"
    if active_provider_blockers:
        status = STATUS_PARTIAL
        reason = (
            "historical/default provider campaign accounting is present, but fresh live "
            "provider fanout remains externally blocked by the blocker ledger"
        )
    return {
        "status": status,
        "reason": reason,
        "campaign_id": data.get("campaign_id"),
        "gate_status": gate_status,
        "expected_counts": expected_counts,
        "observed_counts": observed_counts,
        "status_counts": status_counts,
        "unresolved_status_rows": unresolved_rows,
        "artifacts": _sanitize_nested_paths(artifacts, root, workspace),
        "selection": _sanitize_nested_paths(selection, root, workspace),
        "blockers": _sanitize_nested_paths(blockers, root, workspace),
        "warnings": _sanitize_nested_paths(warnings, root, workspace),
        "blocking_warnings": _sanitize_nested_paths(blocking_warnings, root, workspace),
        "advisory_warning_codes": sorted(
            str(row.get("code") or row.get("kind") or "")
            for row in warnings
            if row not in blocking_warnings
        ),
        "current_blockers": _sanitize_nested_paths(active_provider_blockers, root, workspace),
        "remediation_evidence": _sanitize_nested_paths(data.get("remediation_evidence", {}), root, workspace),
        "source_refs": [_rel(path, root, workspace)],
    }


def _field_validation_evidence(root: Path, workspace: Path | None) -> dict[str, Any]:
    path = _first_existing(_field_validation_paths(root, workspace))
    if path is None:
        return _status_evidence(STATUS_UNMET, "no field-validation report found")
    data = _read_json(path)
    if not isinstance(data, dict):
        return _status_evidence(
            STATUS_UNKNOWN,
            "field-validation report is unreadable",
            [_rel(path, root, workspace)],
        )
    readiness = data.get("readiness") if isinstance(data.get("readiness"), dict) else {}
    ready_sections = int(readiness.get("ready_sections") or 0)
    readiness_status = str(readiness.get("status") or "")
    signal_groups = data.get("signal_groups") if isinstance(data.get("signal_groups"), dict) else {}
    missing_artifacts: list[dict[str, Any]] = []
    next_commands: list[str] = []
    for group in signal_groups.values():
        if not isinstance(group, dict):
            continue
        for artifact in group.get("missing_artifacts") or []:
            if isinstance(artifact, dict):
                missing_artifacts.append(_sanitize_guidance(artifact, root, workspace))
        for command in group.get("next_commands") or []:
            if isinstance(command, str) and command:
                sanitized_command = _sanitize_command(command, root, workspace)
                if sanitized_command not in next_commands:
                    next_commands.append(sanitized_command)
    field_loop_next_steps = [
        _sanitize_guidance(row, root, workspace) for row in readiness.get("field_loop_next_steps") or []
        if isinstance(row, dict)
    ]
    blocking_unknowns = readiness.get("blocking_unknowns", [])
    has_unknowns = isinstance(blocking_unknowns, list) and bool(blocking_unknowns)
    platform_id_gaps = _field_validation_platform_id_gap_evidence(root, workspace)
    platform_id_gap_rows = int(platform_id_gaps.get("gap_rows") or 0)
    platform_id_next_action_rows = [
        row for row in platform_id_gaps.get("next_action_rows") or [] if isinstance(row, dict)
    ]
    if platform_id_gap_rows > 0:
        missing_artifacts.append(
            {
                "artifact": "platform-id outcome backfill rows",
                "expected_paths": ["reference/outcomes.jsonl"],
                "source": "field_validation_platform_id_gaps",
                "remaining_rows": platform_id_gap_rows,
            }
        )
        for row in platform_id_next_action_rows:
            command = row.get("command")
            if isinstance(command, str) and command:
                sanitized = _sanitize_command(command, root, workspace)
                if sanitized not in next_commands:
                    next_commands.append(sanitized)
    gate_closed = (
        readiness_status == "field_validation_ready_for_evaluation"
        and ready_sections >= 3
        and not has_unknowns
        and platform_id_gap_rows == 0
        and not missing_artifacts
        and not field_loop_next_steps
    )
    if gate_closed:
        status = STATUS_MET
    elif ready_sections > 0:
        status = STATUS_PARTIAL
    else:
        status = STATUS_UNMET
    return {
        "status": status,
        "reason": (
            f"field-validation readiness={readiness_status or 'unknown'} ({ready_sections}/3 ready sections); "
            f"blocking_unknowns={len(blocking_unknowns) if isinstance(blocking_unknowns, list) else 0}, "
            f"missing_artifacts={len(missing_artifacts)}, next_steps={len(field_loop_next_steps)}, "
            f"platform_id_gap_rows={platform_id_gap_rows}"
        ),
        "readiness": _sanitize_guidance(readiness, root, workspace),
        "blocking_unknowns": blocking_unknowns if isinstance(blocking_unknowns, list) else [],
        "missing_artifacts": missing_artifacts[:20],
        "field_loop_next_steps": field_loop_next_steps[:20],
        "platform_id_gap_rows": platform_id_gap_rows,
        "platform_id_next_action_rows": platform_id_next_action_rows[:20],
        "next_commands": next_commands[:20],
        "source_refs": [_rel(path, root, workspace)] + [
            ref for ref in platform_id_gaps.get("source_refs", []) if isinstance(ref, str)
        ],
    }


def _lesson_gate_evidence(root: Path) -> dict[str, Any]:
    targets = _parse_make_targets(root / "Makefile")
    target_hits = [
        target
        for target in ("lesson-source-inventory", "lesson-enforcement-inventory", "agent-artifact-lesson-candidates")
        if target in targets
    ]
    tool_hits = [
        rel
        for rel in (
            "tools/lesson-source-inventory.py",
            "tools/v3-provider-learning-compiler.py",
            "tools/agent-artifact-miner.py",
        )
        if (root / rel).is_file()
    ]
    report_hits = [path for path in (root / ".auditooor").glob("*lesson*.json")] if (root / ".auditooor").is_dir() else []
    source_inventory_paths = [
        root / ".auditooor" / "lesson_source_inventory.json",
        root / "reports" / "lesson_source_inventory.json",
    ]
    source_inventory_path = _latest_existing(source_inventory_paths)
    coverage_blockers: list[dict[str, Any]] = []
    source_summary: dict[str, Any] = {}
    if source_inventory_path is not None:
        source_payload = _read_json(source_inventory_path)
        if isinstance(source_payload, dict):
            coverage_blockers = [row for row in source_payload.get("coverage_blockers") or [] if isinstance(row, dict)]
            if isinstance(source_payload.get("summary"), dict):
                source_summary = source_payload["summary"]
    if coverage_blockers:
        status = STATUS_PARTIAL
    elif len(target_hits) >= 3 and len(tool_hits) >= 3 and report_hits:
        status = STATUS_MET
    elif target_hits or tool_hits or report_hits:
        status = STATUS_PARTIAL
    else:
        status = STATUS_UNMET
    reason = f"{len(target_hits)} lesson Make targets, {len(tool_hits)} lesson tools, {len(report_hits)} lesson sidecars"
    if source_inventory_path is not None:
        reason += f"; source coverage blockers={len(coverage_blockers)}"
    return {
        "status": status,
        "reason": reason,
        "source_inventory_summary": _sanitize_nested_paths(source_summary, root),
        "source_coverage_blockers": _sanitize_nested_paths(coverage_blockers[:12], root),
        "source_refs": target_hits + tool_hits + [_rel(path, root) for path in report_hits[:6]],
    }


def _real_hunt_evidence(root: Path, workspace: Path | None, field_evidence: dict[str, Any]) -> dict[str, Any]:
    candidate_roots = [root / "submissions", root / "audits", root / "reports"]
    if workspace is not None:
        candidate_roots.extend([workspace / "submissions", workspace / "poc_execution"])
    evidence_files: list[Path] = []
    for base in candidate_roots:
        if base.is_dir():
            evidence_files.extend(
                path for path in base.rglob("*")
                if path.is_file() and path.suffix in {".md", ".json", ".jsonl"}
                and path.name not in {"field_validation_report.json", "field_validation_report.md"}
                and re.search(r"(submitted|filed|outcome|execution_manifest|field_validation|hunt)", path.name, re.IGNORECASE)
            )
    field_status = field_evidence.get("status")
    if field_status == STATUS_MET and evidence_files:
        status = STATUS_MET
    elif evidence_files or field_status == STATUS_PARTIAL:
        status = STATUS_PARTIAL
    else:
        status = STATUS_UNMET
    return {
        "status": status,
        "reason": f"{len(evidence_files)} local real-hunt/outcome/proof evidence files; field-validation status={field_status}",
        "missing_artifacts": field_evidence.get("missing_artifacts", [])[:20],
        "field_loop_next_steps": field_evidence.get("field_loop_next_steps", [])[:20],
        "platform_id_next_action_rows": field_evidence.get("platform_id_next_action_rows", [])[:20],
        "next_commands": field_evidence.get("next_commands", [])[:20],
        "source_refs": [_rel(path, root, workspace) for path in sorted(evidence_files, key=lambda p: str(p))[:10]],
    }


def _provider_telemetry_evidence(root: Path) -> dict[str, Any]:
    counts = _count_dispatch_rows(root)
    total = int(counts["dispatch_files"]) + int(counts["budget_log_rows"])
    if total >= 10 and counts["dispatch_by_provider"]:
        status = STATUS_MET
    elif total > 0:
        status = STATUS_PARTIAL
    else:
        status = STATUS_UNMET
    return {
        "status": status,
        "reason": f"{counts['dispatch_files']} dispatch records and {counts['budget_log_rows']} budget rows found",
        "counts": counts,
        "source_refs": counts["source_refs"] + (["tools/calibration/llm_budget_log.jsonl"] if counts["budget_log_rows"] else []),
    }


def _latest_report_file(root: Path, pattern: str) -> Path | None:
    reports = root / "reports"
    if not reports.is_dir():
        return None
    matches = [path for path in reports.rglob(pattern) if path.is_file()]
    if not matches:
        return None
    return max(matches, key=lambda path: path.stat().st_mtime)


def _field_validation_platform_id_gap_evidence(root: Path, workspace: Path | None) -> dict[str, Any]:
    candidates: list[Path] = []
    if workspace is not None:
        candidates.extend(
            [
                workspace / ".auditooor" / "field_validation_platform_id_gaps.json",
                workspace / "reports" / "field_validation_platform_id_gaps.json",
            ]
        )
        latest_lane = _latest_report_file(root, "field_validation_platform_id_gaps*.json")
        if latest_lane is not None:
            candidates.append(latest_lane)
    candidates.extend(
        [
            root / ".auditooor" / "field_validation_platform_id_gaps.json",
            root / "reports" / "field_validation_platform_id_gaps.json",
        ]
    )
    if workspace is None:
        latest_lane = _latest_report_file(root, "field_validation_platform_id_gaps*.json")
        if latest_lane is not None:
            candidates.append(latest_lane)
    path = None
    payload: dict[str, Any] | None = None
    unreadable: Path | None = None
    for candidate in candidates:
        if not candidate.is_file():
            continue
        candidate_payload = _read_json(candidate)
        if not isinstance(candidate_payload, dict):
            unreadable = candidate
            break
        if not _field_validation_gap_report_applies(candidate_payload, candidate, root, workspace):
            continue
        path = candidate
        payload = candidate_payload
        break
    if path is None or payload is None:
        if unreadable is not None:
            return {
                "gap_rows": 0,
                "next_action_rows": [],
                "source_refs": [_rel(unreadable, root, workspace)],
                "unreadable": True,
            }
        return {"gap_rows": 0, "next_action_rows": [], "source_refs": []}
    counts = payload.get("counts") if isinstance(payload.get("counts"), dict) else {}
    gap_rows = int(counts.get("gap_rows") or 0)
    next_action_rows = [
        _sanitize_nested_paths(row, root, workspace)
        for row in payload.get("next_action_rows") or []
        if isinstance(row, dict)
    ]
    return {
        "gap_rows": gap_rows,
        "next_action_rows": next_action_rows,
        "source_refs": [_rel(path, root, workspace)],
    }


def _field_validation_gap_report_applies(
    payload: dict[str, Any],
    path: Path,
    root: Path,
    workspace: Path | None,
) -> bool:
    workspace_value = payload.get("workspace")
    if isinstance(workspace_value, str) and workspace_value.strip():
        scoped_workspace = Path(workspace_value).expanduser()
        try:
            scoped_workspace = scoped_workspace.resolve()
        except OSError:
            pass
        expected = workspace if workspace is not None else root
        try:
            expected = expected.resolve()
        except OSError:
            pass
        return scoped_workspace == expected
    if workspace is None:
        return True
    try:
        path.resolve().relative_to(workspace)
    except ValueError:
        return False
    return True


def _count_jsonl_records(path: Path) -> int:
    return len(_read_jsonl(path))


def _p2_index_candidates(root: Path) -> list[Path]:
    candidates = [root / "audit" / "corpus_tags" / "derived" / "causal_chain_index.json"]
    reports = root / "reports"
    if reports.is_dir():
        candidates.extend(path for path in reports.rglob("causal_chain_index*.json") if path.is_file())
    return sorted(set(candidates), key=lambda p: str(p))


def _p2_current_quality_missing_requirements(quality_gate: dict[str, Any]) -> list[str]:
    requirements = {
        str(value)
        for value in quality_gate.get("requirements") or []
        if isinstance(value, str)
    }
    return [req for req in P2_CANONICAL_QUALITY_REQUIREMENTS if req not in requirements]


def _p2_load_index_candidates(root: Path) -> list[tuple[Path, dict[str, Any]]]:
    loaded: list[tuple[Path, dict[str, Any]]] = []
    for path in _p2_index_candidates(root):
        if not path.is_file():
            continue
        payload = _read_json(path)
        if isinstance(payload, dict):
            loaded.append((path, payload))
    return loaded


def _p2_select_index(root: Path) -> tuple[Path | None, dict[str, Any]]:
    loaded = _p2_load_index_candidates(root)
    if not loaded:
        return None, {}
    current_quality = [
        (path, payload)
        for path, payload in loaded
        if isinstance(payload.get("quality_gate"), dict)
        and not _p2_current_quality_missing_requirements(payload["quality_gate"])
    ]
    candidates = current_quality or loaded
    return max(candidates, key=lambda item: (_mtime_or_zero(item[0]), str(item[0])))


def _p2_companion_chain_paths(index_path: Path | None, canonical_path: Path) -> list[Path]:
    canonical_index_path = canonical_path.with_name("causal_chain_index.json")
    paths = []
    if index_path is None or index_path == canonical_index_path:
        paths.append(canonical_path)
    if index_path is not None:
        paths.extend(
            [
                index_path.with_name("causal_chains.canonical.jsonl"),
                index_path.with_name("causal_chains.jsonl"),
            ]
        )
    seen: set[Path] = set()
    unique: list[Path] = []
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        unique.append(path)
    return unique


def _pillar_p1_evidence(root: Path) -> dict[str, Any]:
    index_path = root / "audit" / "corpus_tags" / "derived" / "invariant_library_index.json"
    extracted_path = root / "audit" / "corpus_tags" / "derived" / "invariants_extracted.jsonl"
    pilot_path = root / "audit" / "corpus_tags" / "derived" / "invariants_pilot.jsonl"
    audited_path = root / "audit" / "corpus_tags" / "derived" / "invariants_pilot_audited.jsonl"
    source_refs: list[str] = []
    total = 0
    index = _read_json(index_path)
    if isinstance(index, dict):
        total = int(index.get("total_invariants") or 0)
        source_refs.append(_rel(index_path, root))
    if total == 0:
        total = _count_jsonl_records(extracted_path) + _count_jsonl_records(pilot_path)
        if extracted_path.is_file():
            source_refs.append(_rel(extracted_path, root))
        if pilot_path.is_file():
            source_refs.append(_rel(pilot_path, root))

    quality_path = _latest_report_file(root, "library_quality_audit.json")
    quality: dict[str, Any] = {}
    if quality_path is not None:
        payload = _read_json(quality_path)
        if isinstance(payload, dict):
            quality = payload
            source_refs.append(_rel(quality_path, root))
    tp_rate = quality.get("overall_tp_rate_pct")
    threshold = quality.get("tp_rate_threshold_pct", 80.0)
    broad_quality_met = isinstance(tp_rate, (int, float)) and float(tp_rate) >= float(threshold)

    audited_count = _count_jsonl_records(audited_path) if audited_path.is_file() else 0
    if audited_path.is_file():
        source_refs.append(_rel(audited_path, root))

    routing_files = {
        "vault_invariant_library": root / "tools" / "vault-mcp-server.py",
        "dispatch_prebriefing": root / "tools" / "dispatch-agent-with-prebriefing.py",
        "live_target_intel": root / "tools" / "live-target-intelligence-report.py",
        "r58_invariant_gate": root / "tools" / "invariant-grounded-finding-check.py",
        "p1_candidate_triage": root / "tools" / "p1-candidate-triage-dogfood.py",
    }
    routing_hits: dict[str, bool] = {}
    for label, path in routing_files.items():
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            routing_hits[label] = False
            continue
        if label == "vault_invariant_library":
            routing_hits[label] = "quality_mode" in text and "audited_primary" in text and "invariants_pilot_audited.jsonl" in text
        elif label == "dispatch_prebriefing":
            routing_hits[label] = "quality_mode" in text and "audited_primary" in text and "vault_invariant_library" in text
        elif label == "live_target_intel":
            routing_hits[label] = "invariants_pilot_audited.jsonl" in text and "breadth_paths" in text
        elif label == "r58_invariant_gate":
            routing_hits[label] = "DEFAULT_PILOT_AUDITED" in text and "cited_audited_invariant_ids" in text
        else:
            routing_hits[label] = (
                "DEFAULT_AUDITED_PRIMARY" in text
                and "invariants_pilot_audited.jsonl" in text
                and "include_extracted" in text
                and "opt_in_only" in text
            )
        if routing_hits[label]:
            source_refs.append(_rel(path, root))

    audited_primary_quality_met = audited_count >= 50 and all(routing_hits.values())
    llm_sweep = _p1_llm_sweep_quality_evidence(root)
    if llm_sweep["source_refs"]:
        source_refs.extend(llm_sweep["source_refs"])
    quality_met = broad_quality_met or audited_primary_quality_met

    if total >= PILLAR_TARGETS["p1_invariants_mvp"] and quality_met:
        status = STATUS_MET
        if broad_quality_met:
            reason = f"{total} invariants and P1 broad quality gate passed ({tp_rate}% >= {threshold}%)"
        else:
            reason = (
                f"{total} invariants available; audited-primary route closed with "
                f"{audited_count} retained audited rows and required consumers wired"
            )
    elif total > 0:
        status = STATUS_PARTIAL
        if audited_count and not audited_primary_quality_met:
            missing_routes = [name for name, ok in routing_hits.items() if not ok]
            reason = (
                f"{total} invariants present and {audited_count} audited rows found, "
                f"but audited-primary routing is incomplete: {missing_routes}"
            )
        elif tp_rate is None:
            reason = f"{total} invariants present, but no P1 quality audit or audited-primary closure was found"
        else:
            reason = f"{total} invariants present, but P1 quality gate is not closed ({tp_rate}% < {threshold}%)"
    else:
        status = STATUS_UNMET
        reason = "no invariant library records found"
    return {
        "status": status,
        "reason": reason,
        "target_records": PILLAR_TARGETS["p1_invariants_mvp"],
        "observed_records": total,
        "quality_gate": {
            "tp_rate_pct": tp_rate,
            "threshold_pct": threshold,
            "met": quality_met,
            "broad_quality_met": broad_quality_met,
            "verdict": quality.get("library_verdict"),
            "llm_sweep": llm_sweep,
            "audited_primary": {
                "retained_rows": audited_count,
                "met": audited_primary_quality_met,
                "routing_hits": routing_hits,
                "assumed_retained_tp_rate_pct": 100.0 if audited_count else None,
            },
        },
        "source_refs": source_refs,
    }


def _p1_llm_sweep_quality_evidence(root: Path) -> dict[str, Any]:
    tool_path = root / "tools" / "llm-sweep-invariants-mvp.py"
    lane_dir = root / "reports" / "v3_iter_2026-05-24" / "lane_P1_LLM_SWEEP_MVP"
    fallback_input_path = root / "audit" / "corpus_tags" / "derived" / "invariants_extracted.jsonl"
    fallback_output_path = root / "audit" / "corpus_tags" / "derived" / "invariants_extracted_llm_v1.jsonl"
    fallback_log_path = lane_dir / "sweep_log.jsonl"
    full_input_path = lane_dir / "p1_full_library_sweep_input.jsonl"
    full_output_path = root / "audit" / "corpus_tags" / "derived" / "invariants_full_library_llm_v1.jsonl"
    full_log_path = lane_dir / "sweep_log_full_library.jsonl"
    summary_path = lane_dir / "sweep_summary.json"
    status_path = lane_dir / "sweep_status.json"
    full_library_visible = any(path.is_file() for path in (full_input_path, full_output_path, full_log_path))
    coverage_scope = "full_library" if full_library_visible else "extracted_400"
    input_path = full_input_path if full_library_visible else fallback_input_path
    output_path = full_output_path if full_library_visible else fallback_output_path
    log_path = full_log_path if full_library_visible else fallback_log_path
    refs = [_rel(path, root) for path in (tool_path, input_path, output_path, log_path, summary_path, status_path) if path.is_file()]
    tool_text = ""
    try:
        tool_text = tool_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    input_rows = _count_jsonl_records(input_path) if input_path.is_file() else 0
    output_rows = _count_jsonl_records(output_path) if output_path.is_file() else 0
    log_rows = _read_jsonl(log_path) if log_path.is_file() else []
    gate_markers_present = (
        "evaluate_paid_sweep_gate" in tool_text
        and "MIN_PROMOTION_Y_RATE" in tool_text
        and "disallow_template_or_broad=True" in tool_text
    )
    passed_rows = sum(1 for row in log_rows if row.get("quality_gate", {}).get("passed") is True)
    failed_rows = sum(1 for row in log_rows if row.get("quality_gate", {}).get("passed") is False)
    summary = _read_json(summary_path) if summary_path.is_file() else {}
    status_payload = _read_json(status_path) if status_path.is_file() else {}
    summary_after = summary.get("after_spot_check") if isinstance(summary, dict) else {}
    summary_scope = str(summary.get("coverage_scope") or summary.get("scope") or "") if isinstance(summary, dict) else ""
    status_scope = (
        str(status_payload.get("coverage_scope") or status_payload.get("scope") or "")
        if isinstance(status_payload, dict)
        else ""
    )
    summary_promotion_allowed = bool(isinstance(summary, dict) and summary.get("promotion_allowed") is True)
    if isinstance(summary_after, dict) and summary_after.get("promotion_allowed") is True:
        summary_promotion_allowed = True
    status_live_completed = bool(
        isinstance(status_payload, dict)
        and (
            status_payload.get("live_sweep_completed") is True
            or status_payload.get("sweep_completed") is True
            or status_payload.get("status") in {"complete", "completed", "passed", "success"}
        )
    )
    min_y_rate = (
        float(summary.get("min_promotion_y_rate"))
        if isinstance(summary, dict) and isinstance(summary.get("min_promotion_y_rate"), (int, float))
        else 0.9 if "MIN_PROMOTION_Y_RATE" in tool_text else None
    )
    after_y_rate = (
        float(summary_after.get("y_rate"))
        if isinstance(summary_after, dict) and isinstance(summary_after.get("y_rate"), (int, float))
        else None
    )
    template_or_broad_count = (
        int(summary_after.get("template_or_broad_count") or 0)
        if isinstance(summary_after, dict)
        else None
    )
    expected_rows = input_rows or output_rows
    count_gate_ok = bool(output_rows and log_rows and len(log_rows) >= output_rows)
    if full_library_visible and input_rows:
        count_gate_ok = count_gate_ok and output_rows >= input_rows
    scope_matches_summary = not summary_scope or summary_scope == coverage_scope
    scope_matches_status = not status_scope or status_scope == coverage_scope
    met = bool(
        output_rows
        and count_gate_ok
        and failed_rows == 0
        and scope_matches_summary
        and scope_matches_status
        and (
            (passed_rows > 0)
            or (
                summary_promotion_allowed
                and (status_live_completed or not status_path.is_file())
                and after_y_rate is not None
                and min_y_rate is not None
                and after_y_rate >= min_y_rate
                and (template_or_broad_count or 0) == 0
            )
        )
    )
    if met:
        status = "passed"
        reason = (
            f"LLM sweep output has {output_rows} rows and post-sweep promotion gate passed "
            f"({after_y_rate if after_y_rate is not None else 'logged'} >= {min_y_rate})"
        )
    elif gate_markers_present:
        status = "gate_implemented_not_promoted"
        reason = (
            f"LLM sweep quality gate implementation is visible for {coverage_scope}, "
            "but no promoted passing sweep output is present"
        )
    else:
        status = "not_visible"
        reason = "no LLM sweep quality gate evidence found"
    return {
        "status": status,
        "met": met,
        "coverage_scope": coverage_scope,
        "full_library_artifacts_present": full_library_visible,
        "gate_markers_present": gate_markers_present,
        "input_records": input_rows,
        "output_records": output_rows,
        "log_records": len(log_rows),
        "expected_records": expected_rows,
        "logged_gate_pass_rows": passed_rows,
        "logged_gate_fail_rows": failed_rows,
        "summary_promotion_allowed": summary_promotion_allowed,
        "status_live_completed": status_live_completed,
        "summary_scope": summary_scope,
        "status_scope": status_scope,
        "scope_matches_summary": scope_matches_summary,
        "scope_matches_status": scope_matches_status,
        "after_y_rate": after_y_rate,
        "template_or_broad_count": template_or_broad_count,
        "min_promotion_y_rate": min_y_rate,
        "reason": reason,
        "source_refs": refs,
    }


def _pillar_p2_evidence(root: Path) -> dict[str, Any]:
    chains_path = root / "audit" / "corpus_tags" / "derived" / "causal_chains.jsonl"
    tool_path = root / "tools" / "causal-chain-extract.py"
    legacy_tool_path = root / "tools" / "llm-extract-causal-chains.py"
    mvp_sample_path = (
        root / "reports" / "v3_iter_2026-05-24" / "lane_V3_P2_CAUSAL_CHAIN_MVP" / "causal_chains_sample.jsonl"
    )
    mvp_index_path = root / "reports" / "v3_iter_2026-05-24" / "lane_V3_P2_CAUSAL_CHAIN_MVP" / "index.json"
    index_path, index_payload = _p2_select_index(root)
    count = 0
    if index_path is not None and isinstance(index_payload, dict):
        count = int(index_payload.get("row_count") or 0)
    if count == 0 and chains_path.is_file():
        count = _count_jsonl_records(chains_path)
    mvp_count = _count_jsonl_records(mvp_sample_path) if mvp_sample_path.is_file() else 0
    quality_gate = index_payload.get("quality_gate") if isinstance(index_payload, dict) else {}
    quality_profile = quality_gate.get("profile") if isinstance(quality_gate, dict) else None
    quality_met = bool(isinstance(quality_gate, dict) and quality_gate.get("met"))
    quality_target = int(PILLAR_TARGETS["p2_causal_chains_mvp"])
    quality_accepted = int(quality_gate.get("accepted_rows") or 0) if isinstance(quality_gate, dict) else 0
    missing_quality_requirements = (
        _p2_current_quality_missing_requirements(quality_gate)
        if isinstance(quality_gate, dict)
        else list(P2_CANONICAL_QUALITY_REQUIREMENTS)
    )
    source_refs = [
        _rel(path, root)
        for path in (
            *_p2_companion_chain_paths(index_path, chains_path),
            index_path,
            tool_path,
            legacy_tool_path,
            mvp_sample_path,
            mvp_index_path,
        )
        if path is not None
        if path.is_file()
    ]
    has_tool = tool_path.is_file() or legacy_tool_path.is_file()
    canonical_quality_closed = (
        index_path is not None
        and index_path.is_file()
        and quality_profile in {"canonical", "strict"}
        and quality_met
        and quality_accepted >= quality_target
        and not missing_quality_requirements
    )
    has_index = index_path is not None and index_path.is_file()
    if count >= quality_target and has_index and has_tool and canonical_quality_closed:
        status = STATUS_MET
        reason = (
            f"{count} canonical causal-chain records plus index/tool present; "
            f"current quality gate closed ({quality_profile}, accepted={quality_accepted})"
        )
    elif count >= quality_target and has_index and has_tool:
        status = STATUS_PARTIAL
        if not quality_gate:
            reason = (
                f"{count} canonical causal-chain rows are present, but canonical quality gate is not closed "
                "(quality gate missing)"
            )
        elif missing_quality_requirements:
            reason = (
                f"{count} canonical causal-chain rows are present, but the selected quality gate is stale "
                f"for current extractor requirements; missing={missing_quality_requirements}"
            )
        else:
            reason = (
                f"{count} canonical causal-chain rows are present, but canonical quality gate is not closed "
                f"(profile={quality_profile or 'missing'}, accepted={quality_accepted}/{quality_target}, met={quality_met})"
            )
    elif count > 0 or mvp_count > 0 or has_index or mvp_index_path.is_file() or has_tool:
        status = STATUS_PARTIAL
        observed = count or mvp_count
        reason = (
            f"P2 is partially present ({observed}/{PILLAR_TARGETS['p2_causal_chains_mvp']} "
            "causal-chain records in canonical/sample artifacts); full promoted corpus index is not closed"
        )
    else:
        status = STATUS_UNMET
        reason = "P2 causal-chain extraction is still deferred; no causal_chains.jsonl/tool/index found"
    return {
        "status": status,
        "reason": reason,
        "target_records": PILLAR_TARGETS["p2_causal_chains_mvp"],
        "observed_records": count,
        "sample_records": mvp_count,
        "quality_gate": quality_gate if isinstance(quality_gate, dict) else {},
        "quality_gate_current_requirements_met": not missing_quality_requirements,
        "quality_gate_missing_requirements": missing_quality_requirements,
        "selected_index_ref": _rel(index_path, root) if index_path is not None else "",
        "source_refs": source_refs,
    }


def _pillar_p3_evidence(root: Path) -> dict[str, Any]:
    catalog_root = root / "obsidian-vault" / "anti-patterns" / "v2"
    pattern_files = sorted(catalog_root.rglob("*.yaml")) if catalog_root.is_dir() else []
    solidity_count = sum(1 for path in pattern_files if "/solidity/" in path.as_posix())
    slither_detector_count = 0
    query_type_counts: Counter[str] = Counter()
    for path in pattern_files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        match = re.search(r"^query_type:\s*([A-Za-z0-9_-]+)\s*$", text, re.MULTILINE)
        query_type = match.group(1) if match else "unknown"
        query_type_counts[query_type] += 1
        if query_type == "slither-detector":
            slither_detector_count += 1
    tool_path = root / "tools" / "antipattern-catalog-build.py"
    tool_text = ""
    try:
        tool_text = tool_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    semantic_command_plan_count = sum(query_type_counts.get(query_type, 0) for query_type in P3_COMMAND_PLAN_QUERY_TYPES)
    grep_records = query_type_counts.get("grep", 0)
    command_plan_support_present = (
        "SEMANTIC_COMMAND_PLAN_QUERY_TYPES" in tool_text
        and "query_degraded" in tool_text
        and "command_plan" in tool_text
    )
    unsupported_query_records = slither_detector_count
    if semantic_command_plan_count and not command_plan_support_present:
        unsupported_query_records += semantic_command_plan_count
    target = PILLAR_TARGETS["p3_antipatterns_mvp_min"]
    if len(pattern_files) >= target and unsupported_query_records == 0 and tool_path.is_file():
        status = STATUS_MET
        if semantic_command_plan_count:
            reason = (
                f"{len(pattern_files)} anti-patterns meet the MVP floor; "
                f"{semantic_command_plan_count} non-grep query rows have degraded command-plan adapters "
                "rather than full executable query proof"
            )
        else:
            reason = f"{len(pattern_files)} anti-patterns meet the MVP floor with no unsupported query records"
    elif pattern_files:
        status = STATUS_PARTIAL
        reason = (
            f"{len(pattern_files)}/{target}+ anti-patterns present "
            f"({solidity_count} Solidity); {unsupported_query_records} query records remain unsupported/degraded"
        )
    else:
        status = STATUS_UNMET
        reason = "no P3 anti-pattern catalog records found"
    refs = [_rel(tool_path, root)] if tool_path.is_file() else []
    refs.extend(_rel(path, root) for path in pattern_files[:10])
    return {
        "status": status,
        "reason": reason,
        "target_records_min": target,
        "observed_records": len(pattern_files),
        "total_catalog_records": len(pattern_files),
        "executable_query_records": grep_records,
        "degraded_command_plan_records": semantic_command_plan_count if command_plan_support_present else 0,
        "solidity_records": solidity_count,
        "slither_detector_records": slither_detector_count,
        "query_type_counts": dict(sorted(query_type_counts.items())),
        "semantic_command_plan_records": semantic_command_plan_count,
        "command_plan_support_present": command_plan_support_present,
        "unsupported_query_records": unsupported_query_records,
        "query_execution_status": (
            "degraded_command_plan"
            if semantic_command_plan_count and command_plan_support_present
            else "grep_only"
            if unsupported_query_records == 0
            else "unsupported_or_missing_adapter"
        ),
        "source_refs": refs,
    }


def _pillar_p4_evidence(root: Path) -> dict[str, Any]:
    rules_tool = root / "tools" / "triager-pre-filing-simulator.py"
    schema_helper = root / "tools" / "lib" / "triager_precheck_schema.py"
    pattern_json = root / "reference" / "triager_patterns.json"
    mcp_server = root / "tools" / "vault-mcp-server.py"
    mcp_text = ""
    rules_text = ""
    try:
        mcp_text = mcp_server.read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    try:
        rules_text = rules_tool.read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    has_rules_mvp = rules_tool.is_file() and schema_helper.is_file() and pattern_json.is_file()
    has_precheck_rules_mcp = "vault_triager_precheck_rules" in mcp_text
    simulate_callable_present = "vault_triager_simulate" in mcp_text and rules_tool.is_file()
    provider_reports = sorted(root.glob("reports/**/provider_prereq_resolution.json"))
    latest_provider_report = max(provider_reports, key=lambda p: p.stat().st_mtime) if provider_reports else None
    provider_recheck_path = root / "reports" / "v3_iter_2026-05-24" / "lane_P4_PROVIDER_BACKED_RECHECK" / "summary.json"
    provider_recheck = _read_json(provider_recheck_path) if provider_recheck_path.is_file() else None
    provider_blockers: list[str] = []
    if isinstance(provider_recheck, dict):
        for row in provider_recheck.get("primary_blockers") or []:
            if isinstance(row, dict) and row.get("blocker"):
                provider_blockers.append(str(row["blocker"]))
    if latest_provider_report is not None:
        payload = _read_json(latest_provider_report)
        if isinstance(payload, dict) and payload.get("p4_can_run_now") is False:
            provider_auth = payload.get("provider_auth")
            if isinstance(provider_auth, dict):
                for provider in ("kimi", "minimax", "anthropic"):
                    row = provider_auth.get(provider)
                    if isinstance(row, dict) and row.get("usable_dry_run") is False:
                        provider_blockers.append(f"{provider}_auth_unusable_dry_run")
                    if isinstance(row, dict) and row.get("usable_live_smoke") is False:
                        err = str(row.get("live_smoke_error_class") or "unusable")
                        provider_blockers.append(f"{provider}_live_smoke_{err}")
            local_deps = payload.get("local_dependency_blockers")
            if isinstance(local_deps, list):
                for row in local_deps[:6]:
                    if isinstance(row, dict) and row.get("blocker"):
                        provider_blockers.append(str(row.get("blocker")))
            net = payload.get("network_consent")
            if isinstance(net, dict) and net.get("required_for_live_calls"):
                if not net.get("AUDITOOOR_LLM_NETWORK_CONSENT") and not net.get("ADVERSARIAL_LIVE_CONSENT"):
                    provider_blockers.append("live_network_consent_missing")
            if not provider_blockers:
                provider_blockers.append("p4_can_run_now_false_reported")
    provider_backed_code_present = (
        "build_provider_simulation" in rules_text
        or "--provider-backed" in rules_text
        or 'provider_status["provider_backed"] = True' in mcp_text
        or '"provider_backed": True' in mcp_text
        or "'provider_backed': True" in mcp_text
        or '"provider_backed_simulation": True' in rules_text
        or "'provider_backed_simulation': True" in rules_text
    )
    provider_dispatch_boundary_absent = "simulator_has_no_provider_dispatch_boundary" in provider_blockers
    provider_backed_simulator_present = (
        simulate_callable_present
        and provider_backed_code_present
        and not provider_dispatch_boundary_absent
    )
    provider_backed_simulation_ready = provider_backed_simulator_present and not provider_blockers
    classifier_path = root / "reference" / "triager_disposition_classifier.json"
    local_mind_model_evidence = {
        "rules_mvp_present": has_rules_mvp,
        "rules_mcp_present": has_precheck_rules_mcp,
        "simulate_callable_present": simulate_callable_present,
        "classifier_artifact_present": classifier_path.is_file(),
        "classifier_artifact_ref": _rel(classifier_path, root) if classifier_path.is_file() else "",
    }
    provider_backed_readiness = {
        "ready": provider_backed_simulation_ready,
        "simulator_present": provider_backed_simulator_present,
        "blocked": bool(provider_blockers),
        "blockers": sorted(dict.fromkeys(provider_blockers)),
        "local_rules_runnable_now": bool(
            isinstance(provider_recheck, dict) and provider_recheck.get("local_rules_p4_runnable_now") is True
        ),
        "provider_backed_runnable_now": bool(
            isinstance(provider_recheck, dict) and provider_recheck.get("provider_backed_p4_runnable_now") is True
        ),
        "recheck_verdict": provider_recheck.get("verdict") if isinstance(provider_recheck, dict) else None,
    }
    if has_rules_mvp and (simulate_callable_present or has_precheck_rules_mcp):
        status = STATUS_MET
        reason = "P4 local rules/MCP triager MVP is present"
        if provider_backed_simulation_ready:
            reason += "; provider-backed simulation readiness markers are present"
        elif provider_blockers:
            reason += "; provider-backed triager simulation remains blocked by provider/auth live-smoke and local dependency prerequisites"
        else:
            reason += "; provider-backed triager simulation is not ready/proven"
    elif has_rules_mvp:
        status = STATUS_PARTIAL
        reason = "P4 local rules/data precheck MVP is present; provider-backed simulator is not implemented in MCP yet"
        if provider_blockers:
            reason += " and provider/auth live-smoke or local dependency prerequisites show concrete blockers"
    elif pattern_json.is_file():
        status = STATUS_PARTIAL
        reason = "P4 triager pattern data exists, but pre-filing simulator is not built"
    else:
        status = STATUS_UNMET
        reason = "P4 triager mind-model artifacts are absent"
    refs = [
        _rel(path, root)
        for path in (rules_tool, schema_helper, pattern_json, mcp_server)
        if path.is_file()
    ]
    if latest_provider_report is not None:
        refs.append(_rel(latest_provider_report, root))
    if provider_recheck_path.is_file():
        refs.append(_rel(provider_recheck_path, root))
    if classifier_path.is_file():
        refs.append(_rel(classifier_path, root))
    return {
        "status": status,
        "reason": reason,
        "local_mind_model_evidence": local_mind_model_evidence,
        "provider_backed_readiness": provider_backed_readiness,
        "local_rules_mvp_present": has_rules_mvp,
        "local_rules_mcp_present": has_precheck_rules_mcp,
        "simulate_callable_present": simulate_callable_present,
        "provider_backed_simulation_ready": provider_backed_simulation_ready,
        "provider_backed_simulator_present": provider_backed_simulator_present,
        "provider_backed_blocked": bool(provider_blockers),
        "provider_backed_blockers": sorted(dict.fromkeys(provider_blockers)),
        "source_refs": refs,
    }


def _pillar_p5_evidence(root: Path) -> dict[str, Any]:
    tool_path = root / "tools" / "live-target-intelligence-report.py"
    mcp_server = root / "tools" / "vault-mcp-server.py"
    tests_path = root / "tools" / "tests" / "test_live_target_intelligence_report.py"
    latest_report_path = _latest_existing(
        [
            root
            / "reports"
            / "v3_iter_2026-05-24"
            / "lane_P5_ACCEPTED_P1_SOURCEPROOF"
            / "hyperbridge_LIVE_TARGET_REPORT.json"
        ]
    )
    latest_report = _read_json(latest_report_path) if latest_report_path is not None else None
    tool_text = ""
    mcp_text = ""
    try:
        tool_text = tool_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    try:
        mcp_text = mcp_server.read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    has_v2 = "auditooor.live_target_intelligence.v2" in tool_text or "mvp2" in tool_text.lower()
    has_v3 = "auditooor.live_target_intelligence.v3" in tool_text or "mvp3" in tool_text.lower()
    exact_sourceproof_markers = "accepted_p1_source_proof_matches" in tool_text
    tool_sourceproof_version = bool(
        re.search(
            rf"(?m)^\s*TOOL_VERSION\s*=\s*['\"]{re.escape(P5_ACCEPTED_SOURCEPROOF_TOOL_VERSION)}['\"]",
            tool_text,
        )
    )
    has_mcp = "vault_live_target_report" in mcp_text
    latest_report_summary: dict[str, Any] = {"artifact_present": False}
    artifact_is_exact_sourceproof = False

    def safe_int(value: Any) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    if isinstance(latest_report, dict):
        artifact_tool_version = str(latest_report.get("tool_version") or "")
        artifact_is_exact_sourceproof = (
            latest_report.get("schema") == "auditooor.live_target_intelligence.v3"
            and artifact_tool_version == P5_ACCEPTED_SOURCEPROOF_TOOL_VERSION
            and latest_report_path is not None
            and "lane_P5_ACCEPTED_P1_SOURCEPROOF" in latest_report_path.as_posix()
        )
        summary_card = latest_report.get("summary_card")
        if not isinstance(summary_card, dict):
            summary_card = {}
        composability = summary_card.get("composability")
        if not isinstance(composability, dict):
            composability = {}
        p4_precheck = summary_card.get("p4_triager_precheck")
        if not isinstance(p4_precheck, dict):
            p4_precheck = {}
        entries = latest_report.get("entry_points")
        if not isinstance(entries, list):
            entries = []
        accepted_sourceproof_entry_count = 0
        p4_provider_status: dict[str, Any] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if entry.get("accepted_p1_source_proof_matches"):
                accepted_sourceproof_entry_count += 1
            precheck = entry.get("p4_triager_precheck")
            if isinstance(precheck, dict) and not p4_provider_status:
                provider_status = precheck.get("provider_status")
                if isinstance(provider_status, dict):
                    p4_provider_status = {
                        "state": provider_status.get("state"),
                        "provider_backed": bool(provider_status.get("provider_backed")),
                        "provider_call_made": bool(provider_status.get("provider_call_made")),
                        "predicted_verdict_supported": bool(
                            provider_status.get("predicted_verdict_supported")
                        ),
                        "blockers": provider_status.get("blockers")
                        if isinstance(provider_status.get("blockers"), list)
                        else [],
                    }
        p1_match_tier_counts = composability.get("p1_match_tier_counts")
        if not isinstance(p1_match_tier_counts, dict):
            p1_match_tier_counts = {}
        p1_semantic_gap_counts = composability.get("p1_semantic_gap_counts")
        if not isinstance(p1_semantic_gap_counts, dict):
            p1_semantic_gap_counts = {}
        latest_report_summary = {
            "artifact_present": True,
            "artifact_ref": _rel(latest_report_path, root) if latest_report_path is not None else "",
            "schema": latest_report.get("schema"),
            "tool_version": latest_report.get("tool_version"),
            "exact_sourceproof_artifact": artifact_is_exact_sourceproof,
            "report_generated": latest_report.get("audit_pin", {}).get("report_generated")
            if isinstance(latest_report.get("audit_pin"), dict)
            else None,
            "p1_match_tier_counts": p1_match_tier_counts,
            "p1_semantic_gap_counts": p1_semantic_gap_counts,
            "topical_only_gap_count": safe_int(p1_semantic_gap_counts.get("topical-only")),
            "accepted_sourceproof_semantic_entry_count": accepted_sourceproof_entry_count,
            "p4_triager_precheck": {
                "available": bool(p4_precheck.get("available")),
                "state": p4_precheck.get("state"),
                "provider_backed": bool(p4_precheck.get("provider_backed")),
                "provider_call_made": bool(p4_precheck.get("provider_call_made")),
                "predicted_verdict_supported": bool(
                    p4_precheck.get("predicted_verdict_supported")
                ),
                "triager_verdict_or_clearance": bool(p4_precheck.get("triager_verdict_or_clearance")),
                "entries_prechecked": safe_int(p4_precheck.get("entries_prechecked")),
                "entries_budget_skipped": safe_int(p4_precheck.get("entries_budget_skipped")),
            },
            "p4_provider_status_sample": p4_provider_status,
        }
        exact_sourceproof_markers = exact_sourceproof_markers or any(
            isinstance(entry, dict) and "accepted_p1_source_proof_matches" in entry
            for entry in entries
        )

    exact_sourceproof_ready = (
        tool_path.is_file()
        and tests_path.is_file()
        and has_mcp
        and has_v3
        and exact_sourceproof_markers
        and tool_sourceproof_version
        and artifact_is_exact_sourceproof
    )
    if exact_sourceproof_ready:
        status = STATUS_MET
        counts = latest_report_summary.get("p1_match_tier_counts")
        if not isinstance(counts, dict):
            counts = {}
        reason = (
            "P5 live-target intelligence MVP3 exact-sourceproof tool, tests, MCP reader, "
            "and current accepted-sourceproof report artifact are present"
        )
        if counts:
            reason += (
                f"; semantic/topical/no-match counts are "
                f"{counts.get('SEMANTIC-MATCH', 0)}/"
                f"{counts.get('TOPICAL-MATCH', 0)}/"
                f"{counts.get('NO-MATCH', 0)}"
            )
    elif tool_path.is_file() and tests_path.is_file() and has_mcp and has_v3:
        status = STATUS_PARTIAL
        reason = "P5 live-target intelligence MVP3 tool/tests/MCP are present, but exact-sourceproof artifact evidence is incomplete"
    elif tool_path.is_file() and tests_path.is_file() and has_mcp and has_v2:
        status = STATUS_PARTIAL
        reason = "P5 live-target intelligence MVP2 evidence is present, but MVP3 exact-sourceproof closure is not proven"
    elif tool_path.is_file():
        status = STATUS_PARTIAL
        reason = "P5 live-target intelligence tool exists, but MVP2/MVP3/MCP/test evidence is incomplete"
    else:
        status = STATUS_UNMET
        reason = "P5 live-target intelligence report tool is absent"
    refs = [
        _rel(path, root)
        for path in (tool_path, tests_path, mcp_server)
        if path.is_file()
    ]
    if latest_report_path is not None:
        refs.append(_rel(latest_report_path, root))
    return {
        "status": status,
        "reason": reason,
        "mvp2_markers_present": has_v2,
        "mvp3_markers_present": has_v3,
        "exact_sourceproof_markers_present": exact_sourceproof_markers,
        "tool_sourceproof_version_present": tool_sourceproof_version,
        "exact_sourceproof_ready": exact_sourceproof_ready,
        "mcp_present": has_mcp,
        "current_report_artifact": latest_report_summary,
        "source_refs": refs,
    }


def _range_for_statuses(statuses: Iterable[str]) -> tuple[str, str]:
    values = {
        STATUS_MET: (1.0, 1.0),
        STATUS_PARTIAL: (0.25, 0.75),
        STATUS_UNKNOWN: (0.0, 0.25),
        STATUS_UNMET: (0.0, 0.0),
    }
    lows: list[float] = []
    highs: list[float] = []
    for status in statuses:
        low, high = values.get(status, (0.0, 0.0))
        lows.append(low)
        highs.append(high)
    if not lows:
        return "0-0%", "100-100%"
    low_pct = int((sum(lows) / len(lows)) * 100 // 10 * 10)
    high_pct = int(((sum(highs) / len(highs)) * 100 + 9.999) // 10 * 10)
    high_pct = min(100, max(low_pct, high_pct))
    left_low = max(0, 100 - high_pct)
    left_high = max(0, 100 - low_pct)
    return f"{low_pct}-{high_pct}%", f"{left_low}-{left_high}%"


def build_report(root: Path = ROOT, *, workspace: Path | None = None) -> dict[str, Any]:
    root = root.expanduser().resolve()
    workspace = workspace.expanduser().resolve() if workspace is not None else None
    named_tools = _named_tool_evidence(root)
    makefile = _makefile_evidence(root)
    workflow = _workflow_coverage_evidence(root)
    mining = _mining_dashboard_evidence(root)
    field_validation = _field_validation_evidence(root, workspace)
    provider_campaign = _provider_campaign_evidence(root, workspace)
    provider_keep = _provider_keep_evidence(root, provider_campaign, workspace)
    blocker_ledger_summary = _blocker_ledger_summary(root, workspace)

    categories = {
        "pillar_p1_invariants": {
            "label": "P1 invariant extraction",
            **_pillar_p1_evidence(root),
        },
        "pillar_p2_causal_chains": {
            "label": "P2 causal-chain extraction",
            **_pillar_p2_evidence(root),
        },
        "pillar_p3_antipattern_catalog": {
            "label": "P3 anti-pattern catalog",
            **_pillar_p3_evidence(root),
        },
        "pillar_p4_triager_model": {
            "label": "P4 triager mind model",
            **_pillar_p4_evidence(root),
        },
        "pillar_p5_live_target_intel": {
            "label": "P5 live-target intelligence",
            **_pillar_p5_evidence(root),
        },
        "named_tools": {
            "label": "Named V3 tools",
            **named_tools,
        },
        "makefile_targets": {
            "label": "Makefile targets",
            **makefile,
        },
        "workflow_coverage": {
            "label": "Workflow coverage map",
            **workflow,
        },
        "mining_dashboard": {
            "label": "Mining dashboard",
            **mining,
        },
        "provider_telemetry": {
            "label": "Provider telemetry counts",
            **_provider_telemetry_evidence(root),
        },
        "field_validation": {
            "label": "Field validation",
            **field_validation,
        },
        "source_miners": {
            "label": "Source miners",
            **_source_miner_evidence(root, mining),
        },
        "sidecar_coverage": {
            "label": "Hackerman sidecar coverage",
            **_sidecar_coverage_evidence(root),
        },
        "provider_campaign_completeness": {
            "label": "Approved live-provider campaign accounting before use",
            **provider_campaign,
        },
        "provider_keep_verification": {
            "label": "Provider KEEP verification",
            **provider_keep,
        },
        "lesson_gates": {
            "label": "Lesson gates",
            **_lesson_gate_evidence(root),
        },
        "real_hunt_validation": {
            "label": "Real hunt validation",
            **_real_hunt_evidence(root, workspace, field_validation),
        },
    }

    percent_complete, percent_left = _range_for_statuses(row["status"] for row in categories.values())
    blocking = [
        {
            "category_id": category_id,
            "label": categories[category_id]["label"],
            "status": categories[category_id]["status"],
            "reason": categories[category_id].get("reason", ""),
            **(
                {"field_loop_next_steps": categories[category_id].get("field_loop_next_steps", [])}
                if categories[category_id].get("field_loop_next_steps")
                else {}
            ),
            **(
                {"next_commands": categories[category_id].get("next_commands", [])}
                if categories[category_id].get("next_commands")
                else {}
            ),
            **(
                {"next_action_rows": categories[category_id].get("next_action_rows", [])}
                if categories[category_id].get("next_action_rows")
                else {}
            ),
            **(
                {"platform_id_next_action_rows": categories[category_id].get("platform_id_next_action_rows", [])}
                if categories[category_id].get("platform_id_next_action_rows")
                else {}
            ),
        }
        for category_id in BLOCKING_CATEGORY_IDS
        if categories[category_id]["status"] != STATUS_MET
    ]
    return {
        "schema": SCHEMA,
        "root": ".",
        "workspace": "<workspace>" if workspace is not None else "",
        "offline_only": True,
        "headline_status": "tooling/enforcement mostly complete; empirical roadmap still open",
        "roadmap_complete": False,
        "roadmap_completion_guard": (
            "Do not claim roadmap complete until empirical criteria are satisfied: "
            "P1-P5 pillar criteria plus Phase 0 empirical counter-test disposition, "
            "retrospective validation scoreboards, terminal queue rows, real outcome rows, "
            "provider/local verification where available, and source-miner freshness/blocker evidence."
        ),
        "tooling_enforcement_status": "mostly_complete_with_external_state_blockers",
        "empirical_status": "open",
        "precision_policy": "Progress is reported as coarse ranges; absent local evidence is not inferred complete.",
        "percent_complete_range": percent_complete,
        "percent_left_range": percent_left,
        "status_semantics": {
            STATUS_MET: "strong local evidence found",
            STATUS_PARTIAL: "some local evidence found, but not enough to close the category",
            STATUS_UNKNOWN: "artifact absent or unreadable; no positive completion inference",
            STATUS_UNMET: "expected evidence missing or explicitly insufficient",
        },
        "current_blocker_ledger_summary": blocker_ledger_summary,
        "blocking_unmet_categories": blocking,
        "categories": categories,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# HACKERMAN V3 Roadmap Progress",
        "",
        f"- Root: `{report['root']}`",
        f"- Workspace: `{report.get('workspace') or 'not supplied'}`",
        f"- Offline only: `{report['offline_only']}`",
        f"- Headline status: `{report.get('headline_status', '')}`",
        f"- Roadmap complete: `{report.get('roadmap_complete', False)}`",
        f"- Percent complete: `{report['percent_complete_range']}`",
        f"- Percent left: `{report['percent_left_range']}`",
        "- Precision: coarse ranges only; missing evidence is not inferred complete.",
    ]
    ledger_summary = report.get("current_blocker_ledger_summary")
    if isinstance(ledger_summary, dict) and ledger_summary.get("status") == "present":
        lines.append(
            f"- Blocker ledger: `{ledger_summary.get('open_count', 0)}` open "
            f"(`{ledger_summary.get('external_state_required_open_count', 0)}` external-state, "
            f"`{ledger_summary.get('local_actionable_open_count', 0)}` local-actionable), "
            f"`{ledger_summary.get('closed_count', 0)}` closed"
        )
    lines += [
        "",
        "## Blocking Unmet Categories",
        "",
    ]
    blockers = report.get("blocking_unmet_categories", [])
    if not blockers:
        lines.append("- none")
    else:
        for blocker in blockers:
            lines.append(f"- `{blocker['category_id']}` ({blocker['status']}): {blocker['reason']}")

    lines += [
        "",
        "## Evidence Categories",
        "",
        "| Category | Status | Evidence |",
        "|---|---|---|",
    ]
    for category_id, row in report["categories"].items():
        reason = str(row.get("reason") or "")
        if not reason:
            if "present" in row and "expected" in row:
                reason = f"{row['present']}/{row['expected']} present"
            elif "present" in row and "missing" in row:
                reason = f"present={len(row.get('present', []))}, missing={len(row.get('missing', []))}"
        escaped_reason = reason.replace("|", "\\|")
        lines.append(f"| `{category_id}` | `{row['status']}` | {escaped_reason} |")
    return "\n".join(lines).rstrip() + "\n"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="Repository root to inspect")
    parser.add_argument("--workspace", type=Path, default=None, help="Optional workspace for field/hunt sidecars")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of Markdown")
    parser.add_argument("--out", type=Path, help="optional output path")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if not args.root.is_dir():
        print(f"[v3-roadmap-progress-report] ERR root not found: {args.root}", file=sys.stderr)
        return 2
    report = build_report(args.root, workspace=args.workspace)
    output = json.dumps(report, indent=2, sort_keys=True) + "\n" if args.json else render_markdown(report)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
