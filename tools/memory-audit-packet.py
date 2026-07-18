#!/usr/bin/env python3
"""Emit a compact local memory/audit handoff packet.

The packet is intentionally bounded. It summarizes existing local status
reports so a new model/workspace can orient without rereading the repo, while
preserving conservative audit boundaries.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.memory_audit_packet.v0"
DEFAULT_DATE = "2026-05-05"
MAX_ITEMS = 8
MAX_TEXT = 280
ABS_WORKTREE_RE = re.compile(r"/Users/wolf/auditooor-worktrees/([A-Za-z0-9._-]+)")


@dataclass(frozen=True)
class PacketBounds:
    max_items: int = MAX_ITEMS
    max_text: int = MAX_TEXT

    @classmethod
    def from_values(cls, *, max_items: int, max_text: int) -> "PacketBounds":
        return cls(max(1, max_items), max(80, max_text))

INPUT_REPORTS = [
    "reports/known_limitations_burndown_queue_2026-05-05.json",
    "reports/scanner_wiring_truth_inventory_2026-05-05.json",
    "reports/harness_binding_manifest_status_2026-05-05.json",
    "reports/source_ref_replay_manifest_plan_2026-05-05.json",
    "reports/github_commit_mining_exploit_plan_2026-05-05.json",
    "reports/commit_lifecycle_ledger_2026-05-05.json",
    "reports/no_reason_decline_memory_2026-05-05.json",
]

LATEST_DEFAULT_REPORTS = {
    "reports/scanner_wiring_truth_inventory_2026-05-05.json": (
        "scanner_wiring_truth_inventory",
        "auditooor.scanner_wiring_truth_inventory.v1",
    ),
}

NO_REASON_CAVEAT = (
    "No-reason declines cannot be learned as pattern false positives; treat "
    "them only as platform/base-rate calibration and do not infer duplicate, "
    "out_of_scope, proof_failure, severity_misframe, provider_routing, or "
    "triager intent."
)

NO_CLAIM_CAVEAT = (
    "This packet does not claim exploitability, audit completeness, detector "
    "completeness, or submission readiness."
)

TOP_ACTION_ID_ORDER = {
    "KLBQ-001": 0,
    "KLBQ-006": 1,
    "KLBQ-002": 2,
    "KLBQ-005": 3,
    "KLBQ-008": 4,
}
ALWAYS_SURFACE_ACTION_IDS = {"KLBQ-005", "KLBQ-008"}


def _mask_worktree_refs(value: Any) -> str:
    return ABS_WORKTREE_RE.sub(
        lambda match: f"[worktree-root:{match.group(1)}]",
        str(value),
    )


def _bounded_text(value: Any, *, limit: int = MAX_TEXT) -> str:
    text = " ".join(_mask_worktree_refs(value).split())
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _compact_list(values: Any, *, limit: int = MAX_ITEMS, text_limit: int = MAX_TEXT) -> list[str]:
    out: list[str] = []
    for value in _as_list(values):
        if value is None:
            continue
        text = _bounded_text(value, limit=text_limit)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _read_json(path: Path) -> tuple[Any | None, dict[str, Any]]:
    if not path.exists():
        return None, {"path": str(path), "status": "missing"}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, {
            "path": str(path),
            "status": "invalid_json",
            "error": _bounded_text(exc),
        }
    return payload, {"path": str(path), "status": "loaded"}


def _json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _loop_marker(path: Path) -> int:
    match = re.search(r"(?:^|[-_])(?:r|l|loop)(\d+)(?:[-_.]|$)", path.name.lower())
    return int(match.group(1)) if match else 0


def _report_sort_key(path: Path, payload: dict[str, Any]) -> tuple[str, int, int, int, str]:
    dates = re.findall(r"\d{4}-\d{2}-\d{2}", path.name)
    return (
        dates[-1] if dates else "",
        _loop_marker(path),
        _safe_int(payload.get("item_count") or payload.get("unique_action_count") or payload.get("actionable_row_count")),
        _safe_int(payload.get("total_row_count") or payload.get("top_action_count")),
        path.name,
    )


def _compatible_report(payload: dict[str, Any], schema: str) -> bool:
    if str(payload.get("schema") or "") != schema:
        return False
    if schema == "auditooor.scanner_wiring_truth_inventory.v1":
        return isinstance(payload.get("rows"), list)
    return True


def _latest_default_report(repo_root: Path, fallback_rel: str) -> str:
    spec = LATEST_DEFAULT_REPORTS.get(fallback_rel)
    if spec is None:
        return fallback_rel
    stem, schema = spec
    reports_root = repo_root / "reports"
    if not reports_root.is_dir():
        return fallback_rel
    candidates: list[tuple[Path, dict[str, Any]]] = []
    for path in reports_root.glob(f"{stem}_*.json"):
        payload = _json_object(path)
        if _compatible_report(payload, schema):
            candidates.append((path, payload))
    if not candidates:
        return fallback_rel
    selected = max(candidates, key=lambda item: _report_sort_key(item[0], item[1]))[0]
    try:
        return selected.relative_to(repo_root).as_posix()
    except ValueError:
        return selected.as_posix()


def _normalize_input_reports(input_reports: list[str] | None, *, repo_root: Path | None = None) -> list[str]:
    reports = input_reports or INPUT_REPORTS
    out: list[str] = []
    for report in reports:
        normalized = str(Path(report))
        if input_reports is None and repo_root is not None:
            normalized = _latest_default_report(repo_root, normalized)
        if normalized not in out:
            out.append(normalized)
    return out


def _git_value(root: Path, *args: str) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    value = proc.stdout.strip()
    return value or None


def _source_label(path: str) -> str:
    return Path(path).name


def _append_unique(rows: list[dict[str, Any]], row: dict[str, Any]) -> None:
    key = json.dumps(row, sort_keys=True)
    for existing in rows:
        if json.dumps(existing, sort_keys=True) == key:
            return
    rows.append(row)


def _row_action(row: dict[str, Any]) -> str:
    for key in ("concrete_next_patch", "suggested_next_action", "detail", "limitation", "title"):
        value = row.get(key)
        if value:
            return _bounded_text(value)
    return _bounded_text(row)


def _known_limitation_row_bucket(row: dict[str, Any]) -> str:
    status = str(row.get("implementation_status") or "").strip()
    if status.startswith("implemented"):
        return "implemented_v0"
    if status.startswith("partially_implemented"):
        return "partially_implemented_v0"
    return "open"


def _known_limitation_action_sort_key(row: dict[str, Any]) -> tuple[int, int]:
    row_id = str(row.get("id") or "")
    try:
        rank = int(row.get("rank") or 9999)
    except (TypeError, ValueError):
        rank = 9999
    return (TOP_ACTION_ID_ORDER.get(row_id, 1000), rank)


def _known_limitation_summary_ids(summary: dict[str, Any]) -> dict[str, set[str]]:
    buckets: dict[str, set[str]] = {
        "implemented_v0": set(),
        "partially_implemented_v0": set(),
        "open": set(),
    }
    for bucket in buckets:
        buckets[bucket] = {
            str(item)
            for item in _as_list(summary.get(bucket))
            if str(item).strip()
        }
    return buckets


def _known_limitation_row_ids(rows: list[dict[str, Any]]) -> dict[str, set[str]]:
    buckets: dict[str, set[str]] = {
        "implemented_v0": set(),
        "partially_implemented_v0": set(),
        "open": set(),
    }
    for row in rows:
        row_id = str(row.get("id") or "").strip()
        if not row_id:
            continue
        buckets[_known_limitation_row_bucket(row)].add(row_id)
    return buckets


def _known_limitation_summary_consistency(
    summary: dict[str, Any],
    rows: list[dict[str, Any]],
    *,
    bounds: PacketBounds,
) -> dict[str, Any]:
    summary_buckets = _known_limitation_summary_ids(summary)
    row_buckets = _known_limitation_row_ids(rows)
    row_lookup = {
        str(row.get("id") or "").strip(): row
        for row in rows
        if str(row.get("id") or "").strip()
    }
    row_bucket_by_id = {
        row_id: bucket
        for bucket, ids in row_buckets.items()
        for row_id in ids
    }
    summary_bucket_by_id = {
        row_id: bucket
        for bucket, ids in summary_buckets.items()
        for row_id in ids
    }
    all_ids = sorted(set(row_bucket_by_id) | set(summary_bucket_by_id))
    mismatches: list[dict[str, Any]] = []
    for row_id in all_ids:
        row_bucket = row_bucket_by_id.get(row_id)
        summary_bucket = summary_bucket_by_id.get(row_id)
        if row_bucket == summary_bucket:
            continue
        row = row_lookup.get(row_id, {})
        mismatches.append(
            {
                "id": row_id,
                "summary_bucket": summary_bucket or "missing",
                "row_bucket": row_bucket or "missing",
                "row_implementation_status": str(row.get("implementation_status") or "missing"),
            }
        )

    return {
        "status": "consistent" if not mismatches else "mismatch_fail_closed",
        "row_level_authority": True,
        "implementation_summary_trusted": not mismatches,
        "summary_buckets": {
            bucket: sorted(ids)
            for bucket, ids in summary_buckets.items()
        },
        "row_derived_buckets": {
            bucket: sorted(ids)
            for bucket, ids in row_buckets.items()
        },
        "mismatch_count": len(mismatches),
        "mismatches": mismatches[: bounds.max_items],
    }


def _summarize_known_limitations(
    payload: dict[str, Any],
    *,
    source_path: str,
    readiness: dict[str, Any],
    actions: list[dict[str, Any]],
    blocked: list[dict[str, Any]],
    bounds: PacketBounds,
) -> None:
    rows = [row for row in _as_list(payload.get("rows")) if isinstance(row, dict)]
    summary = payload.get("implementation_summary") if isinstance(payload.get("implementation_summary"), dict) else {}
    consistency = _known_limitation_summary_consistency(summary, rows, bounds=bounds)
    row_buckets = consistency["row_derived_buckets"]
    summary_buckets = consistency["summary_buckets"]
    allow_maintenance_actions = consistency["status"] == "consistent"
    readiness["known_limitations_queue"] = {
        "source": source_path,
        "row_count": len(rows),
        "counts_source": "row_level_implementation_status",
        "implemented_v0": len(row_buckets["implemented_v0"]),
        "partially_implemented_v0": len(row_buckets["partially_implemented_v0"]),
        "open": len(row_buckets["open"]),
        "implementation_summary_counts": {
            "implemented_v0": len(summary_buckets["implemented_v0"]),
            "partially_implemented_v0": len(summary_buckets["partially_implemented_v0"]),
            "open": len(summary_buckets["open"]),
        },
        "implementation_summary_trusted": consistency["implementation_summary_trusted"],
        "summary_consistency": consistency,
        "not_submission_evidence": True,
    }
    if consistency["status"] != "consistent":
        _append_unique(
            blocked,
            {
                "source": source_path,
                "id": "known_limitations_summary_consistency",
                "status": str(consistency["status"]),
                "blocked_until_or_reason": [
                    (
                        f"{item['id']}: implementation_summary={item['summary_bucket']} "
                        f"row={item['row_bucket']} status={item['row_implementation_status']}"
                    )
                    for item in consistency["mismatches"]
                ][: bounds.max_items],
            },
        )
    for row in sorted(rows, key=_known_limitation_action_sort_key):
        status = str(row.get("implementation_status") or "")
        row_id = str(row.get("id") or "")
        if _known_limitation_row_bucket(row) == "implemented_v0" and (
            row_id not in ALWAYS_SURFACE_ACTION_IDS or not allow_maintenance_actions
        ):
            continue
        _append_unique(
            actions,
            {
                "priority": len(actions) + 1,
                "source": source_path,
                "id": row_id,
                "owner_lane": str(row.get("owner_lane") or "unknown"),
                "action": _bounded_text(_row_action(row), limit=bounds.max_text),
                "verification_status": str(row.get("verification_status") or "unknown"),
            },
        )
        blockers = _compact_list(
            row.get("remaining_blockers") or row.get("blocked_until"),
            limit=bounds.max_items,
            text_limit=bounds.max_text,
        )
        if blockers:
            _append_unique(
                blocked,
                {
                    "source": source_path,
                    "id": str(row.get("id") or ""),
                    "status": status or "unknown",
                    "blocked_until_or_reason": blockers,
                },
            )
        if len(actions) >= bounds.max_items:
            break


def _summarize_scanner_inventory(
    payload: dict[str, Any],
    *,
    source_path: str,
    readiness: dict[str, Any],
    blocked: list[dict[str, Any]],
    bounds: PacketBounds,
) -> None:
    rows = [row for row in _as_list(payload.get("rows")) if isinstance(row, dict)]
    status_counts = Counter(str(row.get("wiring_status") or "unknown") for row in rows)
    readiness["scanner_wiring_truth"] = {
        "source": source_path,
        "item_count": int(payload.get("item_count") or len(rows)),
        "truncated": bool(payload.get("truncated", False)),
        "backend_counts": payload.get("backend_counts") if isinstance(payload.get("backend_counts"), dict) else {},
        "evidence_kind_counts": payload.get("evidence_kind_counts") if isinstance(payload.get("evidence_kind_counts"), dict) else {},
        "wiring_status_counts_in_packet_rows": dict(sorted(status_counts.items())),
        "interpretation": "routing/accounting evidence only; not exploitability or completeness evidence",
    }
    blocked_statuses = {
        key: value
        for key, value in status_counts.items()
        if key not in {"wired_verified"} and value
    }
    if blocked_statuses:
        _append_unique(
            blocked,
            {
                "source": source_path,
                "id": "scanner_wiring_truth",
                "status": "fail_closed_inventory",
                "blocked_until_or_reason": [
                    f"{status}: {count}" for status, count in sorted(blocked_statuses.items())
                ][: bounds.max_items],
            },
        )


def _summarize_harness_binding(
    payload: dict[str, Any],
    *,
    source_path: str,
    readiness: dict[str, Any],
    actions: list[dict[str, Any]],
    blocked: list[dict[str, Any]],
    bounds: PacketBounds,
) -> None:
    klbq = payload.get("klbq_004") if isinstance(payload.get("klbq_004"), dict) else {}
    tool = payload.get("tool") if isinstance(payload.get("tool"), dict) else {}
    readiness["harness_binding_manifest"] = {
        "source": source_path,
        "tool": tool.get("path"),
        "status": tool.get("status") or "unknown",
        "queue_state": klbq.get("state_delta"),
        "does_not_execute_harnesses": True,
        "not_submission_evidence": True,
    }
    for item in _compact_list(
        klbq.get("remaining_work"),
        limit=min(3, bounds.max_items),
        text_limit=bounds.max_text,
    ):
        _append_unique(
            actions,
            {
                "priority": len(actions) + 1,
                "source": source_path,
                "id": "KLBQ-004",
                "owner_lane": "harness binding",
                "action": item,
                "verification_status": "blocked_until_wired",
            },
        )
    probe = klbq.get("local_queue_probe") if isinstance(klbq.get("local_queue_probe"), dict) else {}
    blockers = _compact_list(
        probe.get("blockers") or probe.get("missing_inputs"),
        limit=bounds.max_items,
        text_limit=bounds.max_text,
    )
    if blockers:
        _append_unique(
            blocked,
            {
                "source": source_path,
                "id": "KLBQ-004",
                "status": str(probe.get("status") or "blocked"),
                "blocked_until_or_reason": blockers,
            },
        )


def _summarize_source_ref(
    payload: dict[str, Any],
    *,
    source_path: str,
    readiness: dict[str, Any],
    actions: list[dict[str, Any]],
    blocked: list[dict[str, Any]],
    bounds: PacketBounds,
) -> None:
    snapshot = payload.get("local_detector_gap_snapshot")
    readiness["source_ref_replay_manifest"] = {
        "source": source_path,
        "implemented": bool(payload.get("implemented")),
        "source_replay_performed": bool(payload.get("source_replay_performed")),
        "network_used": bool(payload.get("network_used")),
        "statuses": _compact_list(
            payload.get("current_statuses"),
            limit=bounds.max_items,
            text_limit=bounds.max_text,
        ),
        "detector_gap_snapshot": snapshot if isinstance(snapshot, dict) else {},
        "not_submission_evidence": True,
    }
    for row in _as_list(payload.get("next_steps"))[: min(3, bounds.max_items)]:
        if isinstance(row, dict):
            action = row.get("detail") or row.get("step")
            action_id = row.get("step") or "source_ref_next_step"
        else:
            action = row
            action_id = "source_ref_next_step"
        _append_unique(
            actions,
            {
                "priority": len(actions) + 1,
                "source": source_path,
                "id": str(action_id),
                "owner_lane": "source replay",
                "action": _bounded_text(action, limit=bounds.max_text),
                "verification_status": "open",
            },
        )
    limits = []
    for row in _as_list(payload.get("remaining_limits"))[: bounds.max_items]:
        if isinstance(row, dict):
            limits.append(_bounded_text(row.get("detail") or row.get("limit"), limit=bounds.max_text))
        else:
            limits.append(_bounded_text(row, limit=bounds.max_text))
    if limits:
        _append_unique(
            blocked,
            {
                "source": source_path,
                "id": "source_ref_replay",
                "status": "manifest_only",
                "blocked_until_or_reason": limits,
            },
        )


def _summarize_github_commit_mining(
    payload: dict[str, Any],
    *,
    source_path: str,
    readiness: dict[str, Any],
    actions: list[dict[str, Any]],
    blocked: list[dict[str, Any]],
    bounds: PacketBounds,
) -> None:
    bounded = payload.get("bounded_packet") if isinstance(payload.get("bounded_packet"), dict) else {}
    implemented = payload.get("implemented_v0") if isinstance(payload.get("implemented_v0"), dict) else {}
    readiness["github_commit_mining"] = {
        "source": source_path,
        "tool": implemented.get("tool"),
        "advisory_only": bool(payload.get("advisory_only", True)),
        "network_used": bool(payload.get("network_used")),
        "bounded_packet": {
            "unit_of_work": bounded.get("unit_of_work"),
            "max_candidate_commits_per_run": bounded.get("max_candidate_commits_per_run"),
            "max_ranked_review_packets": bounded.get("max_ranked_review_packets"),
            "max_poc_investment_candidates": bounded.get("max_poc_investment_candidates"),
        },
        "submit_ready": False,
    }
    _append_unique(
        actions,
        {
            "priority": len(actions) + 1,
            "source": source_path,
            "id": "commit_mining_replayable_packets",
            "owner_lane": "commit mining",
            "action": "Produce replayable scan_tasks.json and review_packets.json from verified local mirrors before spending PoC effort.",
            "verification_status": "open",
        },
    )
    fail_closed = _compact_list(
        bounded.get("fail_closed_conditions"),
        limit=bounds.max_items,
        text_limit=bounds.max_text,
    )
    if fail_closed:
        _append_unique(
            blocked,
            {
                "source": source_path,
                "id": "github_commit_mining",
                "status": "fail_closed_without_local_mirrors",
                "blocked_until_or_reason": fail_closed,
            },
        )


def _summarize_no_reason_declines(
    payload: dict[str, Any],
    *,
    source_path: str,
    readiness: dict[str, Any],
    bounds: PacketBounds,
) -> None:
    decision = payload.get("decision") if isinstance(payload.get("decision"), dict) else {}
    readiness["no_reason_decline_memory"] = {
        "source": source_path,
        "classification": decision.get("classification") or "unknown-reason decline",
        "memory_effect": decision.get("memory_effect") or "platform/base-rate calibration only",
        "forbid_inference": _compact_list(
            decision.get("forbid_inference"),
            limit=bounds.max_items,
            text_limit=bounds.max_text,
        ),
        "strict_caveat": NO_REASON_CAVEAT,
    }


def _summarize_commit_lifecycle(
    payload: dict[str, Any],
    *,
    source_path: str,
    readiness: dict[str, Any],
    actions: list[dict[str, Any]],
    blocked: list[dict[str, Any]],
    bounds: PacketBounds,
) -> None:
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    readiness["commit_lifecycle_ledger"] = {
        "source": source_path,
        "row_count": summary.get("row_count"),
        "queue_count": summary.get("queue_count"),
        "state_counts": _compact_list(
            [
                f"{row.get('name')}: {row.get('count')}"
                for row in _as_list(summary.get("state_counts"))
                if isinstance(row, dict)
            ],
            limit=bounds.max_items,
            text_limit=bounds.max_text,
        ),
        "lane_counts": _compact_list(
            [
                f"{row.get('name')}: {row.get('count')}"
                for row in _as_list(summary.get("lane_counts"))
                if isinstance(row, dict)
            ],
            limit=bounds.max_items,
            text_limit=bounds.max_text,
        ),
        "proof_boundary": payload.get("proof_boundary") or NO_CLAIM_CAVEAT,
        "network_used": bool(payload.get("network_used")),
    }
    for item in _as_list(payload.get("concrete_queue"))[: bounds.max_items]:
        if not isinstance(item, dict):
            continue
        _append_unique(
            actions,
            {
                "priority": len(actions) + 1,
                "source": source_path,
                "id": str(item.get("item_id") or item.get("title") or "commit_lifecycle_queue"),
                "owner_lane": str(item.get("lane") or "commit lifecycle"),
                "action": _bounded_text(item.get("detail") or item.get("title"), limit=bounds.max_text),
                "verification_status": "advisory_lifecycle_queue",
            },
        )
        if len(actions) >= bounds.max_items:
            break
    limits = _compact_list(
        payload.get("coverage_limits"),
        limit=bounds.max_items,
        text_limit=bounds.max_text,
    )
    if limits:
        _append_unique(
            blocked,
            {
                "source": source_path,
                "id": "commit_lifecycle_coverage_limits",
                "status": "routing_memory_only",
                "blocked_until_or_reason": limits,
            },
        )


def _live_evidence(input_statuses: list[dict[str, Any]], readiness: dict[str, Any]) -> dict[str, Any]:
    status_counts = Counter(str(item.get("status") or "unknown") for item in input_statuses)
    return {
        "loaded_input_reports": int(status_counts.get("loaded", 0)),
        "missing_input_reports": int(status_counts.get("missing", 0)),
        "invalid_input_reports": int(status_counts.get("invalid_json", 0)),
        "readiness_sections": sorted(readiness.keys()),
        "all_inputs_loaded": int(status_counts.get("loaded", 0)) == len(input_statuses),
    }


def build_packet(
    repo_root: Path,
    *,
    date: str = DEFAULT_DATE,
    input_reports: list[str] | None = None,
    bounds: PacketBounds | None = None,
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    bounds = bounds or PacketBounds()
    normalized_reports = _normalize_input_reports(input_reports, repo_root=repo_root)
    branch = _git_value(repo_root, "branch", "--show-current")
    head = _git_value(repo_root, "rev-parse", "--short=12", "HEAD")

    readiness: dict[str, Any] = {}
    actions: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    loaded_inputs: list[dict[str, Any]] = []

    payloads: dict[str, Any] = {}
    for rel_path in normalized_reports:
        payload, status = _read_json(repo_root / rel_path)
        status["path"] = rel_path
        loaded_inputs.append(status)
        if isinstance(payload, dict):
            payloads[rel_path] = payload

    for rel_path, payload in payloads.items():
        name = _source_label(rel_path)
        if name.startswith("known_limitations_burndown_queue"):
            _summarize_known_limitations(
                payload,
                source_path=rel_path,
                readiness=readiness,
                actions=actions,
                blocked=blocked,
                bounds=bounds,
            )
        elif name.startswith("scanner_wiring_truth_inventory"):
            _summarize_scanner_inventory(
                payload,
                source_path=rel_path,
                readiness=readiness,
                blocked=blocked,
                bounds=bounds,
            )
        elif name.startswith("harness_binding_manifest_status"):
            _summarize_harness_binding(
                payload,
                source_path=rel_path,
                readiness=readiness,
                actions=actions,
                blocked=blocked,
                bounds=bounds,
            )
        elif name.startswith("source_ref_replay_manifest_plan"):
            _summarize_source_ref(
                payload,
                source_path=rel_path,
                readiness=readiness,
                actions=actions,
                blocked=blocked,
                bounds=bounds,
            )
        elif name.startswith("github_commit_mining_exploit_plan"):
            _summarize_github_commit_mining(
                payload,
                source_path=rel_path,
                readiness=readiness,
                actions=actions,
                blocked=blocked,
                bounds=bounds,
            )
        elif name.startswith("commit_lifecycle_ledger"):
            _summarize_commit_lifecycle(
                payload,
                source_path=rel_path,
                readiness=readiness,
                actions=actions,
                blocked=blocked,
                bounds=bounds,
            )
        elif name.startswith("no_reason_decline_memory"):
            _summarize_no_reason_declines(
                payload,
                source_path=rel_path,
                readiness=readiness,
                bounds=bounds,
            )

    missing_or_invalid = [
        item for item in loaded_inputs if item.get("status") != "loaded"
    ]
    if missing_or_invalid:
        _append_unique(
            blocked,
            {
                "source": "memory-audit-packet",
                "id": "input_report_availability",
                "status": "missing_or_invalid_inputs",
                "blocked_until_or_reason": [
                    f"{item['path']}: {item['status']}" for item in missing_or_invalid[: bounds.max_items]
                ],
            },
        )

    actions = actions[: bounds.max_items]
    for index, action in enumerate(actions, start=1):
        action["priority"] = index

    packet = {
        "schema": SCHEMA,
        "date": date,
        "repo_root": str(repo_root),
        "branch": branch,
        "head_short": head,
        "live_report_generation": _live_evidence(loaded_inputs, readiness),
        "objective_snapshot": {
            "purpose": "Compact handoff for audit continuation by another workspace/model without rereading the whole repo.",
            "goal_state": "open_by_design",
            "source_basis": "existing local memory/state reports only",
            "network_used": False,
            "llm_dispatch_ran": False,
            "advisory_only": True,
            "strict_caveats": [NO_CLAIM_CAVEAT, NO_REASON_CAVEAT],
        },
        "active_constraints": [
            "stdlib/offline only",
            "read bounded summaries from the known local memory/state reports when present",
            "do not infer exploitability, audit completeness, detector completeness, or submission readiness",
            "do not treat advisory, detector-only, scaffolded, memory-generated, or source-absent work as submission evidence",
            "known-limitations row-level implementation_status is the authority when summary buckets disagree",
            NO_REASON_CAVEAT,
        ],
        "audit_readiness": readiness,
        "top_next_actions": actions,
        "blocked_items": blocked[: bounds.max_items],
        "model_handoff_notes": [
            "Start from top_next_actions, not broad repo rereads.",
            "Use audit_readiness to decide which local tool/status packet to open first.",
            "Treat scanner counts as routing/accounting evidence until fixture/executor proof exists.",
            "Treat source-ref and commit-mining packets as manifest/review lanes, not replay or exploit proof.",
            "Keep no-reason declines out of pattern false-positive learning.",
        ],
        "cli_usage": {
            "default_command": "python3 tools/memory-audit-packet.py .",
            "make_target": "make memory-audit-packet",
            "useful_options": [
                "--stdout-format summary",
                "--stdout-format json",
                "--input-report <path>",
                "--max-items <n>",
                "--fail-on-missing-input",
            ],
        },
        "token_savings_assumptions": {
            "intended_savings": "Avoid rereading full docs/reports/detectors by carrying only status deltas, blockers, and exact next actions.",
            "safe_to_skip_initially": [
                "full scanner inventory rows unless working scanner-wiring burn-down",
                "full known-limitations prose unless changing a queue row",
                "full commit-mining plan unless producing scan_tasks.json/review_packets.json",
                "full harness manifest docs unless wiring scaffold emission",
            ],
            "must_reopen_sources_when": [
                "editing any tool or queue row named by top_next_actions",
                "turning advisory memory into executable proof",
                "claiming readiness, coverage, replay, impact, or submission status",
            ],
            "bounded_packet_limits": {
                "max_input_reports": len(normalized_reports),
                "max_top_next_actions": bounds.max_items,
                "max_blocked_items": bounds.max_items,
                "max_text_chars_per_item": bounds.max_text,
            },
        },
        "input_reports": loaded_inputs,
    }
    return packet


def render_doc(packet: dict[str, Any]) -> str:
    live = packet.get("live_report_generation") if isinstance(packet.get("live_report_generation"), dict) else {}
    lines = [
        f"# Memory Audit Packet Status - {packet.get('date')}",
        "",
        f"Schema: `{packet.get('schema')}`",
        f"Branch: `{packet.get('branch') or 'unknown'}`",
        f"Head: `{packet.get('head_short') or 'unknown'}`",
        "",
        "## Boundary",
        "",
        packet["objective_snapshot"]["purpose"],
        "",
        f"- Goal state: `{packet['objective_snapshot']['goal_state']}`",
        "- Network used: `false`",
        "- LLM dispatch ran: `false`",
        "- Advisory only: `true`",
        f"- Caveat: {NO_CLAIM_CAVEAT}",
        f"- Caveat: {NO_REASON_CAVEAT}",
        "",
        "## Input Reports",
        "",
    ]
    for item in packet.get("input_reports", []):
        lines.append(f"- `{item.get('path')}`: `{item.get('status')}`")

    lines.extend(
        [
            "",
            "## Live Generation",
            "",
            f"- Loaded inputs: `{live.get('loaded_input_reports', 0)}`",
            f"- Missing inputs: `{live.get('missing_input_reports', 0)}`",
            f"- Invalid inputs: `{live.get('invalid_input_reports', 0)}`",
            f"- Readiness sections: `{', '.join(live.get('readiness_sections') or []) or 'none'}`",
        ]
    )

    lines.extend(["", "## Audit Readiness", ""])
    readiness = packet.get("audit_readiness") if isinstance(packet.get("audit_readiness"), dict) else {}
    if readiness:
        for key in sorted(readiness):
            row = readiness[key]
            if not isinstance(row, dict):
                continue
            source = row.get("source") or "unknown"
            summary_bits = []
            for field in (
                "status",
                "implemented",
                "row_count",
                "item_count",
                "counts_source",
                "implemented_v0",
                "partially_implemented_v0",
                "open",
                "implementation_summary_trusted",
                "advisory_only",
                "network_used",
            ):
                if field in row:
                    summary_bits.append(f"{field}={row[field]}")
            summary = "; ".join(str(bit) for bit in summary_bits) or "loaded"
            lines.append(f"- `{key}` from `{source}`: {summary}")
    else:
        lines.append("- No readiness sections emitted.")

    lines.extend(["", "## Top Next Actions", ""])
    actions = packet.get("top_next_actions") or []
    if actions:
        for action in actions:
            lines.append(
                f"- {action.get('priority')}. `{action.get('id')}` "
                f"({action.get('owner_lane')}): {action.get('action')}"
            )
    else:
        lines.append("- None emitted.")

    lines.extend(["", "## Blocked Items", ""])
    blocked = packet.get("blocked_items") or []
    if blocked:
        for item in blocked:
            reasons = "; ".join(_compact_list(item.get("blocked_until_or_reason"), limit=4))
            lines.append(f"- `{item.get('id')}`: `{item.get('status')}` - {reasons}")
    else:
        lines.append("- None emitted.")

    lines.extend(
        [
            "",
            "## Handoff Notes",
            "",
        ]
    )
    for note in packet.get("model_handoff_notes", []):
        lines.append(f"- {note}")

    usage = packet.get("cli_usage") if isinstance(packet.get("cli_usage"), dict) else {}
    lines.extend(["", "## Usage", ""])
    lines.append(f"- Default: `{usage.get('default_command', 'python3 tools/memory-audit-packet.py .')}`")
    lines.append(f"- Make target: `{usage.get('make_target', 'make memory-audit-packet')}`")
    for option in _compact_list(usage.get("useful_options"), limit=8):
        lines.append(f"- Option: `{option}`")

    lines.extend(
        [
            "",
            "## Token Savings Assumptions",
            "",
            packet["token_savings_assumptions"]["intended_savings"],
            "",
            "Reopen source packets before making readiness, coverage, replay, impact, or submission claims.",
            "",
        ]
    )
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo_root", nargs="?", default=".", help="repo root to inspect")
    parser.add_argument(
        "--json-out",
        default=f"reports/memory_audit_packet_status_{DEFAULT_DATE}.json",
        help="path for packet JSON, relative to repo root unless absolute",
    )
    parser.add_argument(
        "--doc-out",
        default=f"docs/MEMORY_AUDIT_PACKET_STATUS_{DEFAULT_DATE}.md",
        help="path for status markdown, relative to repo root unless absolute",
    )
    parser.add_argument("--date", default=DEFAULT_DATE)
    parser.add_argument(
        "--input-report",
        action="append",
        default=None,
        help="input report path relative to repo root; repeat to override the default report set",
    )
    parser.add_argument(
        "--max-items",
        type=int,
        default=MAX_ITEMS,
        help="maximum top actions, blocked items, and compact list rows",
    )
    parser.add_argument(
        "--max-text",
        type=int,
        default=MAX_TEXT,
        help="maximum characters retained for compact text fields",
    )
    parser.add_argument(
        "--stdout-format",
        choices=("none", "json", "markdown", "summary"),
        default="none",
        help="optional stdout rendering while still writing output files",
    )
    parser.add_argument(
        "--fail-on-missing-input",
        action="store_true",
        help="exit non-zero after writing outputs if any requested input report is missing or invalid",
    )
    parser.add_argument("--print-json", action="store_true")
    parser.add_argument("--no-doc", action="store_true")
    return parser.parse_args(argv)


def _output_path(root: Path, value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return root / path


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    repo_root = Path(args.repo_root).resolve()
    stdout_format = "json" if args.print_json else args.stdout_format
    bounds = PacketBounds.from_values(max_items=args.max_items, max_text=args.max_text)
    packet = build_packet(
        repo_root,
        date=args.date,
        input_reports=args.input_report,
        bounds=bounds,
    )

    json_out = _output_path(repo_root, args.json_out)
    json_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if not args.no_doc:
        doc_out = _output_path(repo_root, args.doc_out)
        doc_out.parent.mkdir(parents=True, exist_ok=True)
        doc_out.write_text(render_doc(packet), encoding="utf-8")

    if stdout_format == "json":
        print(json.dumps(packet, indent=2, sort_keys=True))
    elif stdout_format == "markdown":
        print(render_doc(packet))
    elif stdout_format == "summary":
        live = packet.get("live_report_generation", {})
        print(
            "memory-audit-packet: "
            f"loaded={live.get('loaded_input_reports', 0)} "
            f"missing={live.get('missing_input_reports', 0)} "
            f"invalid={live.get('invalid_input_reports', 0)} "
            f"actions={len(packet.get('top_next_actions') or [])} "
            f"blocked={len(packet.get('blocked_items') or [])}"
        )

    if args.fail_on_missing_input and not packet["live_report_generation"]["all_inputs_loaded"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
