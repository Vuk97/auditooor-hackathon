#!/usr/bin/env python3
"""Emit a compact status snapshot for the Hackerman/MCP capability roadmap."""
from __future__ import annotations

import argparse
import json
import os
from collections import Counter, OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TAG_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_DERIVED_DIR = REPO_ROOT / "audit" / "corpus_tags" / "derived"
DEFAULT_INDEX_DIR = REPO_ROOT / "audit" / "corpus_tags" / "index"


GO_COSMOS_RECORD_TARGET = 500
MIN_PROOF_ARTIFACT_TARGET = 100
REALWORLD_SAME_CLASS_RECALL_TARGET = 0.70
SIDECAR_STALE_AFTER_SECONDS = 24 * 60 * 60


# Callables that are expected to be used across hunt iterations. If a callable
# is wired into the MANIFEST but logged <ADOPTION_LOW_THRESHOLD times across
# the last N iterations of the per-workspace MCP call log, it surfaces as
# LOW_ADOPTION. If logged zero times, it surfaces as DEAD_ADOPTION.
TRACKED_CALLABLES_FOR_ADOPTION = (
    "vault_resume_context",
    "vault_exploit_context",
    "vault_harness_context",
    "vault_knowledge_gap_context",
    "vault_function_mindset",
    "vault_function_signature_shape",
    "vault_function_shape_attack_evidence",
    "vault_cross_language_pattern_lift",
    "vault_hackerman_chain_candidates",
    "vault_hackerman_exploit_predicates",
    "vault_hackerman_go_cosmos_inventory",
    "vault_chained_attack_plan_context",
    "vault_toolsite_context",
    "vault_hacker_brief_for_lane",
    "vault_hacker_brief_for_lane_v2",
    "vault_hacker_brief_for_lane_v3",
    "vault_attack_class_evidence",
    "vault_attack_class_evidence_v2",
    "vault_attack_class_evidence_v3",
    "vault_hackerman_detector_relationships",
    "vault_severity_calibration",
    "vault_detector_action_graph_context",
    "vault_high_impact_execution_bridge_context",
    "vault_poc_execution_record_context",
    "vault_cosmos_evidence_pack_context",
    "vault_solidity_detector_proof_context",
    "vault_loop_finalization_check",
    "vault_hackerman_novel_vector_context",
    "vault_current_to_exploit_conversion_gate_context",
    "vault_exploit_queue_context",
    "vault_exploit_severity_scope_oracle",
    "vault_poc_falsification_context",
    "vault_agent_artifact_mining_context",
    "vault_audit_deep_manifest_summary",
    "vault_mcp_explorer_context",
    "vault_originality_before_proof_gate",
    "vault_high_plus_submission_gate",
    "vault_proof_artifact_index_context",
)
ADOPTION_LOW_THRESHOLD = 3
ADOPTION_LOG_FILENAME = "mcp_call_log.jsonl"


def _collect_adoption_counts(
    *,
    workspace: Path | None,
    extra_log_paths: list[Path] | None = None,
) -> dict[str, int]:
    """Walk MCP call logs and return {callable_name: count}.

    Sources tried (in order):
      - <workspace>/.auditooor/mcp_call_log.jsonl when workspace provided
      - extra_log_paths if supplied (used by tests + capability-adoption-status)
      - $AUDITOOOR_MCP_CALL_LOG_PATHS (newline-separated abs paths) if set
    """
    log_paths: list[Path] = []
    if workspace is not None:
        candidate = workspace.expanduser() / ".auditooor" / ADOPTION_LOG_FILENAME
        if candidate.is_file():
            log_paths.append(candidate)
    if extra_log_paths:
        log_paths.extend(p for p in extra_log_paths if p.is_file())
    env_paths = os.environ.get("AUDITOOOR_MCP_CALL_LOG_PATHS", "").strip()
    if env_paths:
        for raw in env_paths.split("\n"):
            raw = raw.strip()
            if raw:
                p = Path(raw)
                if p.is_file():
                    log_paths.append(p)

    # No log surface at all → return empty dict so `if adoption_counts:`
    # falsy-skips adoption-gap emission for workspaces without telemetry.
    if not log_paths:
        return {}

    counts: dict[str, int] = {name: 0 for name in TRACKED_CALLABLES_FOR_ADOPTION}
    for log_path in log_paths:
        try:
            with log_path.open("r", encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except Exception:
                        continue
                    name = row.get("callable")
                    if isinstance(name, str) and name in counts:
                        counts[name] += 1
        except Exception:
            continue
    return counts


def _line_count(path: Path) -> int:
    if not path.is_file():
        return 0
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        return sum(1 for line in handle if line.strip())


def _mtime_utc(path: Path) -> str:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except OSError:
        return ""


def _parse_utc_timestamp(value: str) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _sidecar_generated_at(row: dict[str, Any]) -> str:
    for key in ("generated_at", "generated_at_utc", "_generated_at"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _sidecar_status(path: Path, *, data_row_key: str | None = None) -> dict[str, Any]:
    exists = path.is_file()
    rows = 0
    invalid_rows = 0
    generated_at = ""
    if exists:
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    if data_row_key is None:
                        rows += 1
                    try:
                        parsed = json.loads(line)
                    except json.JSONDecodeError:
                        invalid_rows += 1
                        continue
                    if isinstance(parsed, dict):
                        if data_row_key is not None and parsed.get(data_row_key):
                            rows += 1
                        if not generated_at:
                            generated_at = _sidecar_generated_at(parsed)
                    else:
                        invalid_rows += 1
        except OSError:
            exists = False
            rows = 0

    mtime = _mtime_utc(path) if exists else ""
    freshness_basis = "missing"
    freshness_class = "missing"
    if exists:
        if rows <= 0:
            freshness_basis = "empty"
            freshness_class = "empty"
        else:
            freshness_basis = "generated_at" if generated_at else "mtime"
            timestamp = _parse_utc_timestamp(generated_at) if generated_at else _parse_utc_timestamp(mtime)
            if timestamp is None:
                freshness_class = "unknown"
            else:
                age_seconds = (datetime.now(timezone.utc) - timestamp).total_seconds()
                freshness_class = "stale" if age_seconds > SIDECAR_STALE_AFTER_SECONDS else "fresh"

    return {
        "path": str(path.relative_to(REPO_ROOT) if path.is_relative_to(REPO_ROOT) else path),
        "exists": exists,
        "rows": rows,
        "invalid_rows": invalid_rows,
        "mtime_utc": mtime,
        "generated_at": generated_at,
        "freshness_class": freshness_class,
        "freshness_basis": freshness_basis,
        "stale_after_seconds": SIDECAR_STALE_AFTER_SECONDS,
    }


def _proof_artifact_index_summary(path: Path) -> OrderedDict[str, Any]:
    promotion_ready_rows: int | None = None
    blocker_histogram: Counter[str] = Counter()
    blocker_rows = 0
    promotion_fields_seen = False
    rows = 0

    if path.is_file():
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    try:
                        parsed = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(parsed, dict):
                        continue
                    rows += 1
                    if "promotion_ready" not in parsed and "promotion_blockers" not in parsed:
                        continue
                    promotion_fields_seen = True
                    if bool(parsed.get("promotion_ready")):
                        promotion_ready_rows = (promotion_ready_rows or 0) + 1
                    blockers = parsed.get("promotion_blockers")
                    if isinstance(blockers, list) and blockers:
                        blocker_rows += 1
                        for blocker in blockers:
                            if isinstance(blocker, str) and blocker:
                                blocker_histogram[blocker] += 1
        except OSError:
            pass

    return OrderedDict(
        [
            ("promotion_ready_available", promotion_fields_seen),
            ("promotion_ready_rows", promotion_ready_rows if promotion_fields_seen else None),
            ("promotion_blocker_rows", blocker_rows if promotion_fields_seen else 0),
            (
                "promotion_blocker_histogram",
                dict(sorted(blocker_histogram.items(), key=lambda item: (-item[1], item[0]))),
            ),
            ("promotion_index_rows", rows),
        ]
    )


def _proof_artifact_import_queue_summary(root: Path) -> OrderedDict[str, Any]:
    reports_dir = root / "reports"
    paths = sorted(reports_dir.glob("proof_artifact_missing_record_import_queue*.jsonl")) if reports_dir.is_dir() else []
    packet_paths = (
        sorted(reports_dir.glob("proof_artifact_missing_record_review_packets*.jsonl"))
        if reports_dir.is_dir()
        else []
    )
    proposal_paths = (
        sorted(reports_dir.glob("proof_artifact_record_proposals*_summary.json"))
        if reports_dir.is_dir()
        else []
    )
    promotion_review_paths = (
        sorted(reports_dir.glob("proof_artifact_promotion_review*.jsonl"))
        if reports_dir.is_dir()
        else []
    )
    status_only_paths = (
        sorted(reports_dir.glob("proof_artifact_status_only_review*.jsonl"))
        if reports_dir.is_dir()
        else []
    )
    status_only_reconciliation_paths = (
        sorted(reports_dir.glob("proof_artifact_status_only_reconciliation*.jsonl"))
        if reports_dir.is_dir()
        else []
    )
    valid_paths: list[Path] = []
    valid_packet_paths: list[Path] = []
    valid_promotion_review_paths: list[Path] = []
    valid_status_only_paths: list[Path] = []
    valid_status_only_reconciliation_paths: list[Path] = []
    invalid_rows = 0
    packet_invalid_rows = 0
    promotion_review_invalid_rows = 0
    status_only_invalid_rows = 0
    status_only_reconciliation_invalid_rows = 0
    all_rows = 0
    all_candidates = 0
    by_engagement: Counter[str] = Counter()
    packet_rows = 0
    packet_candidates = 0
    packet_status_counts: Counter[str] = Counter()
    packet_by_engagement: Counter[str] = Counter()
    promotion_review_rows = 0
    promotion_review_action_counts: Counter[str] = Counter()
    promotion_review_apply_status_counts: Counter[str] = Counter()
    promotion_review_blockers: Counter[str] = Counter()
    promotion_review_by_engagement: Counter[str] = Counter()
    promotion_review_ready_to_apply = 0
    status_only_rows = 0
    status_only_review_status_counts: Counter[str] = Counter()
    status_only_recommended_action_counts: Counter[str] = Counter()
    status_only_submission_status_counts: Counter[str] = Counter()
    status_only_by_engagement: Counter[str] = Counter()
    status_only_reconciliation_rows = 0
    status_only_reconciliation_candidates = 0
    status_only_reconciliation_status_counts: Counter[str] = Counter()
    status_only_reconciliation_submission_status_counts: Counter[str] = Counter()
    status_only_reconciliation_by_engagement: Counter[str] = Counter()
    status_only_reconciliation_mutation_allowed = 0

    for path in paths:
        file_has_valid_row = False
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line in lines:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                invalid_rows += 1
                continue
            if not isinstance(row, dict):
                invalid_rows += 1
                continue
            if row.get("schema") != "auditooor.hackerman_missing_record_import_queue.v1":
                continue
            file_has_valid_row = True
            all_rows += 1
            try:
                all_candidates += int(row.get("candidate_count") or 0)
            except (TypeError, ValueError):
                pass
            engagement = str(row.get("engagement") or "_unknown")
            by_engagement[engagement] += 1
        if file_has_valid_row:
            valid_paths.append(path)

    for path in packet_paths:
        file_has_valid_row = False
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line in lines:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                packet_invalid_rows += 1
                continue
            if not isinstance(row, dict):
                packet_invalid_rows += 1
                continue
            if row.get("schema") != "auditooor.hackerman_missing_record_review_packet.v1":
                continue
            file_has_valid_row = True
            packet_rows += 1
            status = str(row.get("validation_status") or "_unknown")
            packet_status_counts[status] += 1
            packet_by_engagement[str(row.get("engagement") or "_unknown")] += 1
            candidates = row.get("artifact_candidates")
            if isinstance(candidates, list):
                packet_candidates += len(candidates)
        if file_has_valid_row:
            valid_packet_paths.append(path)

    for path in promotion_review_paths:
        file_has_valid_row = False
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line in lines:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                promotion_review_invalid_rows += 1
                continue
            if not isinstance(row, dict):
                promotion_review_invalid_rows += 1
                continue
            if row.get("schema") != "auditooor.hackerman_proof_artifact_promotion_review_plan.v1":
                continue
            file_has_valid_row = True
            promotion_review_rows += 1
            action = str(row.get("action") or "_unknown")
            apply_status = str(row.get("apply_status") or "_unknown")
            promotion_review_action_counts[action] += 1
            promotion_review_apply_status_counts[apply_status] += 1
            promotion_review_by_engagement[str(row.get("engagement") or "_unknown")] += 1
            if apply_status == "ready_to_apply" or action == "apply_proof_artifact_path":
                promotion_review_ready_to_apply += 1
            blockers = row.get("blockers")
            if isinstance(blockers, list):
                for blocker in blockers:
                    if isinstance(blocker, str) and blocker:
                        promotion_review_blockers[blocker] += 1
        if file_has_valid_row:
            valid_promotion_review_paths.append(path)

    for path in status_only_paths:
        file_has_valid_row = False
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line in lines:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                status_only_invalid_rows += 1
                continue
            if not isinstance(row, dict):
                status_only_invalid_rows += 1
                continue
            if row.get("schema") != "auditooor.hackerman_proof_artifact_status_only_review.v1":
                continue
            file_has_valid_row = True
            status_only_rows += 1
            status_only_review_status_counts[str(row.get("review_status") or "_unknown")] += 1
            status_only_recommended_action_counts[str(row.get("recommended_action") or "_unknown")] += 1
            status_only_submission_status_counts[str(row.get("submission_status") or "_unknown")] += 1
            status_only_by_engagement[str(row.get("engagement") or "_unknown")] += 1
        if file_has_valid_row:
            valid_status_only_paths.append(path)

    for path in status_only_reconciliation_paths:
        file_has_valid_row = False
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line in lines:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                status_only_reconciliation_invalid_rows += 1
                continue
            if not isinstance(row, dict):
                status_only_reconciliation_invalid_rows += 1
                continue
            if row.get("schema") != "auditooor.hackerman_proof_artifact_status_only_reconciliation.v1":
                continue
            file_has_valid_row = True
            status_only_reconciliation_rows += 1
            status_only_reconciliation_status_counts[str(row.get("reconciliation_status") or "_unknown")] += 1
            status_only_reconciliation_submission_status_counts[str(row.get("submission_status") or "_unknown")] += 1
            status_only_reconciliation_by_engagement[str(row.get("engagement") or "_unknown")] += 1
            if bool(row.get("mutation_allowed")):
                status_only_reconciliation_mutation_allowed += 1
            try:
                status_only_reconciliation_candidates += int(row.get("candidate_count") or 0)
            except (TypeError, ValueError):
                pass
        if file_has_valid_row:
            valid_status_only_reconciliation_paths.append(path)

    latest_path = max(valid_paths, key=lambda path: path.stat().st_mtime) if valid_paths else None
    latest_rows = 0
    latest_candidates = 0
    latest_by_engagement: Counter[str] = Counter()
    if latest_path is not None:
        try:
            for line in latest_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(row, dict) or row.get("schema") != "auditooor.hackerman_missing_record_import_queue.v1":
                    continue
                latest_rows += 1
                try:
                    latest_candidates += int(row.get("candidate_count") or 0)
                except (TypeError, ValueError):
                    pass
                latest_by_engagement[str(row.get("engagement") or "_unknown")] += 1
        except OSError:
            latest_path = None

    latest_packet_path = max(valid_packet_paths, key=lambda path: path.stat().st_mtime) if valid_packet_paths else None
    latest_packet_rows = 0
    latest_packet_candidates = 0
    latest_packet_status_counts: Counter[str] = Counter()
    latest_packet_by_engagement: Counter[str] = Counter()
    if latest_packet_path is not None:
        try:
            for line in latest_packet_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(row, dict) or row.get("schema") != "auditooor.hackerman_missing_record_review_packet.v1":
                    continue
                latest_packet_rows += 1
                latest_packet_status_counts[str(row.get("validation_status") or "_unknown")] += 1
                latest_packet_by_engagement[str(row.get("engagement") or "_unknown")] += 1
                candidates = row.get("artifact_candidates")
                if isinstance(candidates, list):
                    latest_packet_candidates += len(candidates)
        except OSError:
            latest_packet_path = None

    latest_promotion_review_path = (
        max(valid_promotion_review_paths, key=lambda path: path.stat().st_mtime)
        if valid_promotion_review_paths
        else None
    )
    latest_promotion_review_rows = 0
    latest_promotion_review_action_counts: Counter[str] = Counter()
    latest_promotion_review_apply_status_counts: Counter[str] = Counter()
    latest_promotion_review_blockers: Counter[str] = Counter()
    latest_promotion_review_by_engagement: Counter[str] = Counter()
    latest_promotion_review_ready_to_apply = 0
    if latest_promotion_review_path is not None:
        try:
            for line in latest_promotion_review_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(row, dict) or row.get("schema") != "auditooor.hackerman_proof_artifact_promotion_review_plan.v1":
                    continue
                latest_promotion_review_rows += 1
                action = str(row.get("action") or "_unknown")
                apply_status = str(row.get("apply_status") or "_unknown")
                latest_promotion_review_action_counts[action] += 1
                latest_promotion_review_apply_status_counts[apply_status] += 1
                latest_promotion_review_by_engagement[str(row.get("engagement") or "_unknown")] += 1
                if apply_status == "ready_to_apply" or action == "apply_proof_artifact_path":
                    latest_promotion_review_ready_to_apply += 1
                blockers = row.get("blockers")
                if isinstance(blockers, list):
                    for blocker in blockers:
                        if isinstance(blocker, str) and blocker:
                            latest_promotion_review_blockers[blocker] += 1
        except OSError:
            latest_promotion_review_path = None

    latest_status_only_path = (
        max(valid_status_only_paths, key=lambda path: path.stat().st_mtime)
        if valid_status_only_paths
        else None
    )
    latest_status_only_rows = 0
    latest_status_only_review_status_counts: Counter[str] = Counter()
    latest_status_only_recommended_action_counts: Counter[str] = Counter()
    latest_status_only_submission_status_counts: Counter[str] = Counter()
    latest_status_only_by_engagement: Counter[str] = Counter()
    if latest_status_only_path is not None:
        try:
            for line in latest_status_only_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(row, dict) or row.get("schema") != "auditooor.hackerman_proof_artifact_status_only_review.v1":
                    continue
                latest_status_only_rows += 1
                latest_status_only_review_status_counts[str(row.get("review_status") or "_unknown")] += 1
                latest_status_only_recommended_action_counts[str(row.get("recommended_action") or "_unknown")] += 1
                latest_status_only_submission_status_counts[str(row.get("submission_status") or "_unknown")] += 1
                latest_status_only_by_engagement[str(row.get("engagement") or "_unknown")] += 1
        except OSError:
            latest_status_only_path = None

    latest_status_only_reconciliation_path = (
        max(valid_status_only_reconciliation_paths, key=lambda path: path.stat().st_mtime)
        if valid_status_only_reconciliation_paths
        else None
    )
    latest_status_only_reconciliation_rows = 0
    latest_status_only_reconciliation_candidates = 0
    latest_status_only_reconciliation_status_counts: Counter[str] = Counter()
    latest_status_only_reconciliation_submission_status_counts: Counter[str] = Counter()
    latest_status_only_reconciliation_by_engagement: Counter[str] = Counter()
    latest_status_only_reconciliation_mutation_allowed = 0
    if latest_status_only_reconciliation_path is not None:
        try:
            for line in latest_status_only_reconciliation_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(row, dict) or row.get("schema") != "auditooor.hackerman_proof_artifact_status_only_reconciliation.v1":
                    continue
                latest_status_only_reconciliation_rows += 1
                latest_status_only_reconciliation_status_counts[str(row.get("reconciliation_status") or "_unknown")] += 1
                latest_status_only_reconciliation_submission_status_counts[str(row.get("submission_status") or "_unknown")] += 1
                latest_status_only_reconciliation_by_engagement[str(row.get("engagement") or "_unknown")] += 1
                if bool(row.get("mutation_allowed")):
                    latest_status_only_reconciliation_mutation_allowed += 1
                try:
                    latest_status_only_reconciliation_candidates += int(row.get("candidate_count") or 0)
                except (TypeError, ValueError):
                    pass
        except OSError:
            latest_status_only_reconciliation_path = None

    valid_proposal_paths: list[Path] = []
    proposal_invalid_files = 0
    proposal_records_built = 0
    proposal_records_emitted = 0
    for path in proposal_paths:
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, json.JSONDecodeError):
            proposal_invalid_files += 1
            continue
        if not isinstance(data, dict) or data.get("schema") != "auditooor.hackerman_proof_artifact_record_proposals.v1":
            proposal_invalid_files += 1
            continue
        valid_proposal_paths.append(path)
        try:
            proposal_records_built += int(data.get("records_built") or 0)
            proposal_records_emitted += int(data.get("records_emitted") or 0)
        except (TypeError, ValueError):
            pass

    latest_proposal_path = max(valid_proposal_paths, key=lambda path: path.stat().st_mtime) if valid_proposal_paths else None
    latest_proposal_records_built = 0
    latest_proposal_records_emitted = 0
    latest_proposal_records_existing = 0
    latest_proposal_files = 0
    latest_proposal_files_existing = 0
    latest_proposal_collision_files = 0
    latest_proposal_collision_files_existing = 0
    latest_proposal_missing_files: list[str] = []
    latest_proposal_packets_path = ""
    latest_proposal_packets_sha256 = ""
    latest_proposal_generated_at = ""
    latest_proposal_conversion_status = ""
    latest_proposal_failed_count = 0
    latest_proposal_dry_run = False
    latest_proposal_current_for_packet = False
    if latest_proposal_path is not None:
        try:
            latest_data = json.loads(latest_proposal_path.read_text(encoding="utf-8", errors="ignore"))
            latest_proposal_generated_at = str(latest_data.get("generated_at_utc") or latest_data.get("generated_at") or "")
            latest_proposal_conversion_status = str(latest_data.get("conversion_status") or "")
            latest_proposal_failed_count = int(latest_data.get("failed_count") or 0)
            latest_proposal_records_built = int(latest_data.get("records_built") or 0)
            latest_proposal_records_emitted = int(latest_data.get("records_emitted") or 0)
            latest_proposal_records_existing = int(latest_data.get("records_existing") or 0)
            latest_proposal_packets_path = str(latest_data.get("packets_path") or "")
            latest_proposal_packets_sha256 = str(latest_data.get("packets_sha256") or "")
            latest_proposal_dry_run = bool(latest_data.get("dry_run"))
            files = latest_data.get("files")
            if isinstance(files, list):
                latest_proposal_files = len(files)
                for raw in files:
                    rel = str(raw or "")
                    if not rel:
                        continue
                    candidate = root / rel
                    if candidate.is_file():
                        latest_proposal_files_existing += 1
                    else:
                        latest_proposal_missing_files.append(rel)
            collisions = latest_data.get("collisions")
            if isinstance(collisions, list):
                latest_proposal_collision_files = len(collisions)
                for raw in collisions:
                    rel = str(raw or "")
                    if not rel:
                        continue
                    candidate = root / rel
                    if candidate.is_file():
                        latest_proposal_collision_files_existing += 1
            if latest_proposal_packets_path:
                packet_candidate = root / latest_proposal_packets_path
                if packet_candidate.is_file():
                    latest_proposal_current_for_packet = latest_proposal_path.stat().st_mtime >= packet_candidate.stat().st_mtime
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            latest_proposal_path = None

    return OrderedDict(
        [
            (
                "exists",
                bool(
                    valid_paths
                    or valid_packet_paths
                    or valid_proposal_paths
                    or valid_promotion_review_paths
                    or valid_status_only_paths
                    or valid_status_only_reconciliation_paths
                ),
            ),
            ("queue_files", [str(path.relative_to(root)) for path in valid_paths]),
            ("latest_queue_path", str(latest_path.relative_to(root)) if latest_path is not None else ""),
            ("latest_queue_mtime_utc", _mtime_utc(latest_path) if latest_path is not None else ""),
            ("latest_queue_rows", latest_rows),
            ("latest_candidate_count", latest_candidates),
            ("latest_by_engagement", dict(sorted(latest_by_engagement.items()))),
            ("total_queue_rows", all_rows),
            ("total_candidate_count", all_candidates),
            ("total_by_engagement", dict(sorted(by_engagement.items()))),
            ("invalid_rows", invalid_rows),
            ("review_packets_exist", bool(valid_packet_paths)),
            ("review_packet_files", [str(path.relative_to(root)) for path in valid_packet_paths]),
            (
                "latest_review_packet_path",
                str(latest_packet_path.relative_to(root)) if latest_packet_path is not None else "",
            ),
            ("latest_review_packet_mtime_utc", _mtime_utc(latest_packet_path) if latest_packet_path is not None else ""),
            ("latest_review_packet_rows", latest_packet_rows),
            ("latest_review_packet_candidate_count", latest_packet_candidates),
            ("latest_review_packet_status_counts", dict(sorted(latest_packet_status_counts.items()))),
            ("latest_review_packet_by_engagement", dict(sorted(latest_packet_by_engagement.items()))),
            ("total_review_packet_rows", packet_rows),
            ("total_review_packet_candidate_count", packet_candidates),
            ("total_review_packet_status_counts", dict(sorted(packet_status_counts.items()))),
            ("total_review_packet_by_engagement", dict(sorted(packet_by_engagement.items()))),
            ("review_packet_invalid_rows", packet_invalid_rows),
            ("promotion_review_exists", bool(valid_promotion_review_paths)),
            ("promotion_review_files", [str(path.relative_to(root)) for path in valid_promotion_review_paths]),
            (
                "latest_promotion_review_path",
                str(latest_promotion_review_path.relative_to(root)) if latest_promotion_review_path is not None else "",
            ),
            ("latest_promotion_review_mtime_utc", _mtime_utc(latest_promotion_review_path) if latest_promotion_review_path is not None else ""),
            ("latest_promotion_review_rows", latest_promotion_review_rows),
            ("latest_promotion_review_ready_to_apply", latest_promotion_review_ready_to_apply),
            ("latest_promotion_review_safe_to_auto_apply", False),
            ("latest_promotion_review_action_counts", dict(sorted(latest_promotion_review_action_counts.items()))),
            ("latest_promotion_review_apply_status_counts", dict(sorted(latest_promotion_review_apply_status_counts.items()))),
            ("latest_promotion_review_blocker_histogram", dict(sorted(latest_promotion_review_blockers.items(), key=lambda item: (-item[1], item[0])))),
            ("latest_promotion_review_by_engagement", dict(sorted(latest_promotion_review_by_engagement.items()))),
            ("total_promotion_review_rows", promotion_review_rows),
            ("total_promotion_review_ready_to_apply", promotion_review_ready_to_apply),
            ("total_promotion_review_action_counts", dict(sorted(promotion_review_action_counts.items()))),
            ("total_promotion_review_apply_status_counts", dict(sorted(promotion_review_apply_status_counts.items()))),
            ("total_promotion_review_blocker_histogram", dict(sorted(promotion_review_blockers.items(), key=lambda item: (-item[1], item[0])))),
            ("total_promotion_review_by_engagement", dict(sorted(promotion_review_by_engagement.items()))),
            ("promotion_review_invalid_rows", promotion_review_invalid_rows),
            ("status_only_review_exists", bool(valid_status_only_paths)),
            ("status_only_review_files", [str(path.relative_to(root)) for path in valid_status_only_paths]),
            (
                "latest_status_only_review_path",
                str(latest_status_only_path.relative_to(root)) if latest_status_only_path is not None else "",
            ),
            ("latest_status_only_review_mtime_utc", _mtime_utc(latest_status_only_path) if latest_status_only_path is not None else ""),
            ("latest_status_only_review_rows", latest_status_only_rows),
            ("latest_status_only_review_status_counts", dict(sorted(latest_status_only_review_status_counts.items()))),
            ("latest_status_only_recommended_action_counts", dict(sorted(latest_status_only_recommended_action_counts.items()))),
            ("latest_status_only_submission_status_counts", dict(sorted(latest_status_only_submission_status_counts.items()))),
            ("latest_status_only_by_engagement", dict(sorted(latest_status_only_by_engagement.items()))),
            ("total_status_only_review_rows", status_only_rows),
            ("total_status_only_review_status_counts", dict(sorted(status_only_review_status_counts.items()))),
            ("total_status_only_recommended_action_counts", dict(sorted(status_only_recommended_action_counts.items()))),
            ("total_status_only_submission_status_counts", dict(sorted(status_only_submission_status_counts.items()))),
            ("total_status_only_by_engagement", dict(sorted(status_only_by_engagement.items()))),
            ("status_only_invalid_rows", status_only_invalid_rows),
            ("status_only_reconciliation_exists", bool(valid_status_only_reconciliation_paths)),
            ("status_only_reconciliation_files", [str(path.relative_to(root)) for path in valid_status_only_reconciliation_paths]),
            (
                "latest_status_only_reconciliation_path",
                str(latest_status_only_reconciliation_path.relative_to(root)) if latest_status_only_reconciliation_path is not None else "",
            ),
            ("latest_status_only_reconciliation_mtime_utc", _mtime_utc(latest_status_only_reconciliation_path) if latest_status_only_reconciliation_path is not None else ""),
            ("latest_status_only_reconciliation_rows", latest_status_only_reconciliation_rows),
            ("latest_status_only_reconciliation_candidate_count", latest_status_only_reconciliation_candidates),
            (
                "latest_status_only_reconciliation_resolved_record_count",
                latest_status_only_reconciliation_status_counts.get(
                    "record_resolved_needs_owner_confirmation", 0
                ),
            ),
            ("latest_status_only_reconciliation_mutation_allowed_rows", latest_status_only_reconciliation_mutation_allowed),
            ("latest_status_only_reconciliation_status_counts", dict(sorted(latest_status_only_reconciliation_status_counts.items()))),
            ("latest_status_only_reconciliation_submission_status_counts", dict(sorted(latest_status_only_reconciliation_submission_status_counts.items()))),
            ("latest_status_only_reconciliation_by_engagement", dict(sorted(latest_status_only_reconciliation_by_engagement.items()))),
            ("total_status_only_reconciliation_rows", status_only_reconciliation_rows),
            ("total_status_only_reconciliation_candidate_count", status_only_reconciliation_candidates),
            (
                "total_status_only_reconciliation_resolved_record_count",
                status_only_reconciliation_status_counts.get("record_resolved_needs_owner_confirmation", 0),
            ),
            ("total_status_only_reconciliation_mutation_allowed_rows", status_only_reconciliation_mutation_allowed),
            ("total_status_only_reconciliation_status_counts", dict(sorted(status_only_reconciliation_status_counts.items()))),
            ("total_status_only_reconciliation_submission_status_counts", dict(sorted(status_only_reconciliation_submission_status_counts.items()))),
            ("total_status_only_reconciliation_by_engagement", dict(sorted(status_only_reconciliation_by_engagement.items()))),
            ("status_only_reconciliation_invalid_rows", status_only_reconciliation_invalid_rows),
            ("record_proposals_exist", bool(valid_proposal_paths)),
            ("record_proposal_files", [str(path.relative_to(root)) for path in valid_proposal_paths]),
            (
                "latest_record_proposal_path",
                str(latest_proposal_path.relative_to(root)) if latest_proposal_path is not None else "",
            ),
            ("latest_record_proposal_mtime_utc", _mtime_utc(latest_proposal_path) if latest_proposal_path is not None else ""),
            ("latest_record_proposal_records_built", latest_proposal_records_built),
            ("latest_record_proposal_records_emitted", latest_proposal_records_emitted),
            ("latest_record_proposal_records_existing", latest_proposal_records_existing),
            ("latest_record_proposal_failed_count", latest_proposal_failed_count),
            ("latest_record_proposal_files", latest_proposal_files),
            ("latest_record_proposal_files_existing", latest_proposal_files_existing),
            ("latest_record_proposal_collision_files", latest_proposal_collision_files),
            ("latest_record_proposal_collision_files_existing", latest_proposal_collision_files_existing),
            ("latest_record_proposal_missing_files", latest_proposal_missing_files),
            ("latest_record_proposal_packets_path", latest_proposal_packets_path),
            ("latest_record_proposal_packets_sha256", latest_proposal_packets_sha256),
            ("latest_record_proposal_generated_at", latest_proposal_generated_at),
            ("latest_record_proposal_conversion_status", latest_proposal_conversion_status),
            ("latest_record_proposal_dry_run", latest_proposal_dry_run),
            ("latest_record_proposal_current_for_packet", latest_proposal_current_for_packet),
            ("total_record_proposal_records_built", proposal_records_built),
            ("total_record_proposal_records_emitted", proposal_records_emitted),
            ("record_proposal_invalid_files", proposal_invalid_files),
        ]
    )


def _scoreboard_timestamp(data: dict[str, Any], path: Path) -> datetime | None:
    generated_at = str(data.get("generated_at") or "").strip()
    parsed = _parse_utc_timestamp(generated_at)
    if parsed is not None:
        return parsed
    mtime = _mtime_utc(path)
    return _parse_utc_timestamp(mtime)


def _scoreboard_external_metrics(data: dict[str, Any]) -> tuple[int, float | None]:
    overall = data.get("overall") if isinstance(data.get("overall"), dict) else {}
    by_origin = overall.get("by_origin") if isinstance(overall.get("by_origin"), dict) else {}
    external = by_origin.get("external_repo") if isinstance(by_origin.get("external_repo"), dict) else {}
    raw_scorable = external.get("held_out_scorable")
    if raw_scorable is None:
        raw_scorable = overall.get("held_out_scorable")
    try:
        scorable = int(raw_scorable or 0)
    except (TypeError, ValueError):
        scorable = 0

    raw_same_class = external.get("realworld_recall_same_class")
    if raw_same_class is None:
        raw_same_class = overall.get("realworld_recall_same_class")
    try:
        same_class = float(raw_same_class)
    except (TypeError, ValueError):
        same_class = None
    return scorable, same_class


def _scoreboard_entry(path: Path, data: dict[str, Any], root: Path) -> OrderedDict[str, Any]:
    scorable, same_class = _scoreboard_external_metrics(data)
    timestamp = _scoreboard_timestamp(data, path)
    manifest_path = str(data.get("external_manifest") or "")
    return OrderedDict(
        [
            ("path", str(path.relative_to(root))),
            ("generated_at", str(data.get("generated_at") or "")),
            ("timestamp_utc", timestamp.strftime("%Y-%m-%dT%H:%M:%SZ") if timestamp is not None else ""),
            ("manifest_path", manifest_path),
            ("manifest_basename", Path(manifest_path).name if manifest_path else ""),
            ("scorable_samples", scorable),
            ("same_class_recall", same_class),
            ("same_class_recall_pct", round(same_class * 100, 1) if same_class is not None else None),
        ]
    )


def _pick_latest_scoreboard_entry(entries: list[OrderedDict[str, Any]]) -> OrderedDict[str, Any] | None:
    if not entries:
        return None
    best_entry: OrderedDict[str, Any] | None = None
    best_timestamp: datetime | None = None
    for entry in entries:
        current = _parse_utc_timestamp(str(entry.get("timestamp_utc") or entry.get("generated_at") or ""))
        if best_entry is None or (current is not None and (best_timestamp is None or current > best_timestamp)):
            best_entry = entry
            best_timestamp = current
    return best_entry or entries[-1]


def _sidecar_freshness_rollup(sidecars: OrderedDict[str, Any]) -> OrderedDict[str, Any]:
    counts: dict[str, int] = {}
    stale_or_missing: list[str] = []
    for name, sidecar in sidecars.items():
        freshness = str(sidecar.get("freshness_class") or "unknown")
        counts[freshness] = counts.get(freshness, 0) + 1
        if freshness != "fresh":
            stale_or_missing.append(name)
    return OrderedDict(
        [
            ("total", len(sidecars)),
            ("counts", OrderedDict(sorted(counts.items()))),
            ("healthy_count", counts.get("fresh", 0)),
            ("non_fresh", stale_or_missing),
        ]
    )


def _workspace_artifacts(workspace: Path | None) -> dict[str, Any]:
    if workspace is None:
        return {"workspace": None}
    auditooor_dir = workspace.expanduser() / ".auditooor"
    return {
        "workspace": str(workspace),
        "hacker_brief": (auditooor_dir / "hacker_brief.hackerman.json").is_file(),
        "audit_hacker_logic_bridge": (auditooor_dir / "audit_hacker_logic_bridge.json").is_file(),
        "proof_obligation_queue": (auditooor_dir / "proof_obligation_queue.json").is_file(),
    }


def _external_recall_sidecars(root: Path) -> OrderedDict[str, Any]:
    reports = root / "reports"
    manifest_paths = sorted(reports.glob("external_recall_samples*.json")) if reports.is_dir() else []
    scoreboard_paths = sorted(reports.glob("realworld_recall_scoreboard_external*.json")) if reports.is_dir() else []
    sample_keys: set[str] = set()
    manifests: list[str] = []
    scoreboards: list[str] = []
    scoreboard_entries: list[OrderedDict[str, Any]] = []

    for path in manifest_paths:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if data.get("schema") != "auditooor.external_recall_samples.v1":
            continue
        manifests.append(str(path.relative_to(root)))
        samples = data.get("samples")
        if isinstance(samples, list):
            for idx, sample in enumerate(samples):
                if not isinstance(sample, dict):
                    continue
                key = str(sample.get("id") or sample.get("path") or f"{path.name}:{idx}")
                sample_keys.add(key)

    for path in scoreboard_paths:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if data.get("schema") != "auditooor.realworld_recall_scoreboard.v1":
            continue
        scoreboards.append(str(path.relative_to(root)))
        scoreboard_entries.append(_scoreboard_entry(path, data, root))

    latest_entry = _pick_latest_scoreboard_entry(scoreboard_entries)
    phase_f_entries = [entry for entry in scoreboard_entries if "_phase_f" in str(entry.get("path") or "")]
    phase_f_baseline = next(
        (entry for entry in phase_f_entries if str(entry.get("path")) == "reports/realworld_recall_scoreboard_external_phase_f.json"),
        None,
    )
    phase_f_comparable_entries = []
    if phase_f_baseline is not None:
        baseline_manifest = str(phase_f_baseline.get("manifest_basename") or "")
        baseline_scorable = int(phase_f_baseline.get("scorable_samples") or 0)
        phase_f_comparable_entries = [
            entry
            for entry in phase_f_entries
            if str(entry.get("manifest_basename") or "") == baseline_manifest
            and int(entry.get("scorable_samples") or 0) == baseline_scorable
        ]
    latest_phase_f_comparable = _pick_latest_scoreboard_entry(phase_f_comparable_entries)
    phase_f_lift: OrderedDict[str, Any] | None = None
    if phase_f_baseline is not None and latest_phase_f_comparable is not None:
        baseline_pct = phase_f_baseline.get("same_class_recall_pct")
        latest_pct = latest_phase_f_comparable.get("same_class_recall_pct")
        delta_pct_points = None
        if isinstance(baseline_pct, (int, float)) and isinstance(latest_pct, (int, float)):
            delta_pct_points = round(float(latest_pct) - float(baseline_pct), 1)
        phase_f_lift = OrderedDict(
            [
                ("baseline", phase_f_baseline),
                ("latest_comparable", latest_phase_f_comparable),
                ("delta_pct_points", delta_pct_points),
            ]
        )

    return OrderedDict(
        [
            ("sample_count", len(sample_keys)),
            ("manifest_paths", manifests),
            ("scoreboard_paths", scoreboards),
            ("latest_scorable_samples", latest_entry.get("scorable_samples") if latest_entry else 0),
            ("latest_same_class_recall", latest_entry.get("same_class_recall") if latest_entry else None),
            (
                "latest_same_class_recall_pct",
                latest_entry.get("same_class_recall_pct") if latest_entry else None,
            ),
            ("latest_measurement", latest_entry),
            ("latest_phase_f_measurement", latest_phase_f_comparable or phase_f_baseline),
            ("phase_f_recall_lift", phase_f_lift),
        ]
    )


def _solodit_year_enrichment_status(root: Path) -> OrderedDict[str, Any]:
    reports = root / "reports"
    report_paths = (
        sorted(reports.glob("solodit_unknown_year*_2026-05-17.md"))
        + sorted(reports.glob("hackerman_solodit_year_sentinel_burndown_*.json"))
        if reports.is_dir()
        else []
    )
    queue_paths = sorted(reports.glob("solodit_date_enrichment_queue*.jsonl")) if reports.is_dir() else []
    tool_path = root / "tools" / "hackerman-backfill-solodit-years.py"
    queue_tool_path = root / "tools" / "hackerman-solodit-date-enrichment-queue.py"
    safe_audit_ready = any(
        path.name.startswith(("solodit_unknown_year_phase_b_", "solodit_unknown_year_enrichment_slice_"))
        for path in report_paths
    )
    return OrderedDict(
        [
            ("tool_exists", tool_path.is_file()),
            ("enrichment_queue_tool_exists", queue_tool_path.is_file()),
            ("safe_audit_ready", safe_audit_ready),
            ("classification", "source_data_blocked" if safe_audit_ready else "needs_safe_dry_run"),
            ("report_paths", [str(path.relative_to(root)) for path in report_paths]),
            ("queue_paths", [str(path.relative_to(root)) for path in queue_paths]),
            (
                "dry_run_command",
                "python3 tools/hackerman-backfill-solodit-years.py --dry-run --json-summary --candidates-path /tmp/solodit-year-backfill-current.jsonl",
            ),
            (
                "enrichment_queue_command",
                "make hackerman-solodit-date-enrichment-queue LIMIT=50 JSON=1",
            ),
        ]
    )


def _recall_scoreboard(root: Path) -> OrderedDict[str, Any]:
    """Return the compact real-world recall status, if a scoreboard exists."""
    path = root / "reports" / "realworld_recall_scoreboard.json"
    external_sidecars = _external_recall_sidecars(root)
    if not path.is_file():
        return OrderedDict(
            [
                ("path", str(path.relative_to(root))),
                ("exists", False),
                ("generated_at", ""),
                ("same_class_recall", None),
                ("same_class_recall_pct", None),
                ("scorable_samples", 0),
                ("has_external_repo_origin", False),
                ("external_repo_samples", 0),
                ("external_sidecar_samples", external_sidecars["sample_count"]),
                ("external_sidecars", external_sidecars),
            ]
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return OrderedDict(
            [
                ("path", str(path.relative_to(root))),
                ("exists", True),
                ("unreadable", True),
                ("generated_at", ""),
                ("same_class_recall", None),
                ("same_class_recall_pct", None),
                ("scorable_samples", 0),
                ("has_external_repo_origin", False),
                ("external_repo_samples", 0),
                ("external_sidecar_samples", external_sidecars["sample_count"]),
                ("external_sidecars", external_sidecars),
            ]
        )
    overall = data.get("overall") if isinstance(data.get("overall"), dict) else {}
    same_class = overall.get("realworld_recall_same_class")
    try:
        same_class_float = float(same_class)
    except (TypeError, ValueError):
        same_class_float = None
    by_origin = overall.get("by_origin") if isinstance(overall.get("by_origin"), dict) else {}
    external = by_origin.get("external_repo") if isinstance(by_origin.get("external_repo"), dict) else {}
    external_samples = int(external.get("held_out_samples_total") or external.get("scorable") or 0)
    return OrderedDict(
        [
            ("path", str(path.relative_to(root))),
            ("exists", True),
            ("generated_at", str(data.get("generated_at") or "")),
            ("same_class_recall", same_class_float),
            ("same_class_recall_pct", round(same_class_float * 100, 1) if same_class_float is not None else None),
            ("scorable_samples", int(overall.get("held_out_scorable") or 0)),
            ("has_external_repo_origin", external_samples > 0),
            ("external_repo_samples", external_samples),
            ("external_sidecar_samples", external_sidecars["sample_count"]),
            ("external_sidecars", external_sidecars),
        ]
    )


def _realworld_recall_work_queue_summary(root: Path) -> OrderedDict[str, Any]:
    reports = root / "reports"
    queue_paths = sorted(reports.glob("realworld_recall_work_queue*.jsonl")) if reports.is_dir() else []
    summary_paths = sorted(reports.glob("realworld_recall_work_queue*_summary.json")) if reports.is_dir() else []
    valid_queue_paths: list[Path] = []
    invalid_rows = 0
    total_rows = 0
    latest_queue_path: Path | None = None
    latest_queue_rows = 0
    latest_by_task_type: dict[str, int] = {}
    latest_by_attack_class: dict[str, int] = {}
    latest_by_status: dict[str, int] = {}
    latest_quality_blocked_rows = 0
    latest_quality_needs_validation_rows = 0
    latest_quality_disqualified_only_rows = 0
    latest_quality_report_paths: set[str] = set()

    for path in queue_paths:
        rows = 0
        by_task_type: dict[str, int] = {}
        by_attack_class: dict[str, int] = {}
        by_status: dict[str, int] = {}
        quality_blocked_rows = 0
        quality_needs_validation_rows = 0
        quality_disqualified_only_rows = 0
        quality_report_paths: set[str] = set()
        try:
            raw_lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for raw_line in raw_lines:
            line = raw_line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                invalid_rows += 1
                continue
            if not isinstance(row, dict) or row.get("schema") != "auditooor.realworld_recall_work_queue.row.v1":
                invalid_rows += 1
                continue
            rows += 1
            priority = row.get("source_priority") if isinstance(row.get("source_priority"), dict) else {}
            work_item = row.get("work_item") if isinstance(row.get("work_item"), dict) else {}
            attack_class = str(priority.get("attack_class") or "unknown")
            task_type = str(work_item.get("task_type") or "unknown")
            status = str(row.get("status") or "open")
            by_attack_class[attack_class] = by_attack_class.get(attack_class, 0) + 1
            by_task_type[task_type] = by_task_type.get(task_type, 0) + 1
            by_status[status] = by_status.get(status, 0) + 1
            quality = row.get("external_recall_quality") if isinstance(row.get("external_recall_quality"), dict) else {}
            if status == "quality_blocked" or bool(quality.get("quality_blocked")):
                quality_blocked_rows += 1
                if str(quality.get("quality_blocked_reason") or "") == "disqualified_source_state":
                    quality_disqualified_only_rows += 1
                elif int(quality.get("needs_source_state_validation") or 0) > 0:
                    quality_needs_validation_rows += 1
            for qpath in quality.get("quality_report_paths") or []:
                if isinstance(qpath, str) and qpath:
                    quality_report_paths.add(qpath)
        if rows:
            valid_queue_paths.append(path)
            total_rows += rows
            if latest_queue_path is None or path.stat().st_mtime >= latest_queue_path.stat().st_mtime:
                latest_queue_path = path
                latest_queue_rows = rows
                latest_by_task_type = by_task_type
                latest_by_attack_class = by_attack_class
                latest_by_status = by_status
                latest_quality_blocked_rows = quality_blocked_rows
                latest_quality_needs_validation_rows = quality_needs_validation_rows
                latest_quality_disqualified_only_rows = quality_disqualified_only_rows
                latest_quality_report_paths = quality_report_paths

    valid_summary_paths: list[Path] = []
    summary_invalid_files = 0
    latest_summary_path: Path | None = None
    latest_summary: dict[str, Any] = {}
    for path in summary_paths:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            summary_invalid_files += 1
            continue
        if not isinstance(data, dict) or data.get("schema") != "auditooor.realworld_recall_work_queue_summary.v1":
            summary_invalid_files += 1
            continue
        valid_summary_paths.append(path)
        if latest_summary_path is None or path.stat().st_mtime >= latest_summary_path.stat().st_mtime:
            latest_summary_path = path
            latest_summary = data

    priorities_path = root / "reports" / "realworld_recall_gap_priorities.json"
    current_for_priorities = False
    if latest_summary_path is not None and priorities_path.is_file():
        current_for_priorities = latest_summary_path.stat().st_mtime >= priorities_path.stat().st_mtime

    return OrderedDict(
        [
            ("exists", bool(valid_queue_paths)),
            ("queue_paths", [str(path.relative_to(root)) for path in valid_queue_paths]),
            ("latest_queue_path", str(latest_queue_path.relative_to(root)) if latest_queue_path else ""),
            ("latest_queue_rows", latest_queue_rows),
            ("latest_queue_by_task_type", dict(sorted(latest_by_task_type.items()))),
            ("latest_queue_by_attack_class", dict(sorted(latest_by_attack_class.items()))),
            ("latest_queue_by_status", dict(sorted(latest_by_status.items()))),
            ("latest_quality_blocked_rows", latest_quality_blocked_rows),
            ("latest_quality_needs_validation_rows", latest_quality_needs_validation_rows),
            ("latest_quality_disqualified_only_rows", latest_quality_disqualified_only_rows),
            ("latest_quality_report_paths", sorted(latest_quality_report_paths)),
            ("total_queue_rows", total_rows),
            ("invalid_rows", invalid_rows),
            ("summary_paths", [str(path.relative_to(root)) for path in valid_summary_paths]),
            ("latest_summary_path", str(latest_summary_path.relative_to(root)) if latest_summary_path else ""),
            ("latest_summary_rows_written", int(latest_summary.get("rows_written") or 0) if latest_summary else 0),
            ("latest_summary_dry_run", bool(latest_summary.get("dry_run")) if latest_summary else False),
            ("latest_summary_quality_blocked_rows", int(latest_summary.get("quality_blocked_rows") or 0) if latest_summary else 0),
            ("latest_summary_quality_needs_validation_rows", int(latest_summary.get("quality_needs_validation_rows") or 0) if latest_summary else 0),
            ("latest_summary_quality_disqualified_only_rows", int(latest_summary.get("quality_disqualified_only_rows") or 0) if latest_summary else 0),
            ("latest_summary_by_status", latest_summary.get("by_status") or {}),
            ("latest_summary_quality_report_paths", latest_summary.get("quality_report_paths") or []),
            ("latest_summary_current_for_priorities", current_for_priorities),
            ("summary_invalid_files", summary_invalid_files),
        ]
    )


def _normalize_scalar(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1].strip()
    return value


def _gap_detail(
    *,
    gap_id: str,
    severity: str,
    current: int,
    target: int,
    evidence: str,
    next_action: str,
    commands: list[str],
    roadmap_section: str,
    status: dict[str, Any] | None = None,
) -> OrderedDict[str, Any]:
    detail = OrderedDict(
        [
            ("id", gap_id),
            ("severity", severity),
            ("current", current),
            ("target", target),
            ("evidence", evidence),
            ("next_action", next_action),
            ("commands", commands),
            ("roadmap_section", roadmap_section),
        ]
    )
    if status is not None:
        detail["status"] = status
    return detail


def _known_gap_details(
    counters: dict[str, int],
    *,
    sidecars: dict[str, Any] | None = None,
    adoption_counts: dict[str, int] | None = None,
    recall_scoreboard: dict[str, Any] | None = None,
    realworld_work_queue: dict[str, Any] | None = None,
    solodit_year_enrichment: dict[str, Any] | None = None,
    proof_artifact_import_queue: dict[str, Any] | None = None,
) -> list[OrderedDict[str, Any]]:
    details: list[OrderedDict[str, Any]] = []
    go_cosmos_records = max(counters["exact_language_go"], counters["target_language_go"])
    proof_target = max(MIN_PROOF_ARTIFACT_TARGET, counters["yaml_tags"] // 100)
    cross_language_sidecar = (sidecars or {}).get("cross_language_analogues") or {}
    cross_language_sidecar_ready = bool(
        cross_language_sidecar.get("exists") and int(cross_language_sidecar.get("rows") or 0) > 0
    )

    if recall_scoreboard is not None:
        if not recall_scoreboard.get("exists"):
            details.append(
                _gap_detail(
                    gap_id="realworld_recall_scoreboard_missing",
                    severity="high",
                    current=0,
                    target=1,
                    evidence="No reports/realworld_recall_scoreboard.json exists, so detector generalization is not measured.",
                    next_action="Run the real-world recall scoreboard and inspect same-class recall before prioritizing detector work.",
                    commands=[
                        "python3 tools/audit/realworld-recall-scoreboard.py --out-dir reports",
                        "make capability-roadmap-status JSON=1",
                    ],
                    roadmap_section="Wave-7 candidates / Real-world recall measurement",
                )
            )
        else:
            same_class = recall_scoreboard.get("same_class_recall")
            if isinstance(same_class, (int, float)) and same_class < REALWORLD_SAME_CLASS_RECALL_TARGET:
                queue_exists = bool(realworld_work_queue and realworld_work_queue.get("exists"))
                queue_path = str((realworld_work_queue or {}).get("latest_queue_path") or "")
                queue_rows = int((realworld_work_queue or {}).get("latest_queue_rows") or 0)
                queue_current = bool((realworld_work_queue or {}).get("latest_summary_current_for_priorities"))
                quality_blocked_rows = int((realworld_work_queue or {}).get("latest_quality_blocked_rows") or 0)
                if not quality_blocked_rows:
                    quality_blocked_rows = int((realworld_work_queue or {}).get("latest_summary_quality_blocked_rows") or 0)
                quality_needs_validation_rows = int(
                    (realworld_work_queue or {}).get("latest_quality_needs_validation_rows") or 0
                )
                if not quality_needs_validation_rows:
                    quality_needs_validation_rows = int(
                        (realworld_work_queue or {}).get("latest_summary_quality_needs_validation_rows") or 0
                    )
                quality_disqualified_only_rows = int(
                    (realworld_work_queue or {}).get("latest_quality_disqualified_only_rows") or 0
                )
                if not quality_disqualified_only_rows:
                    quality_disqualified_only_rows = int(
                        (realworld_work_queue or {}).get("latest_summary_quality_disqualified_only_rows") or 0
                    )
                quality_paths = (realworld_work_queue or {}).get("latest_quality_report_paths") or (
                    realworld_work_queue or {}
                ).get("latest_summary_quality_report_paths") or []
                if quality_blocked_rows and quality_needs_validation_rows:
                    quality_note = (
                        f" {quality_needs_validation_rows} queue rows are quality-blocked pending vulnerable/pre-fix source-state evidence"
                        + (f" via {', '.join(str(path) for path in quality_paths[:2])}." if quality_paths else ".")
                    )
                elif quality_blocked_rows and quality_disqualified_only_rows:
                    quality_note = (
                        f" {quality_disqualified_only_rows} queue rows are quality-blocked because the current external samples are fixed/out-of-class"
                        + (f" via {', '.join(str(path) for path in quality_paths[:2])}." if quality_paths else ".")
                    )
                elif quality_blocked_rows:
                    quality_note = (
                        f" {quality_blocked_rows} queue rows are quality-blocked"
                        + (f" via {', '.join(str(path) for path in quality_paths[:2])}." if quality_paths else ".")
                    )
                else:
                    quality_note = ""
                queue_note = (
                    f" Work queue exists at {queue_path} with {queue_rows} rows; current_for_priorities={queue_current}."
                    if queue_exists
                    else ""
                )
                details.append(
                    _gap_detail(
                        gap_id="realworld_same_class_recall_low",
                        severity="high",
                        current=int(round(float(same_class) * 100)),
                        target=int(round(REALWORLD_SAME_CLASS_RECALL_TARGET * 100)),
                        evidence=(
                            f"Same-class real-world recall is {float(same_class) * 100:.1f}%, below the "
                            f"{REALWORLD_SAME_CLASS_RECALL_TARGET * 100:.0f}% roadmap threshold."
                            + queue_note
                            + quality_note
                        ),
                        next_action=(
                            "Resolve quality-blocked rows with vulnerable/pre-fix source-state evidence, work the remaining recall queue, then rerun the scoreboard/prioritizer."
                            if quality_needs_validation_rows and queue_exists and queue_current
                            else "Current quality report has no unknown validation rows; replace fixed/out-of-class external samples with vulnerable/pre-fix snapshots, then rerun the quality gate, scoreboard, and prioritizer."
                            if quality_disqualified_only_rows and queue_exists and queue_current
                            else "Resolve quality-blocked rows, work the remaining recall queue, then rerun the scoreboard/prioritizer."
                            if quality_blocked_rows and queue_exists and queue_current
                            else "Work the generated real-world recall queue rows, then rerun the scoreboard/prioritizer."
                            if queue_exists and queue_current
                            else "Generate a real-world recall work queue, then work weak attack classes and add external-repo samples."
                        ),
                        commands=[
                            "make realworld-recall-work-queue OUT=reports/realworld_recall_work_queue.jsonl JSON=1",
                            f"make realworld-recall-drilldown QUEUE={queue_path} JSON=1" if queue_path else "make realworld-recall-drilldown JSON=1",
                            "python3 tools/audit/external-recall-manifest-quality.py reports/external_recall_samples_<class>.json --out-json reports/external_recall_manifest_quality_<class>.json --warn-only",
                            f"sed -n '1,20p' {queue_path}" if queue_path else "sed -n '1,80p' reports/realworld_recall_scoreboard.md",
                            "sed -n '1,80p' reports/realworld_recall_scoreboard.md",
                            "python3 tools/audit/external-recall-manifest.py select --repo-root /path/to/repo --repo-id owner/repo --attack-class <class> --limit 5 --json",
                            "make external-recall-manifest REPO_ROOT=/path/to/repo REPO_ID=owner/repo ATTACK_CLASS=<class> OUT=reports/external_recall_samples.json JSON=1",
                            "python3 tools/audit/realworld-recall-scoreboard.py --external-manifest reports/external_recall_samples.json --external-only --out-dir reports",
                            "make capability-roadmap-status JSON=1",
                        ],
                        roadmap_section="Wave-7 candidates / Real-world recall generalization",
                    )
                )
            external_sample_count = int(recall_scoreboard.get("external_repo_samples") or 0)
            external_sidecar_count = int(recall_scoreboard.get("external_sidecar_samples") or 0)
            if external_sample_count <= 0 and external_sidecar_count <= 0:
                details.append(
                    _gap_detail(
                        gap_id="external_repo_recall_measurement_missing",
                        severity="high",
                        current=0,
                        target=1,
                        evidence=(
                            "The recall scoreboard has no external_repo origin bucket; current recall is still "
                            "fixture-derived rather than measured against pristine third-party repo samples."
                        ),
                        next_action="Build an external recall manifest and rerun the scoreboard with --external-manifest.",
                        commands=[
                            "python3 tools/audit/external-recall-manifest.py select --repo-root /path/to/repo --repo-id owner/repo --attack-class <class> --limit 5 --json",
                            "make external-recall-manifest REPO_ROOT=/path/to/repo REPO_ID=owner/repo ATTACK_CLASS=<class> OUT=reports/external_recall_samples.json JSON=1",
                            "python3 tools/audit/external-recall-manifest.py validate reports/external_recall_samples.json --json",
                            "python3 tools/audit/realworld-recall-scoreboard.py --external-manifest reports/external_recall_samples.json --external-only --out-dir reports",
                            "make capability-roadmap-status JSON=1",
                        ],
                        roadmap_section="Wave-7 candidates / External-repo recall measurement",
                    )
                )

    if go_cosmos_records < GO_COSMOS_RECORD_TARGET:
        details.append(
            _gap_detail(
                gap_id="go_cosmos_coverage_underweight",
                severity="high",
                current=go_cosmos_records,
                target=GO_COSMOS_RECORD_TARGET,
                evidence=(
                    "Hackerman Go/Cosmos coverage is below the roadmap target; "
                    "dYdX, Cosmos SDK, CometBFT, IAVL, Slinky, Spark, and validator-kit "
                    "briefs can remain generic."
                ),
                next_action="Stage and review focused Go/Cosmos import candidates, then rebuild the Hackerman index.",
                commands=[
                    "make hackerman-go-cosmos-inventory",
                    "make hackerman-go-cosmos-stage-imports OUT_DIR=/private/tmp/hackerman-go-cosmos-stage LIMIT=20",
                    "make hackerman-index",
                ],
                roadmap_section="Tier 3 - Corpus Quality and Coverage / Go/Cosmos expansion",
            )
        )

    if counters["unknown_year_2000"]:
        solodit_classification = (solodit_year_enrichment or {}).get("classification")
        solodit_source_blocked = solodit_classification == "source_data_blocked"
        solodit_reports = (solodit_year_enrichment or {}).get("report_paths") or []
        solodit_queue_command = (solodit_year_enrichment or {}).get(
            "enrichment_queue_command",
            "make hackerman-solodit-date-enrichment-queue LIMIT=50 JSON=1",
        )
        details.append(
            _gap_detail(
                gap_id="solodit_unknown_year_bucket_present",
                severity="medium",
                current=counters["unknown_year_2000"],
                target=0,
                evidence=(
                    "Some Solodit-derived records still use the safe year=2000 unknown-year sentinel. "
                    "Chronological ranking must keep these records in an unknown bucket until source-date metadata is proven."
                    + (
                        " Safe-year audit artifacts report zero safe source-date candidates, so this is currently source-data blocked rather than a parser failure."
                        if solodit_source_blocked
                        else ""
                    )
                ),
                next_action=(
                    "Queue explicit source-date enrichment work, accept only primary-source date evidence, then rerun the safe dry-run; keep year=2000 as the unknown bucket meanwhile."
                    if solodit_source_blocked
                    else "Enrich source-date metadata only from safe source fields; do not infer years from path hints."
                ),
                commands=[
                    solodit_queue_command,
                    (solodit_year_enrichment or {}).get(
                        "dry_run_command",
                        "python3 tools/hackerman-backfill-solodit-years.py --dry-run --json-summary --candidates-path /tmp/solodit-year-backfill-current.jsonl",
                    ),
                    "rg -n 'year: 2000' audit/corpus_tags/tags",
                    *[f"sed -n '1,160p' {path}" for path in solodit_reports[:2]],
                ],
                roadmap_section="Tier 3 - Corpus Quality and Coverage / Solodit source-date enrichment",
            )
        )

    if counters["in_record_cross_language_analogues_empty"] and not cross_language_sidecar_ready:
        details.append(
            _gap_detail(
                gap_id="in_record_cross_language_analogues_partial",
                severity="medium",
                current=counters["in_record_cross_language_analogues_populated"],
                target=counters["hackerman_record_v1"],
                evidence=(
                    "The canonical cross-language sidecar is missing or empty, and the in-record analogue "
                    "fields are not complete enough to substitute for it."
                ),
                next_action="Regenerate the canonical sidecar; do not require manual in-record writeback except for intentional snapshots.",
                commands=[
                    "python3 tools/hackerman-cross-language-analogues.py --tags-dir audit/corpus_tags/tags --out audit/corpus_tags/derived/cross_language_analogues.jsonl",
                    "python3 tools/hackerman-capability-status.py --format json",
                ],
                roadmap_section="Tier 3 - Corpus Quality and Coverage / Cross-language analogue unification",
            )
        )

    if counters["proof_artifact_path_populated"] < proof_target:
        proof_index = sidecars.get("proof_artifact_index", {})
        proof_index_rows = int(proof_index.get("rows") or 0)
        promotion_ready_available = bool(proof_index.get("promotion_ready_available"))
        promotion_ready_rows = proof_index.get("promotion_ready_rows")
        blocker_histogram = proof_index.get("promotion_blocker_histogram") or {}
        blocker_histogram_text = (
            ", ".join(f"{name}={count}" for name, count in blocker_histogram.items())
            if blocker_histogram
            else ""
        )
        proof_index_note = ""
        if proof_index_rows:
            proof_index_note = f" A read-only proof_artifact_index sidecar currently exposes {proof_index_rows} candidate rows for review."
        if promotion_ready_available:
            proof_index_note += f" promotion-ready rows={promotion_ready_rows}."
            if blocker_histogram_text:
                proof_index_note += f" blocker_histogram={blocker_histogram_text}."
            elif int(proof_index.get("promotion_blocker_rows") or 0) == 0:
                proof_index_note += " No promotion blockers were recorded in the sidecar."
        else:
            proof_index_note += " Promotion-ready fields are not present in the current proof_artifact_index sidecar."
        queue_note = ""
        queue_commands: list[str] = []
        review_packet_note = ""
        promotion_review_note = ""
        status_only_review_note = ""
        status_only_reconciliation_note = ""
        record_proposal_note = ""
        ready_packets_converted = False
        latest_promotion_ready_to_apply = 0
        latest_status_only_rows = 0
        latest_status_only_reconciliation_rows = 0
        latest_status_only_reconciliation_record_candidates = 0
        latest_status_only_reconciliation_resolved_records = 0
        if proof_artifact_import_queue and proof_artifact_import_queue.get("exists"):
            queue_path = str(proof_artifact_import_queue.get("latest_queue_path") or "")
            queue_rows = int(proof_artifact_import_queue.get("latest_queue_rows") or 0)
            queue_candidates = int(proof_artifact_import_queue.get("latest_candidate_count") or 0)
            if queue_path:
                queue_note = (
                    f" Missing-record import queue exists at {queue_path} with "
                    f"{queue_rows} queued submissions covering {queue_candidates} proof-artifact candidates."
                )
            if queue_path:
                queue_commands.extend(
                    [
                        f"sed -n '1,20p' {queue_path}",
                        (
                            "python3 - <<'PY'\n"
                            "import json\n"
                            f"rows=[json.loads(line) for line in open('{queue_path}') if line.strip()]\n"
                            "print(len(rows), sum(int(row.get('candidate_count') or 0) for row in rows))\n"
                            "PY"
                        ),
                    ]
                )
            packet_path = str(proof_artifact_import_queue.get("latest_review_packet_path") or "")
            packet_rows = int(proof_artifact_import_queue.get("latest_review_packet_rows") or 0)
            packet_candidates = int(proof_artifact_import_queue.get("latest_review_packet_candidate_count") or 0)
            packet_status_counts = proof_artifact_import_queue.get("latest_review_packet_status_counts") or {}
            packet_ready = int(packet_status_counts.get("ready_for_manual_record_creation") or 0)
            packet_blocked = int(packet_status_counts.get("blocked") or 0)
            proposal_path = str(proof_artifact_import_queue.get("latest_record_proposal_path") or "")
            proposal_emitted = int(proof_artifact_import_queue.get("latest_record_proposal_records_emitted") or 0)
            proposal_existing = int(proof_artifact_import_queue.get("latest_record_proposal_records_existing") or 0)
            proposal_built = int(proof_artifact_import_queue.get("latest_record_proposal_records_built") or 0)
            proposal_files = int(proof_artifact_import_queue.get("latest_record_proposal_files") or 0)
            proposal_files_existing = int(proof_artifact_import_queue.get("latest_record_proposal_files_existing") or 0)
            proposal_collision_files = int(proof_artifact_import_queue.get("latest_record_proposal_collision_files") or 0)
            proposal_collision_files_existing = int(proof_artifact_import_queue.get("latest_record_proposal_collision_files_existing") or 0)
            proposal_packets_path = str(proof_artifact_import_queue.get("latest_record_proposal_packets_path") or "")
            proposal_conversion_status = str(proof_artifact_import_queue.get("latest_record_proposal_conversion_status") or "")
            proposal_failed_count = int(proof_artifact_import_queue.get("latest_record_proposal_failed_count") or 0)
            proposal_current_for_packet = bool(proof_artifact_import_queue.get("latest_record_proposal_current_for_packet"))
            proposal_dry_run = bool(proof_artifact_import_queue.get("latest_record_proposal_dry_run"))
            promotion_review_path = str(proof_artifact_import_queue.get("latest_promotion_review_path") or "")
            latest_promotion_rows = int(proof_artifact_import_queue.get("latest_promotion_review_rows") or 0)
            latest_promotion_ready_to_apply = int(
                proof_artifact_import_queue.get("latest_promotion_review_ready_to_apply") or 0
            )
            promotion_review_apply_counts = proof_artifact_import_queue.get(
                "latest_promotion_review_apply_status_counts"
            ) or {}
            promotion_review_blockers = proof_artifact_import_queue.get(
                "latest_promotion_review_blocker_histogram"
            ) or {}
            if promotion_review_path:
                promotion_review_note = (
                    f" Promotion-review plan exists at {promotion_review_path} with "
                    f"{latest_promotion_ready_to_apply}/{latest_promotion_rows} rows ready_to_apply; "
                    f"safe_to_auto_apply=False; apply_status_counts={promotion_review_apply_counts}; "
                    f"blocker_histogram={promotion_review_blockers}."
                )
                queue_commands.extend(
                    [
                        f"sed -n '1,20p' {promotion_review_path}",
                        (
                            "python3 - <<'PY'\n"
                            "import collections, json\n"
                            f"rows=[json.loads(line) for line in open('{promotion_review_path}') if line.strip()]\n"
                            "print(collections.Counter(row.get('apply_status') for row in rows))\n"
                            "print(collections.Counter(blocker for row in rows for blocker in (row.get('blockers') or [])))\n"
                            "PY"
                        ),
                    ]
                )
            status_only_resolved_promotion_plan_current = (
                bool(promotion_review_path) and "status_only_resolved" in promotion_review_path
            )
            status_only_path = str(proof_artifact_import_queue.get("latest_status_only_review_path") or "")
            latest_status_only_rows = int(proof_artifact_import_queue.get("latest_status_only_review_rows") or 0)
            status_only_status_counts = proof_artifact_import_queue.get(
                "latest_status_only_submission_status_counts"
            ) or {}
            status_only_action_counts = proof_artifact_import_queue.get(
                "latest_status_only_recommended_action_counts"
            ) or {}
            if status_only_path:
                status_only_review_note = (
                    f" Status-only review queue exists at {status_only_path} with "
                    f"{latest_status_only_rows} rows requiring manual status reconciliation; "
                    f"submission_status_counts={status_only_status_counts}; "
                    f"recommended_action_counts={status_only_action_counts}."
                )
                queue_commands.extend(
                    [
                        f"sed -n '1,20p' {status_only_path}",
                        (
                            "python3 - <<'PY'\n"
                            "import collections, json\n"
                            f"rows=[json.loads(line) for line in open('{status_only_path}') if line.strip()]\n"
                            "print(collections.Counter(row.get('submission_status') for row in rows))\n"
                            "print(collections.Counter(row.get('recommended_action') for row in rows))\n"
                            "PY"
                        ),
                    ]
                )
            reconciliation_path = str(proof_artifact_import_queue.get("latest_status_only_reconciliation_path") or "")
            latest_status_only_reconciliation_rows = int(
                proof_artifact_import_queue.get("latest_status_only_reconciliation_rows") or 0
            )
            latest_status_only_reconciliation_status_counts = proof_artifact_import_queue.get(
                "latest_status_only_reconciliation_status_counts"
            ) or {}
            latest_status_only_reconciliation_record_candidates = int(
                latest_status_only_reconciliation_status_counts.get("record_creation_candidate") or 0
            )
            latest_status_only_reconciliation_resolved_records = int(
                latest_status_only_reconciliation_status_counts.get(
                    "record_resolved_needs_owner_confirmation"
                )
                or 0
            )
            latest_status_only_reconciliation_mutation_allowed = int(
                proof_artifact_import_queue.get("latest_status_only_reconciliation_mutation_allowed_rows") or 0
            )
            if reconciliation_path:
                status_only_reconciliation_note = (
                    f" Status-only reconciliation queue exists at {reconciliation_path} with "
                    f"{latest_status_only_reconciliation_rows} grouped rows; "
                    f"reconciliation_status_counts={latest_status_only_reconciliation_status_counts}; "
                    f"mutation_allowed_rows={latest_status_only_reconciliation_mutation_allowed}."
                )
                queue_commands.extend(
                    [
                        f"sed -n '1,20p' {reconciliation_path}",
                        (
                            "python3 - <<'PY'\n"
                            "import collections, json\n"
                            f"rows=[json.loads(line) for line in open('{reconciliation_path}') if line.strip()]\n"
                            "print(collections.Counter(row.get('reconciliation_status') for row in rows))\n"
                            "print(sum(int(row.get('candidate_count') or 0) for row in rows))\n"
                            "PY"
                        ),
                    ]
                )
            if packet_path:
                review_packet_note = (
                    f" Review packets exist at {packet_path} with {packet_ready}/{packet_rows} ready "
                    f"and {packet_blocked} blocked across {packet_candidates} proof-artifact candidates."
                )
                queue_commands.extend(
                    [
                        f"sed -n '1,20p' {packet_path}",
                        (
                            "python3 - <<'PY'\n"
                            "import collections, json\n"
                            f"rows=[json.loads(line) for line in open('{packet_path}') if line.strip()]\n"
                            "print(collections.Counter(row.get('validation_status') for row in rows))\n"
                            "print(sum(len(row.get('artifact_candidates') or []) for row in rows))\n"
                            "PY"
                        ),
                    ]
                )
                if proposal_path:
                    proposal_matches_packet = proposal_packets_path == packet_path
                    proposal_files_materialized = bool(proposal_files and proposal_files_existing == proposal_files)
                    proposal_existing_materialized = bool(
                        proposal_collision_files
                        and proposal_collision_files_existing == proposal_collision_files
                    )
                    proposal_materialized_count = proposal_files_existing + proposal_collision_files_existing
                    proposal_conversion_ok = proposal_conversion_status in {
                        "success",
                        "success-with-existing",
                        "already-materialized",
                    }
                    ready_packets_converted = bool(
                        packet_rows
                        and proposal_materialized_count >= packet_ready
                        and not proposal_dry_run
                        and proposal_matches_packet
                        and (proposal_files_materialized or proposal_existing_materialized)
                        and proposal_current_for_packet
                        and proposal_conversion_ok
                        and proposal_failed_count == 0
                    )
                    record_proposal_note = (
                        f" Latest record-proposal summary at {proposal_path} built {proposal_built} records "
                        f"and emitted {proposal_emitted} schema-valid Hackerman records "
                        f"({proposal_existing} already existed); "
                        f"materialized_files={proposal_files_existing}/{proposal_files}; "
                        f"existing_materialized={proposal_collision_files_existing}/{proposal_collision_files}; "
                        f"packets_path={proposal_packets_path or 'unknown'}; dry_run={proposal_dry_run}; "
                        f"conversion_status={proposal_conversion_status or 'unknown'}; "
                        f"failed_count={proposal_failed_count}; current_for_packet={proposal_current_for_packet}."
                    )
                    queue_commands.extend([f"cat {proposal_path}"])
        default_commands = [
            "python3 tools/hackerman-proof-artifact-index.py --json-summary",
            "python3 tools/hackerman-backfill-proof-artifact-path.py --review-proof-artifact-index --json-summary --limit 100 --out reports/proof_artifact_promotion_review.jsonl --missing-record-import-queue reports/proof_artifact_missing_record_import_queue.jsonl",
            "python3 tools/hackerman-backfill-proof-artifact-path.py --status-only-blocker-review --json-summary --limit 100 --out reports/proof_artifact_status_only_review.jsonl",
            "python3 tools/hackerman-backfill-proof-artifact-path.py --status-only-reconciliation-queue --json-summary --limit 100 --out reports/proof_artifact_status_only_reconciliation.jsonl",
            "python3 tools/hackerman-backfill-proof-artifact-path.py --status-only-resolved-promotion-review --json-summary --limit 100 --status-only-reconciliation reports/proof_artifact_status_only_reconciliation.jsonl --out reports/proof_artifact_promotion_review_status_only_resolved.jsonl",
            "python3 tools/hackerman-proof-hardening.py --json",
            "make capability-roadmap-status JSON=1",
        ]
        next_action = (
            "Review ready_to_apply rows, then run the explicit confirm-gated promotion plan only for manually verified rows."
            if latest_promotion_ready_to_apply
            else "Build the status-only resolved-record promotion review plan, then apply only manually verified ready_to_apply rows through the existing confirm gate."
            if latest_status_only_reconciliation_resolved_records
            and not status_only_resolved_promotion_plan_current
            else "Create or link exact Hackerman records for status-only reconciliation candidates, then rerun promotion review; do not mutate proof_artifact_path directly."
            if latest_status_only_reconciliation_record_candidates
            else "Reconcile status-only proof-artifact candidates, then rerun promotion review; do not bulk-apply candidates as proof_artifact_path."
            if latest_status_only_rows
            else (
            "Ready review packets have been converted; refresh proof-artifact sidecars, then continue the remaining promotion-ready queue."
            if ready_packets_converted
            else "Create exact Hackerman records from the ready review packets, then rerun proof_artifact_path backfill."
            if review_packet_note
            else "Review the missing-record import queue and create exact Hackerman records before any proof_artifact_path write-through."
            if queue_note
            else (
                "Review the proof_artifact_index sidecar, promote only high-confidence low-fanout paths into safe "
                "proof_artifact_path backfill, then refresh proof hardening."
            )
            )
        )
        details.append(
            _gap_detail(
                gap_id="proof_artifact_feedback_sparse",
                severity="high",
                current=counters["proof_artifact_path_populated"],
                target=proof_target,
                evidence=(
                    "Few Hackerman records link back to concrete PoC or submission proof artifacts, "
                    "so proof maturity has limited ranking power."
                    + proof_index_note
                    + queue_note
                    + review_packet_note
                    + promotion_review_note
                    + status_only_review_note
                    + status_only_reconciliation_note
                    + record_proposal_note
                ),
                next_action=next_action,
                commands=queue_commands + default_commands,
                roadmap_section="Tier 3 - Corpus Quality and Coverage / Proof artifact feedback",
                status=OrderedDict(
                    [
                        ("proof_artifact_path_populated", counters["proof_artifact_path_populated"]),
                        ("proof_artifact_index_rows", proof_index_rows),
                        ("promotion_ready_available", promotion_ready_available),
                        ("promotion_ready_rows", promotion_ready_rows if promotion_ready_available else None),
                        ("promotion_blocker_rows", int(proof_index.get("promotion_blocker_rows") or 0)),
                        ("promotion_blocker_histogram", blocker_histogram),
                        ("missing_record_import_queue", proof_artifact_import_queue or {}),
                    ]
                ),
            )
        )

    if adoption_counts:
        for name in TRACKED_CALLABLES_FOR_ADOPTION:
            count = int(adoption_counts.get(name, 0))
            if count >= ADOPTION_LOW_THRESHOLD:
                continue
            if count == 0:
                gap_id = f"dead_adoption_{name}"
                severity = "high"
                evidence = (
                    f"MCP callable `{name}` is wired into the MANIFEST but has zero invocations "
                    f"in the per-workspace MCP call log; agents are not exercising the surface."
                )
            else:
                gap_id = f"low_adoption_{name}"
                severity = "medium"
                evidence = (
                    f"MCP callable `{name}` is invoked {count} time(s) (threshold {ADOPTION_LOW_THRESHOLD}); "
                    f"adoption is below the per-iteration target."
                )
            details.append(
                _gap_detail(
                    gap_id=gap_id,
                    severity=severity,
                    current=count,
                    target=ADOPTION_LOW_THRESHOLD,
                    evidence=evidence,
                    next_action=(
                        f"Verify `{name}` appears in worker briefs or workflow MANIFEST rows where it "
                        f"should fire; expand adoption gravity via tools/hackerman-tooling-index.py if needed."
                    ),
                    commands=[
                        "make capability-adoption-status",
                        f"python3 tools/vault-mcp-server.py --call {name} --args '{{}}'",
                    ],
                    roadmap_section="Tier 0 - Toolsite / Adoption telemetry",
                )
            )

    return details


def _field_value(lines: list[str], field: str) -> tuple[str | None, bool]:
    prefix = f"{field}:"
    for i, line in enumerate(lines):
        if not line.startswith(prefix):
            continue
        rest = line.split(":", 1)[1].strip()
        normalized = _normalize_scalar(rest)
        if rest:
            return normalized, normalized not in {"[]", "", "null", "None"}
        j = i + 1
        while j < len(lines):
            child = lines[j]
            if child and not child.startswith((" ", "\t")):
                break
            stripped = child.strip()
            if stripped.startswith("- "):
                return "", True
            j += 1
        return "", False
    return None, False


def build_status(
    *,
    root: Path = REPO_ROOT,
    tag_dir: Path | None = None,
    derived_dir: Path | None = None,
    index_dir: Path | None = None,
    workspace: Path | None = None,
) -> dict[str, Any]:
    tag_dir = tag_dir or root / "audit" / "corpus_tags" / "tags"
    derived_dir = derived_dir or root / "audit" / "corpus_tags" / "derived"
    index_dir = index_dir or root / "audit" / "corpus_tags" / "index"

    yaml_paths = sorted(tag_dir.glob("*.yaml")) if tag_dir.is_dir() else []
    counters = {
        "yaml_tags": len(yaml_paths),
        "hackerman_record_v1": 0,
        "unknown_year_2000": 0,
        "exact_language_go": 0,
        "target_language_go": 0,
        "in_record_cross_language_analogues_populated": 0,
        "in_record_cross_language_analogues_empty": 0,
        "proof_artifact_path_populated": 0,
    }

    for path in yaml_paths:
        text = path.read_text(encoding="utf-8", errors="ignore")
        lines = text.splitlines()
        is_hackerman_record = "auditooor.hackerman_record.v1" in text
        if is_hackerman_record:
            counters["hackerman_record_v1"] += 1
        if _field_value(lines, "year")[0] == "2000":
            counters["unknown_year_2000"] += 1
        if _field_value(lines, "language")[0] == "go":
            counters["exact_language_go"] += 1
        if _field_value(lines, "target_language")[0] == "go":
            counters["target_language_go"] += 1
        _, has_analogues = _field_value(lines, "cross_language_analogues")
        if is_hackerman_record:
            if has_analogues:
                counters["in_record_cross_language_analogues_populated"] += 1
            else:
                counters["in_record_cross_language_analogues_empty"] += 1
        _, has_proof_artifact = _field_value(lines, "proof_artifact_path")
        if is_hackerman_record and has_proof_artifact:
            counters["proof_artifact_path_populated"] += 1

    sidecars = OrderedDict(
        [
            ("record_quality", _sidecar_status(derived_dir / "record_quality.jsonl")),
            ("proof_hardening", _sidecar_status(derived_dir / "proof_hardening.jsonl")),
            (
                "proof_artifact_index",
                _sidecar_status(
                    derived_dir / "proof_artifact_index.jsonl",
                    data_row_key="candidate_proof_path",
                ),
            ),
            ("cross_language_analogues", _sidecar_status(derived_dir / "cross_language_analogues.jsonl")),
            ("exploit_predicates", _sidecar_status(derived_dir / "exploit_predicates.jsonl")),
            ("detector_relationship_records", _sidecar_status(derived_dir / "detector_relationship_records.jsonl")),
            ("chain_candidates", _sidecar_status(derived_dir / "chain_candidates.jsonl")),
            ("chain_unify_payload", _sidecar_status(derived_dir / "chain_unify_payload.json")),
        ]
    )
    if sidecars["proof_artifact_index"]["exists"]:
        sidecars["proof_artifact_index"].update(_proof_artifact_index_summary(derived_dir / "proof_artifact_index.jsonl"))

    hooks = OrderedDict(
        [
            ("pre_source_read_injector", (root / "tools" / "auditooor-pre-source-read-injector.py").is_file()),
            ("claude_pre_source_read_hook", (root / "tools" / "claude-pre-source-read-hook.sh").is_file()),
            ("hackerman_tooling_index", (root / "tools" / "hackerman-tooling-index.py").is_file()),
        ]
    )

    index_files = sorted(p.name for p in index_dir.glob("*.jsonl")) if index_dir.is_dir() else []

    adoption_counts = _collect_adoption_counts(workspace=workspace)
    recall_scoreboard = _recall_scoreboard(root)
    realworld_work_queue = _realworld_recall_work_queue_summary(root)
    solodit_year_enrichment = _solodit_year_enrichment_status(root)
    proof_artifact_import_queue = _proof_artifact_import_queue_summary(root)
    gap_details = _known_gap_details(
        counters,
        sidecars=sidecars,
        adoption_counts=adoption_counts,
        recall_scoreboard=recall_scoreboard,
        realworld_work_queue=realworld_work_queue,
        solodit_year_enrichment=solodit_year_enrichment,
        proof_artifact_import_queue=proof_artifact_import_queue,
    )
    known_gaps = [detail["id"] for detail in gap_details]
    xlang_sidecar = sidecars["cross_language_analogues"]
    xlang_sidecar_ready = bool(xlang_sidecar["exists"] and int(xlang_sidecar["rows"] or 0) > 0)
    cross_language_analogue_policy = OrderedDict(
        [
            ("canonical_source", "derived_sidecar" if xlang_sidecar_ready else "missing_derived_sidecar"),
            ("sidecar_path", xlang_sidecar["path"]),
            ("sidecar_rows", xlang_sidecar["rows"]),
            ("in_record_writeback_required", False),
            ("consumer_contract", "tools/hackerman_query_common.py:load_cross_language_analogue_index"),
            (
                "major_consumers",
                [
                    "tools/function-mindset.py",
                    "tools/vault-mcp-server.py:vault_cross_language_pattern_lift",
                    "tools/hackerman-brief-for-lane.py",
                    "tools/auditooor-pre-source-read-injector.py",
                ],
            ),
        ]
    )

    return OrderedDict(
        [
            ("schema", "auditooor.hackerman_capability_status.v1"),
            ("root", str(root)),
            ("corpus", counters),
            ("derived_sidecars", sidecars),
            ("sidecar_freshness", _sidecar_freshness_rollup(sidecars)),
            ("cross_language_analogue_policy", cross_language_analogue_policy),
            ("index_files", {"count": len(index_files), "files": index_files}),
            ("hooks", hooks),
            ("workspace_artifacts", _workspace_artifacts(workspace)),
            ("recall_scoreboard", recall_scoreboard),
            ("realworld_recall_work_queue", realworld_work_queue),
            ("solodit_year_enrichment", solodit_year_enrichment),
            ("proof_artifact_import_queue", proof_artifact_import_queue),
            ("adoption_counts", adoption_counts),
            ("known_gaps", known_gaps),
            ("gap_details", gap_details),
        ]
    )


def render_text(status: dict[str, Any]) -> str:
    corpus = status["corpus"]
    freshness = status.get("sidecar_freshness") or {}
    freshness_counts = freshness.get("counts") or {}
    freshness_summary = ", ".join(f"{key}={value}" for key, value in freshness_counts.items()) or "none"
    recall = status["recall_scoreboard"]
    external_sidecars = recall.get("external_sidecars") if isinstance(recall.get("external_sidecars"), dict) else {}
    phase_f_lift = external_sidecars.get("phase_f_recall_lift") if isinstance(external_sidecars, dict) else None
    latest_measurement = external_sidecars.get("latest_measurement") if isinstance(external_sidecars, dict) else None
    latest_phase_f = external_sidecars.get("latest_phase_f_measurement") if isinstance(external_sidecars, dict) else None
    lines = [
        "=== hackerman-capability-status ===",
        f"root={status['root']}",
        "",
        "Corpus:",
        f"  yaml_tags={corpus['yaml_tags']}",
        f"  hackerman_record_v1={corpus['hackerman_record_v1']}",
        f"  unknown_year_2000={corpus['unknown_year_2000']}",
        f"  exact_language_go={corpus['exact_language_go']}",
        f"  target_language_go={corpus['target_language_go']}",
        f"  in_record_cross_language_analogues_populated={corpus['in_record_cross_language_analogues_populated']}",
        f"  in_record_cross_language_analogues_empty={corpus['in_record_cross_language_analogues_empty']}",
        f"  proof_artifact_path_populated={corpus['proof_artifact_path_populated']}",
        "",
        "Sidecar freshness:",
        f"  total={freshness.get('total', 0)} healthy={freshness.get('healthy_count', 0)} counts={freshness_summary}",
    ]
    non_fresh = freshness.get("non_fresh") or []
    if non_fresh:
        lines.append(f"  non_fresh={', '.join(non_fresh[:5])}")
    if phase_f_lift:
        baseline = phase_f_lift.get("baseline") or {}
        latest_comparable = phase_f_lift.get("latest_comparable") or {}
        lines.extend(
            [
                "",
                "Phase F external recall:",
                f"  phase_f_lift={baseline.get('same_class_recall_pct')}% -> {latest_comparable.get('same_class_recall_pct')}% "
                f"on {latest_comparable.get('scorable_samples')} scorable "
                f"(delta={phase_f_lift.get('delta_pct_points')} pts, updated={latest_comparable.get('timestamp_utc') or latest_comparable.get('generated_at')})",
            ]
        )
    elif latest_phase_f:
        lines.extend(
            [
                "",
                "Phase F external recall:",
                f"  latest_phase_f_same_class_recall_pct={latest_phase_f.get('same_class_recall_pct')} "
                f"scorable_samples={latest_phase_f.get('scorable_samples')} updated={latest_phase_f.get('timestamp_utc') or latest_phase_f.get('generated_at')}",
            ]
        )
    if latest_measurement and latest_phase_f and latest_measurement.get("path") != latest_phase_f.get("path"):
        lines.extend(
            [
                "",
                "Latest scoped follow-up:",
                f"  latest_scoped_followup={latest_measurement.get('same_class_recall_pct')}% on "
                f"{latest_measurement.get('scorable_samples')} scorable "
                f"({latest_measurement.get('path')}, updated={latest_measurement.get('timestamp_utc') or latest_measurement.get('generated_at')})",
            ]
        )
    lines.extend(["", "Derived sidecars:"])
    for name, sidecar in status["derived_sidecars"].items():
        lines.append(
            f"  {name}: exists={sidecar['exists']} rows={sidecar['rows']} "
            f"freshness={sidecar.get('freshness_class')} mtime_utc={sidecar.get('mtime_utc', '')} "
            f"path={sidecar['path']}"
        )
    xlang_policy = status.get("cross_language_analogue_policy") or {}
    if xlang_policy:
        lines.extend(
            [
                "",
                "Cross-language analogue policy:",
                f"  canonical_source={xlang_policy.get('canonical_source')}",
                f"  sidecar_rows={xlang_policy.get('sidecar_rows')}",
                f"  in_record_writeback_required={xlang_policy.get('in_record_writeback_required')}",
                f"  consumer_contract={xlang_policy.get('consumer_contract')}",
            ]
        )
    lines.extend(["", "Hooks:"])
    for name, exists in status["hooks"].items():
        lines.append(f"  {name}: {'present' if exists else 'missing'}")
    lines.extend(
        [
            "",
            "Recall scoreboard:",
            f"  canonical_same_class_recall_pct={recall.get('same_class_recall_pct')} scorable_samples={recall.get('scorable_samples')}",
            f"  external_repo_samples={recall.get('external_repo_samples')} sidecar_sample_count={external_sidecars.get('sample_count')}",
            "",
            f"Index files: {status['index_files']['count']}",
            "Known gaps:",
        ]
    )
    for gap in status["known_gaps"]:
        lines.append(f"  - {gap}")
    if not status["known_gaps"]:
        lines.append("  - none")
    if status.get("gap_details"):
        lines.extend(["", "Gap details:"])
        for gap in status["gap_details"]:
            lines.append(
                f"  - {gap['id']}: severity={gap['severity']} current={gap['current']} target={gap['target']}"
            )
            lines.append(f"    next_action={gap['next_action']}")
            if gap["id"] == "proof_artifact_feedback_sparse":
                proof_status = gap.get("status") if isinstance(gap.get("status"), dict) else {}
                if proof_status:
                    lines.append(
                        "    proof_artifact_index="
                        f"rows={proof_status.get('proof_artifact_index_rows')} "
                        f"promotion_ready_rows={proof_status.get('promotion_ready_rows')} "
                        f"promotion_blocker_rows={proof_status.get('promotion_blocker_rows')}"
                    )
                    blocker_histogram = proof_status.get("promotion_blocker_histogram") or {}
                    if blocker_histogram:
                        histogram_text = ", ".join(f"{name}={count}" for name, count in blocker_histogram.items())
                        lines.append(f"    blocker_histogram={histogram_text}")
                    import_queue = proof_status.get("missing_record_import_queue") or {}
                    if import_queue.get("exists"):
                        lines.append(
                            "    missing_record_import_queue="
                            f"path={import_queue.get('latest_queue_path')} "
                            f"rows={import_queue.get('latest_queue_rows')} "
                            f"candidate_count={import_queue.get('latest_candidate_count')}"
                        )
                    if import_queue.get("review_packets_exist"):
                        status_counts = import_queue.get("latest_review_packet_status_counts") or {}
                        lines.append(
                            "    missing_record_review_packets="
                            f"path={import_queue.get('latest_review_packet_path')} "
                            f"rows={import_queue.get('latest_review_packet_rows')} "
                            f"ready={status_counts.get('ready_for_manual_record_creation', 0)} "
                            f"blocked={status_counts.get('blocked', 0)} "
                            f"candidate_count={import_queue.get('latest_review_packet_candidate_count')}"
                        )
                    if import_queue.get("promotion_review_exists"):
                        lines.append(
                            "    promotion_review="
                            f"path={import_queue.get('latest_promotion_review_path')} "
                            f"rows={import_queue.get('latest_promotion_review_rows')} "
                            f"ready_to_apply={import_queue.get('latest_promotion_review_ready_to_apply')} "
                            f"safe_to_auto_apply={import_queue.get('latest_promotion_review_safe_to_auto_apply')}"
                        )
                    if import_queue.get("status_only_review_exists"):
                        lines.append(
                            "    status_only_review="
                            f"path={import_queue.get('latest_status_only_review_path')} "
                            f"rows={import_queue.get('latest_status_only_review_rows')} "
                            f"submission_status_counts={import_queue.get('latest_status_only_submission_status_counts')}"
                        )
                    if import_queue.get("status_only_reconciliation_exists"):
                        lines.append(
                            "    status_only_reconciliation="
                            f"path={import_queue.get('latest_status_only_reconciliation_path')} "
                            f"rows={import_queue.get('latest_status_only_reconciliation_rows')} "
                            f"candidates={import_queue.get('latest_status_only_reconciliation_candidate_count')} "
                            f"mutation_allowed_rows={import_queue.get('latest_status_only_reconciliation_mutation_allowed_rows')} "
                            f"status_counts={import_queue.get('latest_status_only_reconciliation_status_counts')}"
                        )
            for command in gap["commands"][:3]:
                lines.append(f"    command={command}")
    return "\n".join(lines) + "\n"


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(REPO_ROOT))
    parser.add_argument("--workspace", default="")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    root = Path(args.root).expanduser().resolve()
    workspace = Path(args.workspace).expanduser() if args.workspace else None
    status = build_status(root=root, workspace=workspace)
    if args.format == "json":
        print(json.dumps(status, indent=2, ensure_ascii=False), end="\n")
    else:
        print(render_text(status), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
