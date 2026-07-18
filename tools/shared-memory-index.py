#!/usr/bin/env python3
"""Build a bounded shared-memory index over auditooor operational artifacts.

The index is intentionally repo-local and offline.  It gives Codex, Claude,
Kimi, Minimax, MCP helpers, and Obsidian-facing tools one callable preflight
surface instead of forcing each model to reread the full docs/reports tree.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import datetime as _dt
import glob
import json
import re
import unicodedata
from pathlib import Path
from typing import Any, Iterable


DEFAULT_DATE = "2026-05-05"
SCHEMA = "auditooor.shared_memory_index.v1"

MAX_TEXT_BYTES = 64 * 1024
MAX_JSON_PARSE_BYTES = 512 * 1024
MAX_JSONL_LINES = 40
MAX_SAMPLE_ROWS = 5
MAX_GLOB_MATCHES = 6

CATEGORIES = (
    "current_state",
    "tool_status",
    "known_limitations",
    "scanner_truth",
    "scanner_burndown",
    "detector_proof_gaps",
    "rust_detector_coverage",
    "commit_lifecycle",
    "commit_mining",
    "source_mirror",
    "harness_binding",
    "harness_execution",
    "source_replay",
    "outcome_memory",
    "next_loops",
    "model_handoff",
    "goal_loop",
    "obsidian_memory_entrypoints",
    "operational_memory_day_to_day",
    "model_takeover_readiness",
    "model_takeover_provider_handoff",
    "known_limitations_harness_memory_status",
    "commit_mining_source_review",
    "commit_mining_source_disposition",
    "commit_mining_review_task_packet",
    "commit_mining_next_step_packet",
    "base_audit_patch_review",
    "rust_xfail_burndown",
)

DATE_RE = re.compile(r"(20\d{2}-\d{2}-\d{2})")
ABS_WORKTREE_RE = re.compile(r"/Users/wolf/auditooor-worktrees/[A-Za-z0-9._-]+")
COMPACT_WS_RE = re.compile(r"\s+")
SECRET_PATTERNS = (
    re.compile(r"(?i)(api[_ -]?key|api[_ -]?secret|private[_ -]?key|mnemonic|seed[_ -]?phrase)\s*[:=][^\n]+"),
    re.compile(r"0x[0-9a-fA-F]{64,}"),
)


@dataclass(frozen=True)
class SourceSpec:
    category: str
    paths: tuple[str, ...]
    globs: tuple[str, ...] = ()
    callable_use: str = ""


LATEST_REPORT_SOURCES = {
    "reports/scanner_wiring_truth_inventory_2026-05-05.json": (
        "scanner_wiring_truth_inventory",
        "auditooor.scanner_wiring_truth_inventory.v1",
    ),
    "reports/scanner_wiring_burndown_queue_2026-05-05.json": (
        "scanner_wiring_burndown_queue",
        "auditooor.scanner_wiring_burndown_queue.v1",
    ),
    "reports/scanner_worker_active_claims_2026-05-05.json": (
        "scanner_worker_active_claims",
        "auditooor.scanner_worker_active_claims.v1",
    ),
    "reports/detector_proof_gap_queue_2026-05-05.json": (
        "detector_proof_gap_queue",
        "auditooor.detector_proof_gap_queue.v1",
    ),
}


SOURCE_SPECS: tuple[SourceSpec, ...] = (
    SourceSpec(
        "current_state",
        (
            "docs/CURRENT_STATE.md",
            "docs/CONTINUATION_PLAN.md",
            "docs/CROSS_WORKSPACE_STATE_2026-05-05.md",
            "reports/cross_workspace_state.json",
        ),
        callable_use="Orient the model to branch state, operating contract, and what to read next.",
    ),
    SourceSpec(
        "tool_status",
        (
            "docs/TOOL_STATUS.md",
            "docs/TOOLS_INVENTORY.md",
            "docs/MEMORY_TIER1_EMITTERS.md",
            "reports/memory_tier1_emitters_self_test.json",
        ),
        callable_use="Decide which repo-local tool or memory emitter is available before dispatching work.",
    ),
    SourceSpec(
        "known_limitations",
        (
            "docs/KNOWN_LIMITATIONS.md",
            "docs/KNOWN_LIMITATIONS_DELTA_2026-05-05.md",
            "docs/KNOWN_LIMITATIONS_BURNDOWN_QUEUE_2026-05-05.md",
            "reports/known_limitations_burndown_queue_2026-05-05.json",
            "docs/KNOWN_LIMITATIONS_DISPATCH_2026-05-05.md",
            "reports/known_limitations_dispatch_2026-05-05.json",
        ),
        callable_use="Load explicit blockers and burn-down rows before claiming capability coverage.",
    ),
    SourceSpec(
        "scanner_truth",
        (
            "docs/SCANNER_WIRING_TRUTH_LEDGER_RUNBOOK_2026-05-05.md",
            "docs/SCANNER_WIRING_MEMORY_STATUS_2026-05-05.md",
            "reports/scanner_wiring_truth_inventory_2026-05-05.json",
            "reports/scanner_wiring_truth_ledger_runbook_2026-05-05.json",
            "reports/scanner_wiring_memory_status_2026-05-05.json",
        ),
        callable_use="Check honest scanner evidence, fake/quarantine debt, and fail-closed wiring status.",
    ),
    SourceSpec(
        "scanner_burndown",
        (
            "docs/SCANNER_WIRING_BURNDOWN_QUEUE_2026-05-05.md",
            "reports/scanner_wiring_burndown_queue_2026-05-05.json",
            "reports/scanner_worker_active_claims_2026-05-05.json",
        ),
        callable_use=(
            "Pick bounded scanner repair rows and check live worker ownership before rereading "
            "scanner truth inventory or dispatching duplicate workers."
        ),
    ),
    SourceSpec(
        "detector_proof_gaps",
        (
            "docs/DETECTOR_PROOF_GAP_QUEUE_2026-05-05.md",
            "reports/detector_proof_gap_queue_2026-05-05.json",
        ),
        callable_use="Pick detector proof, fixture, backend, and retirement work without claiming detector validity.",
    ),
    SourceSpec(
        "rust_detector_coverage",
        (
            "docs/RUST_DETECTOR_COVERAGE_2026-05-05.md",
            "reports/rust_detector_coverage_2026-05-05.json",
        ),
        callable_use="Route Rust detector fixture, loader, and regression-list gaps into concrete work.",
    ),
    SourceSpec(
        "commit_lifecycle",
        (
            "docs/COMMIT_LIFECYCLE_LEDGER_2026-05-05.md",
            "reports/commit_lifecycle_ledger_2026-05-05.json",
            "docs/COMMIT_MINING_NEXT_JOBS_2026-05-05.md",
            "reports/commit_mining_next_jobs_2026-05-05.json",
            "docs/COMMIT_MINING_SCAN_TASKS_2026-05-05.md",
            "reports/commit_mining_scan_tasks_2026-05-05.json",
            "docs/BASE_AUDIT_PATCH_COMMIT_INVENTORY_2026-05-05.md",
            "reports/base_audit_patch_commit_inventory_2026-05-05.json",
        ),
        callable_use="Determine commit artifact lifecycle state before treating patch rows as proof.",
    ),
    SourceSpec(
        "commit_mining",
        (
            "docs/GITHUB_COMMIT_MINING_EXPLOIT_PLAN_2026-05-05.md",
            "docs/PRIOR_COMMIT_MINING_ARTIFACTS_2026-05-05.md",
            "reports/github_commit_mining_exploit_plan_2026-05-05.json",
            "reports/prior_commit_mining_artifacts_2026-05-05.json",
            "reports/local_corpus_commit_mining_inventory_2026-05-05.json",
        ),
        callable_use="Route commit-ref mining to advisory review packets and avoid treating refs as exploit proof.",
    ),
    SourceSpec(
        "source_mirror",
        (
            "docs/SOURCE_MIRROR_QUEUE_2026-05-05.md",
            "reports/source_mirror_queue_2026-05-05.json",
            "docs/SOURCE_MIRROR_VERIFY_2026-05-05.md",
            "reports/source_mirror_verify_2026-05-05.json",
        ),
        callable_use="Verify which commit/source refs can be locally mirrored, locally proven, or remain blocked.",
    ),
    SourceSpec(
        "harness_binding",
        (
            "docs/HARNESS_BINDING_MANIFEST_STATUS_2026-05-05.md",
            "reports/harness_binding_manifest_status_2026-05-05.json",
        ),
        callable_use="Verify exact harness bindings or missing inputs before asking a worker to execute.",
    ),
    SourceSpec(
        "harness_execution",
        (
            "docs/HARNESS_EXECUTION_QUEUE_2026-05-05.md",
            "reports/harness_execution_queue_2026-05-05.json",
            "docs/HARNESS_FAILURE_MEMORY.md",
            "reports/harness_failures.jsonl",
        ),
        callable_use="Find dry-run executable commands and blocked harness rows without executing anything.",
    ),
    SourceSpec(
        "source_replay",
        (
            "docs/SOURCE_REF_REPLAY_MANIFEST_PLAN_2026-05-05.md",
            "reports/source_ref_replay_manifest_plan_2026-05-05.json",
            "docs/SOLODIT_SOURCE_REPLAY_READINESS_2026-05-05.md",
            "reports/solodit_source_replay_readiness_2026-05-05.json",
            "docs/DETECTOR_GAP_REGEN_PROVENANCE_2026-05-05.md",
            "reports/detector_gap_regen_provenance_2026-05-05.json",
            "reports/g1_source_root_locator_2026-05-05.json",
        ),
        callable_use="Fail closed on source refs unless local bytes, ref locks, and replay proof are present.",
    ),
    SourceSpec(
        "outcome_memory",
        (
            "docs/OUTCOME_LEDGER.md",
            "docs/OUTCOME_CALIBRATION.md",
            "docs/NO_REASON_DECLINE_MEMORY_2026-05-05.md",
            "reports/no_reason_decline_memory_2026-05-05.json",
            "reports/outcome_feedback_self_test.json",
        ),
        callable_use="Use prior outcomes and unknown-decline rules without inventing rejection reasons.",
    ),
    SourceSpec(
        "next_loops",
        (
            "docs/NEXT_10_LOOPS_2026-05-05.md",
            "docs/NEXT_50_LOOPS_2026-05-05.md",
            "docs/G1_NEXT_WORK_PACKETS_2026-05-05.md",
            "reports/next_50_loops_2026-05-05.json",
            "reports/g1_next_work_packets_2026-05-05.json",
        ),
        globs=("docs/LOOP_ITER_*_PLAN.md",),
        callable_use="Select bounded next-loop packets instead of scanning the whole roadmap.",
    ),
    SourceSpec(
        "model_handoff",
        (
            "docs/LLM_DELEGATION_MATRIX.md",
            "docs/PROVIDER_DISPATCH_TEMPLATES.md",
            "docs/STRATEGIC_LLM_POLICY.md",
            "docs/CAPABILITY_LOOP_CLAUDE_HANDOFF_2026-05-02.md",
            "docs/MEMORY_AUDIT_PACKET_STATUS_2026-05-05.md",
            "reports/memory_audit_packet_status_2026-05-05.json",
            "docs/MEMORY_BRIEF_2026-05-05.md",
            "reports/memory_brief_2026-05-05.json",
        ),
        callable_use="Prepare Claude/Kimi/Minimax handoff with provider constraints, compact briefs, and memory packet status.",
    ),
    SourceSpec(
        "goal_loop",
        (
            "docs/GOAL_LOOP_STATUS_2026-05-05.md",
            "reports/goal_loop_status_2026-05-05.json",
        ),
        callable_use="Preserve the non-terminal loop policy and handoff thresholds.",
    ),
    SourceSpec(
        "obsidian_memory_entrypoints",
        (
            "docs/OBSIDIAN_MEMORY_ENTRYPOINTS_2026-05-05.md",
            "reports/obsidian_memory_entrypoints_2026-05-05.json",
        ),
        callable_use="Find the active vault, plain-file entrypoints, and vault/MCP commands without requiring Obsidian or a GUI.",
    ),
    SourceSpec(
        "operational_memory_day_to_day",
        (
            "docs/OPERATIONAL_MEMORY_DAY_TO_DAY_2026-05-05.md",
            "reports/operational_memory_day_to_day_2026-05-05.json",
            "reports/task_finalization_loop_hardening_2026-05-05.json",
        ),
        callable_use="Start day-to-day dispatch from lane-level read-first artifacts, blockers, closeout rules, and verification commands.",
    ),
    SourceSpec(
        "model_takeover_readiness",
        (
            "docs/MODEL_TAKEOVER_READINESS_2026-05-05.md",
            "reports/model_takeover_readiness_2026-05-05.json",
        ),
        callable_use="Check Claude/Kimi/Minimax takeover readiness, bounded packet sizing, blockers, warnings, and provider gates.",
    ),
    SourceSpec(
        "model_takeover_provider_handoff",
        (
            "docs/MODEL_TAKEOVER_PROVIDER_HANDOFF_2026-05-05.md",
            "reports/model_takeover_provider_handoff_2026-05-05.json",
        ),
        callable_use="Prepare provider-specific Claude/Kimi/Minimax handoffs with current posture, packet sizing, and fail-closed blockers.",
    ),
    SourceSpec(
        "known_limitations_harness_memory_status",
        (
            "docs/KNOWN_LIMITATIONS_HARNESS_MEMORY_STATUS_2026-05-05.md",
            "reports/known_limitations_harness_memory_status_2026-05-05.json",
            "reports/klbq_006_precision_evidence_2026-05-05.json",
            "reports/klbq_006_real_source_anchors_2026-05-05.json",
            "reports/klbq_006_taxonomy_reconciliation_2026-05-05.json",
        ),
        callable_use="Check harness/memory known-limitation closure truth before claiming KLBQ rows are closed or dispatching replacements.",
    ),
    SourceSpec(
        "commit_mining_source_review",
        (
            "docs/COMMIT_MINING_SOURCE_REVIEW_2026-05-05.md",
            "reports/commit_mining_source_review_2026-05-05.json",
        ),
        callable_use="Route mirror-verified commit-mining scan tasks into advisory source-review packets without claiming exploit proof.",
    ),
    SourceSpec(
        "commit_mining_source_disposition",
        (
            "docs/COMMIT_MINING_SOURCE_DISPOSITION_2026-05-05.md",
            "reports/commit_mining_source_disposition_2026-05-05.json",
        ),
        callable_use="Route source-review packets into bounded advisory follow-up lanes without making proof or submission claims.",
    ),
    SourceSpec(
        "commit_mining_review_task_packet",
        (
            "docs/COMMIT_MINING_REVIEW_TASK_PACKET_2026-05-05.md",
            "reports/commit_mining_review_task_packet_2026-05-05.json",
        ),
        callable_use="Hand bounded source-review tasks to workers from verified commit-mining disposition rows.",
    ),
    SourceSpec(
        "commit_mining_next_step_packet",
        (
            "docs/COMMIT_MINING_NEXT_STEP_PACKET_2026-05-05.md",
            "reports/commit_mining_next_step_packet_2026-05-05.json",
        ),
        callable_use="Open the next concrete commit-mining source-review packet with exact refs and files to inspect.",
    ),
    SourceSpec(
        "base_audit_patch_review",
        (),
        globs=(
            "docs/BA_PATCH_*_SOURCE_REVIEW_2026-05-05.md",
            "reports/ba_patch_*_source_review_2026-05-05.json",
            "docs/BA_PATCH_*_PROOF_PACKET_PLAN_2026-05-05.md",
            "reports/ba_patch_*_proof_packet_plan_2026-05-05.json",
            "docs/BA_PATCH_*_PROOF_EXECUTION_2026-05-05.md",
            "reports/ba_patch_*_proof_execution_2026-05-05.json",
            "docs/BA_PATCH_*_DETECTOR_2026-05-05.md",
            "reports/ba_patch_*_detector_2026-05-05.json",
        ),
        callable_use="Load bounded BA patch source-review, proof-plan, proof-execution, and detectorization artifacts without treating them as submission-ready exploit proof.",
    ),
    SourceSpec(
        "rust_xfail_burndown",
        (
            "docs/RUST_XFAIL_BURNDOWN_2026-05-05.md",
            "reports/rust_xfail_burndown_2026-05-05.json",
        ),
        callable_use="Track Rust generated-XFAIL residual burndown and fail closed on non-XFAIL harness failures.",
    ),
)


def _mask_worktree_refs(text: Any) -> str:
    return ABS_WORKTREE_RE.sub(
        lambda match: f"[worktree-root:{Path(match.group(0)).name}]",
        str(text),
    )


def _redact(text: str) -> str:
    out = text
    for pattern in SECRET_PATTERNS:
        out = pattern.sub("[REDACTED]", out)
    return _mask_worktree_refs(out)


def _clean_text(text: str, *, limit: int = 240) -> str:
    cleaned = COMPACT_WS_RE.sub(" ", _redact(str(text))).strip()
    if len(cleaned) > limit:
        return cleaned[: limit - 3].rstrip() + "..."
    return cleaned


def _ascii_markdown(text: Any) -> str:
    translated = str(text).translate(
        {
            0x2013: "-",
            0x2014: "-",
            0x2018: "'",
            0x2019: "'",
            0x201C: '"',
            0x201D: '"',
            0x00A7: "section ",
            0x2265: ">=",
            0x00D7: "x",
        }
    )
    return unicodedata.normalize("NFKD", translated).encode("ascii", "ignore").decode("ascii")


def _read_prefix(path: Path, max_bytes: int = MAX_TEXT_BYTES) -> tuple[str, bool]:
    raw = path.read_bytes()
    truncated = len(raw) > max_bytes
    return raw[:max_bytes].decode("utf-8", errors="replace"), truncated


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


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
    dates = DATE_RE.findall(path.name)
    return (
        dates[-1] if dates else "",
        _loop_marker(path),
        _safe_int(payload.get("item_count") or payload.get("unique_action_count") or payload.get("actionable_row_count")),
        _safe_int(payload.get("total_row_count") or payload.get("top_action_count")),
        path.name,
    )


def _latest_report_compatible(payload: dict[str, Any], schema: str) -> bool:
    if str(payload.get("schema") or "") != schema:
        return False
    if schema == "auditooor.scanner_wiring_truth_inventory.v1":
        return isinstance(payload.get("rows"), list)
    if schema == "auditooor.scanner_wiring_burndown_queue.v1":
        if isinstance(payload.get("actions"), list) and payload["actions"]:
            return True
        lane_top_actions = payload.get("lane_top_actions")
        return isinstance(lane_top_actions, dict) and any(
            isinstance(rows, list) and rows for rows in lane_top_actions.values()
        )
    if schema == "auditooor.scanner_worker_active_claims.v1":
        return isinstance(payload.get("active_claims"), list)
    if schema == "auditooor.detector_proof_gap_queue.v1":
        return isinstance(payload.get("sections"), dict)
    return True


def _latest_source_path(root: Path, rel_path: str) -> str:
    spec = LATEST_REPORT_SOURCES.get(rel_path)
    if spec is None:
        return rel_path
    stem, schema = spec
    reports_root = root / "reports"
    if not reports_root.is_dir():
        return rel_path
    candidates: list[tuple[Path, dict[str, Any]]] = []
    for path in reports_root.glob(f"{stem}_*.json"):
        payload = _json_object(path)
        if _latest_report_compatible(payload, schema):
            candidates.append((path, payload))
    if not candidates:
        return rel_path
    selected = max(candidates, key=lambda item: _report_sort_key(item[0], item[1]))[0]
    return _rel(selected, root)


def _freshness_date(rel_path: str, text_prefix: str | None) -> str:
    path_match = DATE_RE.search(rel_path)
    if path_match:
        return path_match.group(1)
    if text_prefix:
        text_match = DATE_RE.search(text_prefix[:4096])
        if text_match:
            return text_match.group(1)
    return "undated"


def _stale_or_missing_reason(
    path: Path,
    freshness_date: str,
    current_date: str,
    truncated: bool,
    parse_note: str = "",
    extra_reasons: Iterable[str] = (),
) -> str:
    reasons: list[str] = []
    if not path.exists():
        return "missing_source"
    if freshness_date == "undated":
        reasons.append("undated_source")
    elif freshness_date < current_date:
        reasons.append(f"older_than_{current_date}")
    if truncated:
        reasons.append(f"content_summary_truncated_at_{MAX_TEXT_BYTES}_bytes")
    if parse_note:
        reasons.append(parse_note)
    if isinstance(extra_reasons, str):
        reasons.append(extra_reasons)
    else:
        reasons.extend(str(reason) for reason in extra_reasons if reason)
    return "; ".join(reasons)


def _stale_worktree_reference_guard(root: Path, text_prefix: str, summary: dict[str, Any]) -> dict[str, Any] | None:
    selected_root = root.resolve().as_posix()
    refs = sorted(
        ref
        for ref in set(ABS_WORKTREE_RE.findall(text_prefix + "\n" + json.dumps(summary, sort_keys=True, default=str)))
        if ref != selected_root
    )
    if not refs:
        return None
    return {
        "status": "fail_closed",
        "reason": "summary_contains_non_selected_worktree_root",
        "selected_root": selected_root,
        "stale_roots": [_mask_worktree_refs(ref) for ref in refs[:6]],
        "trusted_handoff_state": False,
    }


def _object_type_for_path(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".md":
        return "markdown_note"
    if suffix == ".json":
        return "json_report"
    if suffix == ".jsonl":
        return "jsonl_ledger"
    return "repo_artifact"


def _summary_from_markdown(path: Path) -> tuple[dict[str, Any], str, bool]:
    text, truncated = _read_prefix(path)
    lines = text.splitlines()
    title = ""
    headings: list[str] = []
    bullets: list[str] = []
    commands: list[str] = []
    in_code = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```"):
            in_code = not in_code
            continue
        if in_code and (stripped.startswith("make ") or stripped.startswith("python3 ") or stripped.startswith("tools/")):
            commands.append(_clean_text(stripped, limit=180))
            continue
        if stripped.startswith("#"):
            heading = stripped.lstrip("#").strip()
            if heading:
                if not title:
                    title = _clean_text(heading, limit=160)
                headings.append(_clean_text(heading, limit=160))
            continue
        if stripped.startswith(("- ", "* ")) and len(bullets) < 12:
            bullets.append(_clean_text(stripped[2:], limit=220))

    summary = {
        "byte_size": path.stat().st_size,
        "title": title,
        "headings": headings[:10],
        "headline_bullets": bullets[:8],
        "command_hints": commands[:6],
        "parse_mode": "markdown_prefix",
    }
    return summary, text, truncated


def _is_simple_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def _simple_mapping(value: Any, *, max_items: int = 12) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    out: dict[str, Any] = {}
    for key in sorted(value)[:max_items]:
        item = value[key]
        if _is_simple_scalar(item):
            out[str(key)] = _clean_text(item, limit=180) if isinstance(item, str) else item
    return out


def _sample_row(row: Any) -> dict[str, Any]:
    if not isinstance(row, dict):
        return {"value": _clean_text(row, limit=120)}
    keep_keys = (
        "id",
        "provider",
        "agent_id",
        "row_id",
        "gap_id",
        "limitation_id",
        "task_id",
        "packet_id",
        "lane_id",
        "detector_id",
        "source_row_id",
        "display_name",
        "title",
        "status",
        "current_status",
        "handoff_allowed",
        "readiness_estimate_percent",
        "takeover_posture",
        "target_packet_tokens",
        "owner_lane",
        "open",
        "dispatch_lane",
        "priority",
        "next_action_status",
        "action",
        "next_action",
        "expected_next_action",
        "suggested_next_action",
        "actionable_now_commands",
        "blocked_command_templates",
        "wiring_status",
        "proof_status",
        "blockers",
        "missing_inputs",
        "source_path",
        "kind",
        "role",
        "symbol",
        "summary",
        "impact",
        "risk_before",
        "closure",
        "command",
        "result",
    )
    out: dict[str, Any] = {}
    for key in keep_keys:
        if key not in row:
            continue
        value = row[key]
        if key == "blocked_command_templates" and isinstance(value, list):
            out[key] = [
                {
                    "command": _clean_text(item.get("command", ""), limit=180),
                    "missing_inputs": [_clean_text(raw, limit=80) for raw in item.get("missing_inputs", [])[:4]]
                    if isinstance(item.get("missing_inputs"), list)
                    else [],
                    "unblock_criteria": [_clean_text(raw, limit=120) for raw in item.get("unblock_criteria", [])[:3]]
                    if isinstance(item.get("unblock_criteria"), list)
                    else [],
                }
                for item in value[:3]
                if isinstance(item, dict)
            ]
        elif isinstance(value, list):
            out[key] = [_clean_text(item, limit=120) for item in value[:4]]
        elif _is_simple_scalar(value):
            out[key] = _clean_text(value, limit=180) if isinstance(value, str) else value
    if not out:
        for key in sorted(row)[:4]:
            value = row[key]
            if _is_simple_scalar(value):
                out[str(key)] = _clean_text(value, limit=120) if isinstance(value, str) else value
    return out


def _list_count_fields(payload: dict[str, Any]) -> dict[str, Any]:
    counts: dict[str, Any] = {}
    for key, value in payload.items():
        if isinstance(value, list):
            counts[f"{key}_count"] = len(value)
        elif key == "providers" and isinstance(value, dict):
            counts["providers_count"] = len(value)
        elif key.endswith("_count") and isinstance(value, int):
            counts[key] = value
    summary = payload.get("summary")
    if isinstance(summary, dict):
        for key, value in summary.items():
            if isinstance(value, (int, float, bool)) or value is None:
                counts[str(key)] = value
            elif isinstance(value, dict):
                nested = _simple_mapping(value)
                if nested:
                    counts[str(key)] = nested
    return counts


def _samples_from_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        rows = []
        if isinstance(payload.get("selected_row"), dict):
            rows = [payload["selected_row"]]
        if not rows and isinstance(payload.get("gap_closed"), dict):
            rows = [payload["gap_closed"]]
        for key in (
            "rows",
            "items",
            "actions",
            "candidates",
            "work_items",
            "top_next_actions",
            "blocked_commands",
            "ready_commands",
            "queue",
            "slots",
            "artifacts",
            "lanes",
            "open_focus_rows",
            "verified_focus_rows",
            "blocked_items",
            "blocked_or_missing",
            "source_review_packets",
            "disposition_queue",
            "tasks",
            "active_claims",
            "skipped_rows",
            "files_to_inspect",
            "observations",
            "inspect_targets",
            "commands_run",
            "local_verification",
            "residual_skip_detectors",
            "xfails",
        ):
            value = payload.get(key)
            if not rows and isinstance(value, list):
                rows = value
                break
        if not rows and isinstance(payload.get("providers"), dict):
            rows = [
                {"provider": provider, **provider_payload}
                for provider, provider_payload in payload["providers"].items()
                if isinstance(provider_payload, dict)
            ]
    else:
        rows = []
    return [_sample_row(row) for row in rows[:MAX_SAMPLE_ROWS]]


def _summary_from_json(path: Path, max_json_parse_bytes: int) -> tuple[dict[str, Any], str, bool, str]:
    size = path.stat().st_size
    text, truncated = _read_prefix(path)
    if size > max_json_parse_bytes:
        summary = {
            "byte_size": size,
            "parse_mode": "skipped_large_json",
            "max_json_parse_bytes": max_json_parse_bytes,
            "prefix_keys_hint": sorted(set(re.findall(r'"([A-Za-z_][A-Za-z0-9_]*)"\s*:', text)))[:20],
        }
        return summary, text, truncated, f"json_parse_skipped_above_{max_json_parse_bytes}_bytes"

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return (
            {
                "byte_size": size,
                "parse_mode": "json_parse_error",
                "parse_error": _clean_text(exc, limit=200),
            },
            text,
            truncated,
            "json_parse_error",
        )

    if isinstance(payload, dict):
        count_fields = _list_count_fields(payload)
        for key in ("status_counts", "backend_counts", "evidence_kind_counts", "counts_by_status"):
            value = payload.get(key)
            if isinstance(value, dict):
                count_fields[key] = _simple_mapping(value)
        summary = {
            "byte_size": size,
            "parse_mode": "json_full_bounded",
            "schema": payload.get("schema"),
            "top_level_keys": sorted(str(key) for key in payload.keys())[:30],
            "counts": count_fields,
            "samples": _samples_from_payload(payload),
        }
        summary.update(_special_json_summary(payload))
        for key in ("next_action_priority", "goal_policy", "artifact_coverage", "safety_caveats"):
            value = payload.get(key)
            if isinstance(value, dict):
                summary[key] = _simple_mapping(value)
            elif isinstance(value, list):
                summary[key] = [_clean_text(item, limit=180) for item in value[:5]]
    elif isinstance(payload, list):
        summary = {
            "byte_size": size,
            "parse_mode": "json_full_bounded",
            "top_level_type": "list",
            "item_count": len(payload),
            "samples": _samples_from_payload(payload),
        }
    else:
        summary = {
            "byte_size": size,
            "parse_mode": "json_full_bounded",
            "top_level_type": type(payload).__name__,
        }
    return summary, text, truncated, ""


def _special_json_summary(payload: dict[str, Any]) -> dict[str, Any]:
    schema = _clean_text(payload.get("schema", ""), limit=120)
    if schema == "auditooor.scanner_worker_active_claims.v1":
        claims = [
            row for row in payload.get("active_claims", [])
            if isinstance(row, dict)
        ]
        active_claims = [
            row for row in claims
            if _clean_text(row.get("status", ""), limit=40) == "active"
        ]
        completed_claims = [
            row for row in claims
            if _clean_text(row.get("status", ""), limit=40) == "completed"
        ]
        summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
        active_samples = [
            {
                "agent_id": _clean_text(row.get("agent_id", ""), limit=80),
                "row_id": _clean_text(row.get("row_id", ""), limit=120),
                "status": "active",
            }
            for row in active_claims[:MAX_SAMPLE_ROWS]
        ]
        return {
            "headline_bullets": [
                (
                    f"Scanner worker claim map has active={summary.get('active', len(active_claims))} "
                    f"and completed={summary.get('completed', len(completed_claims))}; dispatchers must "
                    "check this before assigning scanner rows."
                ),
                (
                    "Active scanner claims are live ownership, not proof of detector readiness; completed "
                    "claims mean row-local fixture/test closure was recorded by the loop."
                ),
            ],
            "samples": active_samples,
            "active_claim_count": len(active_claims),
            "completed_claim_count": len(completed_claims),
            "active_row_ids": [
                _clean_text(row.get("row_id", ""), limit=120)
                for row in active_claims[:10]
            ],
            "active_agent_ids": [
                _clean_text(row.get("agent_id", ""), limit=80)
                for row in active_claims[:10]
            ],
            "command_hints": [
                "jq '.active_claims | map(select(.status==\"active\")) | map({agent_id,row_id})' reports/scanner_worker_active_claims_2026-05-05.json",
                "python3 tools/scanner-worker-next-rows.py --active-claims reports/scanner_worker_active_claims_2026-05-05.json --limit 5",
            ],
        }
    if schema == "auditooor.known_limitations_harness_memory_status.v1":
        summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
        samples = _samples_from_payload(payload)
        actionable_rows = [
            row
            for row in payload.get("open_focus_rows", [])
            if isinstance(row, dict) and row.get("next_action_status") == "actionable_now_with_blocked_followups"
        ]
        blocked_rows = payload.get("blocked_or_missing_rows") if isinstance(payload.get("blocked_or_missing_rows"), list) else []
        bullets = [
            (
                "Current priority ordering is MEMORY > HARNESS > KNOWN LIMITATION BURNDOWN; "
                "memory handoff remains the first surface before harness execution or KLBQ burn-down."
            ),
            (
                f"Known-limitations harness-memory integration_status={payload.get('integration_status', 'unknown')}; "
                f"open_focus_rows={summary.get('open_focus_row_count', 'unknown')}; "
                f"actionable_open_rows={summary.get('open_rows_with_actionable_now_commands', 'unknown')}."
            ),
        ]
        if actionable_rows:
            first = actionable_rows[0]
            bullets.append(
                f"{first.get('id', 'unknown')} has next_action_status={first.get('next_action_status')} with "
                f"{len(first.get('actionable_now_commands', []) or [])} actionable-now commands and "
                f"{len(first.get('blocked_command_templates', []) or [])} blocked command templates."
            )
        return {
            "headline_bullets": bullets,
            "samples": samples,
            "current_priority_order": ["MEMORY", "HARNESS", "KNOWN LIMITATION BURNDOWN"],
            "current_priority_lanes": ["memory_handoff", "harness_execution", "known_limitations_burndown"],
            "command_hints": [
                _clean_text(command, limit=180)
                for row in actionable_rows[:2]
                for command in row.get("actionable_now_commands", [])[:2]
                if isinstance(command, str)
            ],
            "blocked_row_ids": [
                _clean_text(row.get("id", ""), limit=80)
                for row in blocked_rows[:5]
                if isinstance(row, dict)
            ],
        }
    if schema == "auditooor.klbq_006_precision_evidence.v1":
        summary_flags = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
        bullets = [
            (
                "KLBQ-006 precision moved forward beyond dedicated fixture smoke, "
                "but verification remains blocked."
            ),
            (
                "Synthetic precision is clean for both Rust detectors, "
                "while real-target replay and taxonomy reconciliation remain incomplete."
            ),
            (
                f"promotion_ready={bool(payload.get('promotion_ready'))}; "
                f"verification_claim_allowed={bool(payload.get('verification_claim_allowed'))}; "
                f"taxonomy_reconciled={bool(summary_flags.get('taxonomy_reconciled'))}."
            ),
        ]
        detector_rows = []
        for row in payload.get("combined_synthetic_accounting_by_detector", [])[:2]:
            if not isinstance(row, dict):
                continue
            detector_rows.append(
                {
                    "id": _clean_text(row.get("detector_id", "KLBQ-006"), limit=120),
                    "status": "synthetic_precision_clean",
                    "summary": (
                        f"precision={row.get('precision')} recall={row.get('recall')} "
                        f"tp={row.get('true_positive_count')} fp={row.get('false_positive_count')} "
                        f"tn={row.get('true_negative_count')} fn={row.get('false_negative_count')}"
                    ),
                    "next_action": _clean_text(
                        payload.get("next_commands", ["Acquire exact reNFT source root and rerun real-target replay."])[0],
                        limit=180,
                    ),
                }
            )
        return {
            "headline_bullets": bullets,
            "samples": detector_rows,
            "command_hints": [_clean_text(item, limit=180) for item in payload.get("next_commands", [])[:3]],
        }
    if schema == "auditooor.klbq006_real_source_anchors.v1":
        classification = payload.get("classification") if isinstance(payload.get("classification"), dict) else {}
        summary_counts = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
        bullets = [
            "KLBQ-006 exact real-source replay remains blocked by absent local reNFT source anchors.",
            (
                "The local tree has reference and sibling base clues, "
                "but no exact #30522 file/line or checkout anchor."
            ),
            (
                f"exact_renft_source_root={classification.get('exact_renft_source_root', 'unknown')}; "
                f"real_source_anchors={classification.get('real_source_anchors', 'unknown')}; "
                f"candidate_renft_roots={summary_counts.get('candidate_renft_roots', 'unknown')}."
            ),
        ]
        sample = {
            "id": _clean_text(payload.get("limitation_id", "KLBQ-006"), limit=64),
            "status": "exact_source_absent",
            "summary": (
                f"exact_renft_source_root={classification.get('exact_renft_source_root', 'unknown')}; "
                f"real_source_anchors={classification.get('real_source_anchors', 'unknown')}; "
                f"exact_finding_github_blob_anchors={classification.get('exact_finding_github_blob_anchors', 'unknown')}; "
                f"renft_base_github_blob_anchors={classification.get('renft_base_github_blob_anchors', 'unknown')}"
            ),
            "next_action": _clean_text(
                payload.get("commands_to_reproduce", ["Acquire or declare the exact local reNFT source root."])[0],
                limit=180,
            ),
        }
        return {
            "headline_bullets": bullets,
            "samples": [sample],
            "command_hints": [_clean_text(item, limit=180) for item in payload.get("commands_to_reproduce", [])[:3]],
        }
    if schema == "auditooor.klbq_006_taxonomy_reconciliation.v1":
        decision = payload.get("taxonomy_decision") if isinstance(payload.get("taxonomy_decision"), dict) else {}
        accounting = payload.get("reconciled_accounting") if isinstance(payload.get("reconciled_accounting"), dict) else {}
        bullets = [
            "KLBQ-006 taxonomy reconciliation is decided locally, but the limitation remains open.",
            (
                f"Canonical leaf family is `{decision.get('canonical_leaf_family', 'unknown')}`, "
                f"with `{decision.get('parent_class', 'unknown')}` retained as a parent/alias only."
            ),
            (
                f"closure_posture={accounting.get('closure_posture', 'unknown')}; "
                f"promotion_posture={accounting.get('promotion_posture', 'unknown')}; "
                f"repo_wide_metadata_updated={bool(accounting.get('repo_wide_metadata_updated'))}."
            ),
        ]
        sample = {
            "id": _clean_text(payload.get("limitation_id", "KLBQ-006"), limit=64),
            "status": _clean_text(payload.get("status", "taxonomy_reconciled"), limit=120),
            "summary": (
                f"canonical_leaf_family={decision.get('canonical_leaf_family', 'unknown')}; "
                f"parent_class={decision.get('parent_class', 'unknown')}; "
                f"preferred_accounting_key={decision.get('preferred_accounting_key', 'unknown')}"
            ),
            "next_action": _clean_text(
                payload.get("exact_next_commands", ["Acquire exact source anchors before replay."])[0],
                limit=180,
            ),
        }
        return {
            "headline_bullets": bullets,
            "samples": [sample],
            "command_hints": [_clean_text(item, limit=180) for item in payload.get("exact_next_commands", [])[:3]],
        }
    return {}


def _summary_from_jsonl(path: Path) -> tuple[dict[str, Any], str, bool, str]:
    text, truncated = _read_prefix(path)
    samples: list[dict[str, Any]] = []
    parse_errors = 0
    line_count = 0
    status_counts: dict[str, int] = {}
    for line in text.splitlines()[:MAX_JSONL_LINES]:
        if not line.strip():
            continue
        line_count += 1
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            parse_errors += 1
            continue
        if len(samples) < MAX_SAMPLE_ROWS:
            samples.append(_sample_row(row))
        if isinstance(row, dict) and isinstance(row.get("status"), str):
            status_counts[row["status"]] = status_counts.get(row["status"], 0) + 1
    summary = {
        "byte_size": path.stat().st_size,
        "parse_mode": "jsonl_prefix",
        "sampled_line_count": line_count,
        "max_jsonl_lines": MAX_JSONL_LINES,
        "parse_errors": parse_errors,
        "status_counts_in_sample": status_counts,
        "samples": samples,
    }
    note = "jsonl_sample_has_parse_errors" if parse_errors else ""
    return summary, text, truncated, note


def summarize_source(
    root: Path,
    rel_path: str,
    category: str,
    callable_use: str,
    current_date: str,
    *,
    max_json_parse_bytes: int = MAX_JSON_PARSE_BYTES,
) -> dict[str, Any]:
    path = root / rel_path
    if not path.exists():
        return {
            "category": category,
            "object_type": "missing_source",
            "freshness_date": "missing",
            "source_path": rel_path,
            "summary_fields": {},
            "callable_use": callable_use,
            "stale_or_missing_reason": "missing_source",
        }

    object_type = _object_type_for_path(path)
    parse_note = ""
    if path.suffix.lower() == ".md":
        summary, text_prefix, truncated = _summary_from_markdown(path)
    elif path.suffix.lower() == ".json":
        summary, text_prefix, truncated, parse_note = _summary_from_json(path, max_json_parse_bytes)
    elif path.suffix.lower() == ".jsonl":
        summary, text_prefix, truncated, parse_note = _summary_from_jsonl(path)
    else:
        text_prefix, truncated = _read_prefix(path)
        summary = {
            "byte_size": path.stat().st_size,
            "parse_mode": "raw_prefix",
            "prefix": _clean_text(text_prefix, limit=240),
        }

    freshness = _freshness_date(rel_path, text_prefix)
    stale_root_guard = _stale_worktree_reference_guard(root, text_prefix, summary)
    stale_reason = _stale_or_missing_reason(
        path,
        freshness,
        current_date,
        truncated,
        parse_note,
        extra_reasons=(
            "summary_contains_non_selected_worktree_root"
            if stale_root_guard
            else ""
        ),
    )
    if stale_root_guard:
        summary["stale_source_guard"] = stale_root_guard
    return {
        "category": category,
        "object_type": object_type,
        "freshness_date": freshness,
        "source_path": rel_path,
        "summary_fields": summary,
        "callable_use": callable_use,
        "stale_or_missing_reason": stale_reason,
    }


def _controlled_glob_matches(root: Path, pattern: str) -> list[str]:
    if not (pattern.startswith("docs/") or pattern.startswith("reports/")):
        return []
    matches = [
        _rel(Path(path), root)
        for path in glob.glob(str(root / pattern))
        if Path(path).is_file()
    ]
    return sorted(matches, reverse=True)[:MAX_GLOB_MATCHES]


def discover_sources(root: Path) -> list[tuple[str, str, str]]:
    discovered: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for spec in SOURCE_SPECS:
        for rel_path in spec.paths:
            rel_path = _latest_source_path(root, rel_path)
            key = (spec.category, rel_path)
            if key not in seen:
                discovered.append((spec.category, rel_path, spec.callable_use))
                seen.add(key)
        for pattern in spec.globs:
            for rel_path in _controlled_glob_matches(root, pattern):
                key = (spec.category, rel_path)
                if key not in seen:
                    discovered.append((spec.category, rel_path, spec.callable_use))
                    seen.add(key)
    return discovered


def build_index(
    root: Path,
    *,
    current_date: str = DEFAULT_DATE,
    max_json_parse_bytes: int = MAX_JSON_PARSE_BYTES,
) -> dict[str, Any]:
    root = root.resolve()
    memory_objects = [
        summarize_source(
            root,
            rel_path,
            category,
            callable_use,
            current_date,
            max_json_parse_bytes=max_json_parse_bytes,
        )
        for category, rel_path, callable_use in discover_sources(root)
    ]

    coverage: dict[str, dict[str, int]] = {}
    for category in CATEGORIES:
        category_objects = [obj for obj in memory_objects if obj["category"] == category]
        present = [obj for obj in category_objects if obj["object_type"] != "missing_source"]
        fresh = [obj for obj in present if not obj["stale_or_missing_reason"]]
        coverage[category] = {
            "object_count": len(category_objects),
            "present_count": len(present),
            "fresh_count": len(fresh),
            "missing_count": len(category_objects) - len(present),
        }

    return {
        "schema": SCHEMA,
        "generated_date": current_date,
        "repo_root": root.as_posix(),
        "purpose": (
            "Bounded callable index over repo-local operational memory artifacts; "
            "use it as model preflight before reading full docs or reports."
        ),
        "categories": list(CATEGORIES),
        "category_coverage": coverage,
        "memory_object_count": len(memory_objects),
        "memory_objects": memory_objects,
        "callable_contract": [
            "Start with category_coverage to find missing or stale memory surfaces.",
            "Use memory_objects[].summary_fields for counts, statuses, and sample next actions.",
            "Only open source_path when summary_fields is insufficient for the current task.",
            "Treat stale_or_missing_reason as a fail-closed signal, not permission to infer state.",
        ],
    }


def render_markdown(index: dict[str, Any]) -> str:
    lines = [
        f"# Shared Memory Index - {index['generated_date']}",
        "",
        "This is the repo-local preflight index for operational memory. It is built from bounded reads of known docs/reports and does not require Obsidian APIs.",
        "",
        f"- Schema: `{index['schema']}`",
        f"- Generated date: `{index['generated_date']}`",
        f"- Memory objects: `{index['memory_object_count']}`",
        "",
        "## Category Coverage",
        "",
        "| Category | Objects | Present | Fresh | Missing |",
        "|---|---:|---:|---:|---:|",
    ]
    coverage = index["category_coverage"]
    for category in index["categories"]:
        row = coverage[category]
        lines.append(
            f"| `{category}` | {row['object_count']} | {row['present_count']} | {row['fresh_count']} | {row['missing_count']} |"
        )

    lines.extend(["", "## Callable Objects", ""])
    for obj in index["memory_objects"]:
        if obj["object_type"] == "missing_source":
            lines.append(
                f"- `{obj['category']}` missing `{obj['source_path']}` - {obj['stale_or_missing_reason']}"
            )
            continue
        summary = obj["summary_fields"]
        label = _ascii_markdown(summary.get("title") or summary.get("schema") or summary.get("parse_mode") or obj["object_type"])
        counts = summary.get("counts")
        count_hint = ""
        if isinstance(counts, dict) and counts:
            compact_counts = []
            for key, value in list(counts.items())[:4]:
                if isinstance(value, dict):
                    compact_counts.append(f"{key}={len(value)} keys")
                else:
                    compact_counts.append(f"{key}={value}")
            count_hint = f" ({', '.join(compact_counts)})"
        stale = f" [{obj['stale_or_missing_reason']}]" if obj["stale_or_missing_reason"] else ""
        lines.append(
            f"- `{obj['category']}` `{obj['source_path']}`: {label}{count_hint}{stale}"
        )

    lines.extend(
        [
            "",
            "## Use",
            "",
            "Use `reports/shared_memory_index_2026-05-05.json` as the callable artifact. Open source files only when a summarized object is insufficient for the current task.",
            "",
        ]
    )
    return "\n".join(lines)


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_markdown(path: Path, index: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_markdown(index), encoding="utf-8")


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--current-date", default=DEFAULT_DATE)
    parser.add_argument("--output", default="reports/shared_memory_index_2026-05-05.json")
    parser.add_argument("--markdown-output", default="docs/SHARED_MEMORY_INDEX_2026-05-05.md")
    parser.add_argument("--max-json-parse-bytes", type=int, default=MAX_JSON_PARSE_BYTES)
    parser.add_argument("--print-json", action="store_true", help="Print JSON to stdout instead of writing artifacts.")
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    root = Path(args.root).resolve()
    index = build_index(
        root,
        current_date=args.current_date,
        max_json_parse_bytes=args.max_json_parse_bytes,
    )
    if args.print_json:
        print(json.dumps(index, indent=2, sort_keys=True))
        return 0

    output = Path(args.output)
    markdown_output = Path(args.markdown_output)
    if not output.is_absolute():
        output = root / output
    if not markdown_output.is_absolute():
        markdown_output = root / markdown_output
    write_json(output, index)
    write_markdown(markdown_output, index)
    print(f"[shared-memory-index] wrote {_rel(output, root)} and {_rel(markdown_output, root)}")
    print(f"[shared-memory-index] memory_objects={index['memory_object_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
