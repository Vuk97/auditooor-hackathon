#!/usr/bin/env python3
"""Render compact task-scoped briefs from the shared-memory index.

This tool is deliberately a second-stage surface over
``reports/shared_memory_index_2026-05-05.json``.  It should be cheap enough to
paste into Claude/Kimi/Minimax/Codex handoffs before opening full docs.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import math
import re
import sys
import unicodedata
from pathlib import Path
from typing import Any, Iterable


DEFAULT_DATE = "2026-05-05"
SCHEMA = "auditooor.memory_brief.v1"
QUERY_PACKET_SCHEMA = "auditooor.memory_topic_packet.v1"
BOOTSTRAP_PACKET_SCHEMA = "auditooor.agent_bootstrap_packet.v1"
MEMORY_BOOTSTRAP_PACKET_SCHEMA = "auditooor.memory_bootstrap.v1"
DEFAULT_INDEX = "reports/shared_memory_index_2026-05-05.json"
DEFAULT_OUTPUT = "reports/memory_brief_2026-05-05.json"
DEFAULT_MARKDOWN_OUTPUT = "docs/MEMORY_BRIEF_2026-05-05.md"

COMPACT_WS_RE = re.compile(r"\s+")

BRIEF_CATEGORY_SPECS: dict[str, dict[str, Any]] = {
    "audit_handoff": {
        "source_categories": (
            "current_state",
            "model_handoff",
            "model_takeover_readiness",
            "model_takeover_provider_handoff",
            "operational_memory_day_to_day",
            "obsidian_memory_entrypoints",
            "goal_loop",
            "next_loops",
        ),
        "purpose": "Orient an agent to current repo state, handoff rules, and bounded next work.",
        "handoff_rule": "Read this first; open full current-state or provider docs only if the task needs details absent below.",
    },
    "scanner_truth": {
        "source_categories": (
            "scanner_truth",
            "scanner_burndown",
            "detector_proof_gaps",
            "rust_detector_coverage",
            "rust_xfail_burndown",
        ),
        "purpose": "Preserve honest scanner coverage, fake/quarantine debt, and proof boundaries.",
        "handoff_rule": "Treat unverified scanner rows as repair or retirement work, not live detector coverage.",
    },
    "commit_lifecycle": {
        "source_categories": (
            "commit_lifecycle",
            "commit_mining",
            "commit_mining_source_review",
            "commit_mining_source_disposition",
            "commit_mining_review_task_packet",
            "commit_mining_next_step_packet",
            "base_audit_patch_review",
            "source_replay",
        ),
        "purpose": "Route commit artifacts through lifecycle state before using them as evidence.",
        "handoff_rule": "Commit refs are source-review leads until local bytes, provenance, and replay evidence exist.",
    },
    "known_limitations": {
        "source_categories": ("known_limitations", "known_limitations_harness_memory_status"),
        "purpose": "Carry explicit blockers and burn-down queues into model prompts without rereading the limitation docs.",
        "handoff_rule": "Fail closed on limitations; a missing or stale row blocks capability claims.",
    },
    "source_mirror": {
        "source_categories": ("source_mirror", "source_replay", "commit_lifecycle"),
        "purpose": "Show which source refs can be mirrored locally and which remain blocked.",
        "handoff_rule": "Source mirror readiness is not exploitability, detector coverage, or submission readiness.",
    },
}

SUPPORTED_CATEGORIES = tuple(BRIEF_CATEGORY_SPECS)
MAX_OBJECTS_PER_SOURCE_CATEGORY = 4
MAX_BULLETS_PER_OBJECT = 2
MAX_SAMPLES_PER_OBJECT = 2
MAX_COUNT_FIELDS = 6
DEFAULT_QUERY_MAX_SOURCES = 6
DEFAULT_BOOTSTRAP_SOURCE_ORDER = (
    "docs/CURRENT_STATE.md",
    "reports/memory_audit_packet_status_2026-05-05.json",
    "reports/memory_brief_2026-05-05.json",
    "reports/shared_memory_index_2026-05-05.json",
    "reports/obsidian_memory_entrypoints_2026-05-05.json",
)
BOOTSTRAP_SOURCE_PATHS = {
    "goal_loop": "reports/goal_loop_status_2026-05-05.json",
    "current_state": "docs/CURRENT_STATE.md",
    "memory_audit_packet": "reports/memory_audit_packet_status_2026-05-05.json",
    "memory_brief": "reports/memory_brief_2026-05-05.json",
    "shared_memory_index": "reports/shared_memory_index_2026-05-05.json",
    "entrypoints": "reports/obsidian_memory_entrypoints_2026-05-05.json",
    "declines": "reports/no_reason_decline_memory_2026-05-05.json",
    "next_50": "reports/next_50_loops_2026-05-05.json",
    "g1_next_work": "reports/g1_next_work_packets_2026-05-05.json",
}
DEFAULT_MEMORY_BOOTSTRAP_MAX_ACTIONS = 8
MEMORY_BOOTSTRAP_SOURCE_PATHS: tuple[str, ...] = (
    "reports/memory_audit_packet_status_2026-05-05.json",
    "reports/operational_memory_day_to_day_2026-05-05.json",
    "reports/goal_loop_status_2026-05-05.json",
    "reports/known_limitations_harness_memory_status_2026-05-05.json",
    "reports/known_limitations_dispatch_2026-05-05.json",
    "reports/harness_execution_queue_2026-05-05.json",
    "reports/harness_binding_manifest_status_2026-05-05.json",
    "reports/model_takeover_provider_handoff_2026-05-05.json",
)
BROAD_DOCS_AVOIDED_BY_MEMORY_BOOTSTRAP: tuple[str, ...] = (
    "README.md",
    "docs/CURRENT_STATE.md",
    "docs/CONTINUATION_PLAN.md",
    "docs/KNOWN_LIMITATIONS.md",
    "docs/MEMORY_ARCHITECTURE_2026-05-04.md",
    "docs/OPERATIONAL_MEMORY_DAY_TO_DAY_2026-05-05.md",
    "docs/MEMORY_AUDIT_PACKET_STATUS_2026-05-05.md",
    "docs/KNOWN_LIMITATIONS_HARNESS_MEMORY_STATUS_2026-05-05.md",
)
PINNED_SOURCE_PATHS: dict[str, tuple[str, ...]] = {
    "source_replay": (
        "reports/detector_gap_regen_provenance_2026-05-05.json",
        "docs/DETECTOR_GAP_REGEN_PROVENANCE_2026-05-05.md",
    ),
    "known_limitations_harness_memory_status": (
        "reports/known_limitations_harness_memory_status_2026-05-05.json",
        "reports/klbq_006_precision_evidence_2026-05-05.json",
        "reports/klbq_006_real_source_anchors_2026-05-05.json",
        "reports/klbq_006_taxonomy_reconciliation_2026-05-05.json",
    ),
}

QUERY_TOPIC_SPECS: dict[str, dict[str, Any]] = {
    "scanner wiring": {
        "source_categories": (
            "scanner_truth",
            "scanner_burndown",
            "detector_proof_gaps",
            "rust_detector_coverage",
            "rust_xfail_burndown",
        ),
        "brief_categories": ("scanner_truth",),
        "extra_terms": ("scanner", "wiring", "truth", "burndown", "detector", "proof", "fixture", "xfail"),
        "purpose": "Route bounded scanner wiring evidence without reopening the full truth ledgers and burndown docs.",
    },
    "commit mining": {
        "source_categories": (
            "commit_lifecycle",
            "commit_mining",
            "commit_mining_source_review",
            "commit_mining_source_disposition",
            "commit_mining_review_task_packet",
            "commit_mining_next_step_packet",
            "base_audit_patch_review",
            "source_replay",
            "source_mirror",
        ),
        "brief_categories": ("commit_lifecycle", "source_mirror"),
        "extra_terms": ("commit", "mining", "review", "disposition", "packet", "replay", "mirror", "patch"),
        "purpose": "Keep commit-ref work on compact lifecycle packets until exact local source bytes and replay proof exist.",
    },
    "bug bounty declines": {
        "source_categories": ("outcome_memory",),
        "brief_categories": (),
        "extra_terms": ("bug", "bounty", "decline", "declines", "rejection", "outcome", "calibration"),
        "purpose": "Surface prior decline and outcome memory without rereading broad calibration docs.",
    },
    "memory checkpoint": {
        "source_categories": (
            "current_state",
            "model_handoff",
            "goal_loop",
            "next_loops",
            "obsidian_memory_entrypoints",
            "operational_memory_day_to_day",
            "model_takeover_readiness",
            "model_takeover_provider_handoff",
        ),
        "brief_categories": ("audit_handoff",),
        "extra_terms": ("memory", "checkpoint", "handoff", "state", "entrypoint", "vault", "brief", "continuation"),
        "purpose": "Find the latest compact checkpoint and handoff surfaces before reading broader memory docs.",
    },
    "agent bootstrap": {
        "source_categories": (
            "current_state",
            "goal_loop",
            "model_handoff",
            "obsidian_memory_entrypoints",
            "outcome_memory",
            "next_loops",
        ),
        "brief_categories": ("audit_handoff",),
        "extra_terms": ("agent", "bootstrap", "checkpoint", "handoff", "decline", "worktree", "next", "queue"),
        "purpose": "Emit the minimum live takeover context for a replacement model before it opens broader memory docs.",
        "mode": "agent_bootstrap",
    },
}


class MemoryBriefError(RuntimeError):
    pass


def _clean_text(value: Any, *, limit: int = 220) -> str:
    text = COMPACT_WS_RE.sub(" ", str(value)).strip()
    if len(text) > limit:
        text = text[: limit - 3].rstrip() + "..."
    translated = text.translate(
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


def _token_estimate(text_or_chars: str | int) -> int:
    chars = text_or_chars if isinstance(text_or_chars, int) else len(text_or_chars)
    return max(1, math.ceil(chars / 4))


def _read_index(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise MemoryBriefError(f"missing shared memory index: {path}") from exc
    except json.JSONDecodeError as exc:
        raise MemoryBriefError(f"invalid shared memory index JSON: {path}: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("memory_objects"), list):
        raise MemoryBriefError("shared memory index must contain memory_objects[]")
    return payload


def _read_optional_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _status_for_object(obj: dict[str, Any]) -> str:
    if obj.get("object_type") == "missing_source":
        return "missing"
    if obj.get("stale_or_missing_reason"):
        return "stale_or_limited"
    return "fresh"


def _compact_counts(counts: Any, *, limit: int = MAX_COUNT_FIELDS) -> dict[str, Any]:
    if not isinstance(counts, dict):
        return {}
    compact: dict[str, Any] = {}
    for key in sorted(counts)[:limit]:
        value = counts[key]
        if isinstance(value, dict):
            compact[str(key)] = {
                str(inner_key): value[inner_key]
                for inner_key in sorted(value, key=str)[:limit]
                if isinstance(value[inner_key], (str, int, float, bool)) or value[inner_key] is None
            }
        elif isinstance(value, (str, int, float, bool)) or value is None:
            compact[str(key)] = value
    return compact


def _compact_sample(sample: Any) -> dict[str, Any]:
    if not isinstance(sample, dict):
        return {"value": _clean_text(sample, limit=140)}
    keep = (
        "id",
        "provider",
        "agent_id",
        "row_id",
        "gap_id",
        "limitation_id",
        "task_id",
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
        "actionable_now_commands",
        "blocked_command_templates",
        "wiring_status",
        "proof_status",
        "suggested_next_action",
        "expected_next_action",
        "blockers",
        "missing_inputs",
        "source_row_id",
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
    for key in keep:
        if key not in sample:
            continue
        value = sample[key]
        if key == "blocked_command_templates" and isinstance(value, list):
            out[key] = [
                {
                    "command": _clean_text(item.get("command", ""), limit=160),
                    "missing_inputs": [_clean_text(raw, limit=80) for raw in item.get("missing_inputs", [])[:3]]
                    if isinstance(item.get("missing_inputs"), list)
                    else [],
                    "unblock_criteria": [_clean_text(raw, limit=100) for raw in item.get("unblock_criteria", [])[:2]]
                    if isinstance(item.get("unblock_criteria"), list)
                    else [],
                }
                for item in value[:2]
                if isinstance(item, dict)
            ]
        elif isinstance(value, list):
            out[key] = [_clean_text(item, limit=100) for item in value[:3]]
        elif isinstance(value, (str, int, float, bool)) or value is None:
            out[key] = _clean_text(value, limit=160) if isinstance(value, str) else value
    return out


def _label_for_object(obj: dict[str, Any]) -> str:
    summary = obj.get("summary_fields") if isinstance(obj.get("summary_fields"), dict) else {}
    return _clean_text(
        summary.get("title") or summary.get("schema") or summary.get("parse_mode") or obj.get("object_type", "memory_object"),
        limit=140,
    )


def _brief_object(obj: dict[str, Any]) -> dict[str, Any]:
    summary = obj.get("summary_fields") if isinstance(obj.get("summary_fields"), dict) else {}
    brief: dict[str, Any] = {
        "source_path": obj.get("source_path", ""),
        "object_type": obj.get("object_type", ""),
        "freshness_date": obj.get("freshness_date", ""),
        "status": _status_for_object(obj),
        "label": _label_for_object(obj),
    }
    reason = obj.get("stale_or_missing_reason")
    if reason:
        brief["fail_closed_note"] = _clean_text(reason, limit=220)
    counts = _compact_counts(summary.get("counts"))
    if counts:
        brief["counts"] = counts
    bullets = summary.get("headline_bullets")
    if isinstance(bullets, list) and bullets:
        brief["key_points"] = [_clean_text(item, limit=180) for item in bullets[:MAX_BULLETS_PER_OBJECT]]
    samples = summary.get("samples")
    if isinstance(samples, list) and samples:
        brief["samples"] = [_compact_sample(item) for item in samples[:MAX_SAMPLES_PER_OBJECT]]
    commands = summary.get("command_hints")
    if isinstance(commands, list) and commands:
        brief["command_hints"] = [_clean_text(item, limit=160) for item in commands[:2]]
    return brief


def _object_rank(obj: dict[str, Any]) -> tuple[int, int, str]:
    status_rank = {"fresh": 0, "stale_or_limited": 1, "missing": 2}.get(_status_for_object(obj), 3)
    type_rank = {"json_report": 0, "markdown_note": 1, "jsonl_ledger": 2}.get(str(obj.get("object_type")), 3)
    missing_rank = 1 if _status_for_object(obj) == "missing" else 0
    return (missing_rank, type_rank, status_rank, str(obj.get("source_path", "")))


def _select_objects(index: dict[str, Any], source_category: str, max_objects: int) -> list[dict[str, Any]]:
    objects = [
        obj
        for obj in index.get("memory_objects", [])
        if isinstance(obj, dict) and obj.get("category") == source_category
    ]
    pinned_paths = PINNED_SOURCE_PATHS.get(source_category, ())
    pinned = [obj for obj in objects if obj.get("source_path") in pinned_paths]
    pinned.sort(key=lambda obj: pinned_paths.index(str(obj.get("source_path"))))
    remainder = sorted(
        [obj for obj in objects if obj.get("source_path") not in pinned_paths],
        key=_object_rank,
    )
    return (pinned + remainder)[:max_objects]


def _coverage_slice(index: dict[str, Any], source_categories: Iterable[str]) -> dict[str, dict[str, int]]:
    coverage = index.get("category_coverage")
    if not isinstance(coverage, dict):
        return {}
    out: dict[str, dict[str, int]] = {}
    for category in source_categories:
        row = coverage.get(category)
        if isinstance(row, dict):
            out[category] = {
                key: int(value)
                for key, value in row.items()
                if key in {"object_count", "present_count", "fresh_count", "missing_count"} and isinstance(value, int)
            }
    return out


def _index_object_by_path(index: dict[str, Any], source_path: str) -> dict[str, Any] | None:
    for obj in index.get("memory_objects", []):
        if isinstance(obj, dict) and obj.get("source_path") == source_path:
            return obj
    return None


def _resolve_local_report(root: Path | None, path_value: str) -> dict[str, Any]:
    if root is None:
        return {}
    return _read_optional_json(_resolve_under_root(root, path_value))


def _byte_size_for_source(index: dict[str, Any], source_path: str, *, root: Path | None = None) -> int:
    if root is not None:
        path = _resolve_under_root(root, source_path)
        try:
            return path.stat().st_size
        except OSError:
            pass
    if source_path == BOOTSTRAP_SOURCE_PATHS["shared_memory_index"]:
        return len(json.dumps(index, sort_keys=True))
    obj = _index_object_by_path(index, source_path)
    if obj and isinstance(obj.get("summary_fields"), dict):
        try:
            return int(obj["summary_fields"].get("byte_size", 0))
        except (TypeError, ValueError):
            return 0
    return 0


def _bootstrap_source_entry(
    index: dict[str, Any],
    source_path: str,
    *,
    order: int,
    why: str,
) -> dict[str, Any]:
    obj = _index_object_by_path(index, source_path)
    if source_path == BOOTSTRAP_SOURCE_PATHS["shared_memory_index"]:
        return {
            "order": order,
            "source_path": source_path,
            "status": "fresh",
            "live_state_allowed": True,
            "label": _clean_text(index.get("schema", "shared-memory index"), limit=140),
            "object_type": "json_report",
            "freshness_date": index.get("generated_date", ""),
            "why": _clean_text(why, limit=180),
        }
    if not obj:
        return {
            "order": order,
            "source_path": source_path,
            "status": "missing",
            "live_state_allowed": False,
            "why": _clean_text(why, limit=180),
        }
    source = _brief_object(obj)
    source["order"] = order
    source["live_state_allowed"] = source.get("status") == "fresh"
    source["why"] = _clean_text(why, limit=180)
    return source


def _query_tokens(value: str) -> list[str]:
    return [token for token in re.findall(r"[a-z0-9]+", value.lower()) if len(token) >= 3]


def _query_topic_spec(query: str) -> tuple[str, dict[str, Any] | None]:
    normalized_query = " ".join(_query_tokens(query))
    for topic, spec in QUERY_TOPIC_SPECS.items():
        topic_tokens = _query_tokens(topic)
        if topic_tokens and all(token in normalized_query for token in topic_tokens):
            return topic, spec
    return normalized_query, None


def _brief_categories_for_source_categories(source_categories: Iterable[str]) -> list[str]:
    categories = set(source_categories)
    matched: list[str] = []
    for brief_category, spec in BRIEF_CATEGORY_SPECS.items():
        if categories.intersection(spec["source_categories"]):
            matched.append(brief_category)
    return matched


def _stringify_sample(sample: Any) -> str:
    compact = _compact_sample(sample)
    return " ".join(f"{key}={value}" for key, value in compact.items())


def _match_reasons_for_object(
    obj: dict[str, Any],
    query_terms: list[str],
    alias_spec: dict[str, Any] | None,
) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    category = str(obj.get("category", ""))
    category_lc = category.lower()
    source_path = str(obj.get("source_path", ""))
    source_path_lc = source_path.lower()
    summary = obj.get("summary_fields") if isinstance(obj.get("summary_fields"), dict) else {}
    title = str(summary.get("title") or summary.get("schema") or summary.get("parse_mode") or "")
    title_lc = title.lower()
    callable_use = str(obj.get("callable_use") or "")
    callable_use_lc = callable_use.lower()
    bullets = [
        str(item).lower()
        for item in summary.get("headline_bullets", [])
        if isinstance(item, str)
    ]
    commands = [
        str(item).lower()
        for item in summary.get("command_hints", [])
        if isinstance(item, str)
    ]
    samples = [
        _stringify_sample(item).lower()
        for item in summary.get("samples", [])
    ]

    if alias_spec and category in alias_spec.get("source_categories", ()):
        score += 70
        reasons.append(f"source_category={category}")

    for term in query_terms:
        if term in category_lc:
            score += 40
            reasons.append(f"category term={term}")
        if term in source_path_lc:
            score += 30
            reasons.append(f"path term={term}")
        if term in title_lc:
            score += 18
            reasons.append(f"label term={term}")
        if term in callable_use_lc:
            score += 14
            reasons.append(f"use term={term}")
        if any(term in bullet for bullet in bullets):
            score += 12
            reasons.append(f"bullet term={term}")
        if any(term in sample for sample in samples):
            score += 10
            reasons.append(f"sample term={term}")
        if any(term in command for command in commands):
            score += 6
            reasons.append(f"command term={term}")

    deduped_reasons: list[str] = []
    seen: set[str] = set()
    for reason in reasons:
        if reason in seen:
            continue
        deduped_reasons.append(reason)
        seen.add(reason)
    return score, deduped_reasons[:6]


def build_brief(
    index: dict[str, Any],
    category: str,
    *,
    provider: str = "agent",
    task: str = "",
    max_objects_per_source_category: int = MAX_OBJECTS_PER_SOURCE_CATEGORY,
) -> dict[str, Any]:
    if category not in BRIEF_CATEGORY_SPECS:
        raise MemoryBriefError(f"unsupported brief category: {category}")
    spec = BRIEF_CATEGORY_SPECS[category]
    source_categories = tuple(spec["source_categories"])
    objects_by_source_category: dict[str, list[dict[str, Any]]] = {}
    selected_objects: list[dict[str, Any]] = []
    missing_source_categories: list[str] = []
    for source_category in source_categories:
        raw_selected = _select_objects(index, source_category, max_objects_per_source_category)
        if not raw_selected:
            missing_source_categories.append(source_category)
        selected = [_brief_object(obj) for obj in raw_selected]
        objects_by_source_category[source_category] = selected
        selected_objects.extend(selected)

    source_paths = [obj["source_path"] for obj in selected_objects if obj.get("source_path")]
    fail_closed_flags = [
        f"{obj['source_path']}: {obj['fail_closed_note']}"
        for obj in selected_objects
        if obj.get("fail_closed_note")
    ][:10]
    fail_closed_flags.extend(
        f"{source_category}: no indexed objects selected; treat this brief surface as unavailable"
        for source_category in missing_source_categories
    )
    estimated_source_bytes = sum(
        int(obj.get("summary_fields", {}).get("byte_size", 0))
        for source_category in source_categories
        for obj in _select_objects(index, source_category, max_objects_per_source_category)
        if isinstance(obj.get("summary_fields"), dict)
    )
    rough_source_tokens = _token_estimate(estimated_source_bytes)

    brief = {
        "category": category,
        "provider": provider,
        "task": _clean_text(task, limit=260) if task else "",
        "purpose": spec["purpose"],
        "handoff_rule": spec["handoff_rule"],
        "source_categories": list(source_categories),
        "coverage": _coverage_slice(index, source_categories),
        "objects_by_source_category": objects_by_source_category,
        "source_paths": source_paths,
        "fail_closed_flags": fail_closed_flags,
        "rough_source_tokens_if_opened": rough_source_tokens,
        "rough_brief_tokens": 0,
        "rough_token_savings": 0,
        "token_saving_mechanism": (
            "Uses the shared index only; caps source categories, objects, bullets, samples, and count fields; "
            "opens full source_path artifacts only when the selected brief is insufficient."
        ),
    }
    brief_json = json.dumps(brief, sort_keys=True)
    brief["rough_brief_tokens"] = _token_estimate(brief_json)
    brief["rough_token_savings"] = max(0, rough_source_tokens - brief["rough_brief_tokens"])
    return brief


def build_report(
    index: dict[str, Any],
    *,
    categories: Iterable[str] = SUPPORTED_CATEGORIES,
    provider: str = "agent",
    task: str = "",
    max_objects_per_source_category: int = MAX_OBJECTS_PER_SOURCE_CATEGORY,
    generated_at: str | None = None,
) -> dict[str, Any]:
    selected_categories = list(categories)
    if not selected_categories:
        selected_categories = list(SUPPORTED_CATEGORIES)
    briefs = [
        build_brief(
            index,
            category,
            provider=provider,
            task=task,
            max_objects_per_source_category=max_objects_per_source_category,
        )
        for category in selected_categories
    ]
    return {
        "schema": SCHEMA,
        "generated_date": DEFAULT_DATE,
        "generated_at_utc": generated_at or _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "source_index_schema": index.get("schema", ""),
        "source_index_generated_date": index.get("generated_date", ""),
        "source_index_memory_object_count": index.get("memory_object_count", len(index.get("memory_objects", []))),
        "supported_categories": list(SUPPORTED_CATEGORIES),
        "selected_categories": selected_categories,
        "provider": provider,
        "task": _clean_text(task, limit=260) if task else "",
        "briefs": briefs,
        "total_rough_source_tokens_if_opened": sum(item["rough_source_tokens_if_opened"] for item in briefs),
        "total_rough_brief_tokens": sum(item["rough_brief_tokens"] for item in briefs),
        "total_rough_token_savings": sum(item["rough_token_savings"] for item in briefs),
        "contract": [
            "Paste the matching brief category into model handoffs before asking for repo work.",
            "Use fail_closed_flags as blockers, not permission to infer missing evidence.",
            "Open source_paths only when the compact object list lacks the required detail.",
        ],
    }


def build_agent_bootstrap_packet(
    index: dict[str, Any],
    *,
    root: Path | None = None,
    provider: str = "agent",
    task: str = "",
    generated_at: str | None = None,
) -> dict[str, Any]:
    goal_loop = _resolve_local_report(root, BOOTSTRAP_SOURCE_PATHS["goal_loop"])
    decline_memory = _resolve_local_report(root, BOOTSTRAP_SOURCE_PATHS["declines"])
    entrypoints = _resolve_local_report(root, BOOTSTRAP_SOURCE_PATHS["entrypoints"])
    next_50 = _resolve_local_report(root, BOOTSTRAP_SOURCE_PATHS["next_50"])
    g1_next_work = _resolve_local_report(root, BOOTSTRAP_SOURCE_PATHS["g1_next_work"])

    goal_policy = goal_loop.get("goal_policy") if isinstance(goal_loop.get("goal_policy"), dict) else {}
    decline_decision = decline_memory.get("decision") if isinstance(decline_memory.get("decision"), dict) else {}
    next_packets = g1_next_work.get("packets") if isinstance(g1_next_work.get("packets"), list) else []
    top_priorities = g1_next_work.get("top_priorities") if isinstance(g1_next_work.get("top_priorities"), list) else []
    next_phases = next_50.get("phases") if isinstance(next_50.get("phases"), list) else []

    source_order = [
        _bootstrap_source_entry(index, path, order=idx, why=why)
        for idx, (path, why) in enumerate(
            (
                (
                    DEFAULT_BOOTSTRAP_SOURCE_ORDER[0],
                    "Anchor on the live branch state, operating contract, and front-door commands first.",
                ),
                (
                    DEFAULT_BOOTSTRAP_SOURCE_ORDER[1],
                    "Use the compact handoff status packet to pick the next local artifact instead of rereading the repo.",
                ),
                (
                    DEFAULT_BOOTSTRAP_SOURCE_ORDER[2],
                    "Open only the matching brief category once the slot or topic is known.",
                ),
                (
                    DEFAULT_BOOTSTRAP_SOURCE_ORDER[3],
                    "Escalate to the full index only when you need category coverage, stale flags, or source-path expansion.",
                ),
                (
                    DEFAULT_BOOTSTRAP_SOURCE_ORDER[4],
                    "Check vault and plain-file roots only when you need memory entrypoints or handoff file locations.",
                ),
            ),
            start=1,
        )
    ]

    next_work_categories = []
    for packet in next_packets[:3]:
        if not isinstance(packet, dict):
            continue
        next_work_categories.append(
            {
                "category": _clean_text(packet.get("primary_next_work", "unknown"), limit=80),
                "packet_id": _clean_text(packet.get("packet_id", ""), limit=80),
                "title": _clean_text(packet.get("title", ""), limit=140),
                "blocked_until": [_clean_text(item, limit=140) for item in packet.get("blocked_until", [])[:2] if isinstance(item, str)],
            }
        )
    if not next_work_categories:
        for phase in next_phases[:3]:
            if not isinstance(phase, dict):
                continue
            next_work_categories.append(
                {
                    "category": _clean_text(phase.get("name", "unknown"), limit=80),
                    "title": _clean_text(phase.get("goal", ""), limit=140),
                    "blocked_until": [_clean_text(item, limit=140) for item in phase.get("exit_criteria", [])[:2] if isinstance(item, str)],
                }
            )

    worktree = _clean_text(
        g1_next_work.get("worktree") or entrypoints.get("memory_root") or "",
        limit=200,
    )
    branch = _clean_text(
        g1_next_work.get("branch") or next_50.get("branch") or "",
        limit=100,
    )
    fail_closed_flags: list[str] = []
    if not goal_policy:
        fail_closed_flags.append("reports/goal_loop_status_2026-05-05.json: missing goal_policy")
    if not decline_decision:
        fail_closed_flags.append("reports/no_reason_decline_memory_2026-05-05.json: missing decision")
    if not next_work_categories:
        fail_closed_flags.append("reports/g1_next_work_packets_2026-05-05.json: missing next-work categories")
    for source in source_order:
        if source.get("status") == "missing":
            fail_closed_flags.append(f"{source['source_path']}: missing from shared-memory index")
        elif not source.get("live_state_allowed"):
            note = source.get("fail_closed_note") or "stale_or_limited"
            fail_closed_flags.append(
                f"{source['source_path']}: {note}; do not treat as live bootstrap state"
            )

    packet = {
        "schema": BOOTSTRAP_PACKET_SCHEMA,
        "generated_date": DEFAULT_DATE,
        "generated_at_utc": generated_at or _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "source_index_schema": index.get("schema", ""),
        "source_index_generated_date": index.get("generated_date", ""),
        "provider": provider,
        "task": _clean_text(task, limit=260) if task else "",
        "query": "agent bootstrap",
        "purpose": "Compact takeover packet for another model to resume work without opening broad docs first.",
        "active_checkpoint_policy": {
            "status": _clean_text(goal_policy.get("status", "unknown"), limit=80),
            "terminal_completion_allowed": bool(goal_policy.get("terminal_completion_allowed")),
            "loop_back_phase": _clean_text(goal_policy.get("loop_back_phase", ""), limit=80),
            "reason": _clean_text(goal_policy.get("reason", ""), limit=220),
            "source_path": BOOTSTRAP_SOURCE_PATHS["goal_loop"],
        },
        "live_state_source_order": source_order,
        "bug_bounty_decline_policy": {
            "classification": _clean_text(decline_decision.get("classification", "unknown"), limit=80),
            "memory_effect": _clean_text(decline_decision.get("memory_effect", ""), limit=160),
            "forbid_inference": [
                _clean_text(item, limit=80)
                for item in decline_decision.get("forbid_inference", [])[:6]
                if isinstance(item, str)
            ],
            "source_path": BOOTSTRAP_SOURCE_PATHS["declines"],
        },
        "branch_worktree_safety_warning": {
            "branch": branch,
            "worktree": worktree,
            "warning": _clean_text(
                (
                    f"Live memory/control-plane artifacts point at branch `{branch}` and worktree `{worktree}`. "
                    "Verify your own branch and worktree before editing, and do not assume the memory root is your active checkout."
                ),
                limit=260,
            ),
            "source_paths": [
                BOOTSTRAP_SOURCE_PATHS["entrypoints"],
                BOOTSTRAP_SOURCE_PATHS["g1_next_work"],
                BOOTSTRAP_SOURCE_PATHS["next_50"],
            ],
        },
        "next_work_categories": next_work_categories,
        "top_priority_titles": [
            _clean_text(item.get("title", ""), limit=140)
            for item in top_priorities[:3]
            if isinstance(item, dict) and item.get("title")
        ],
        "suggested_brief_categories": ["audit_handoff"],
        "source_paths": [entry["source_path"] for entry in source_order],
        "fail_closed_flags": fail_closed_flags[:10],
        "contract": [
            "Use this packet before broader docs when a fresh model needs only the live takeover guardrails.",
            "Treat missing bootstrap fields as blockers and reopen the named source artifact before proceeding.",
            "Treat stale or truncated live-state sources as blockers until the shared-memory index is regenerated.",
            "Escalate to memory brief categories or the shared-memory index only when this packet lacks task-specific detail.",
        ],
        "rough_packet_tokens": 0,
        "rough_selected_source_tokens": 0,
        "rough_token_savings": 0,
    }
    source_token_estimate = sum(
        _token_estimate(_byte_size_for_source(index, entry["source_path"], root=root))
        for entry in source_order
        if entry.get("status") != "missing"
    )
    source_token_estimate += _token_estimate(_byte_size_for_source(index, BOOTSTRAP_SOURCE_PATHS["goal_loop"], root=root))
    source_token_estimate += _token_estimate(_byte_size_for_source(index, BOOTSTRAP_SOURCE_PATHS["declines"], root=root))
    source_token_estimate += _token_estimate(_byte_size_for_source(index, BOOTSTRAP_SOURCE_PATHS["next_50"], root=root))
    source_token_estimate += _token_estimate(_byte_size_for_source(index, BOOTSTRAP_SOURCE_PATHS["g1_next_work"], root=root))
    packet["rough_selected_source_tokens"] = source_token_estimate
    packet["rough_packet_tokens"] = _token_estimate(json.dumps(packet, sort_keys=True))
    packet["rough_token_savings"] = max(0, packet["rough_selected_source_tokens"] - packet["rough_packet_tokens"])
    return packet


def build_query_packet(
    index: dict[str, Any],
    query: str,
    *,
    root: Path | None = None,
    provider: str = "agent",
    task: str = "",
    max_sources: int = DEFAULT_QUERY_MAX_SOURCES,
    generated_at: str | None = None,
) -> dict[str, Any]:
    normalized_query, alias_spec = _query_topic_spec(query)
    if alias_spec and alias_spec.get("mode") == "agent_bootstrap":
        return build_agent_bootstrap_packet(
            index,
            root=root,
            provider=provider,
            task=task,
            generated_at=generated_at,
        )
    base_terms = _query_tokens(query)
    alias_terms = list(alias_spec.get("extra_terms", ())) if alias_spec else []
    query_terms = sorted(set(base_terms + alias_terms))
    matches: list[dict[str, Any]] = []
    for obj in index.get("memory_objects", []):
        if not isinstance(obj, dict):
            continue
        if alias_spec and str(obj.get("category", "")) not in alias_spec.get("source_categories", ()):
            continue
        score, reasons = _match_reasons_for_object(obj, query_terms, alias_spec)
        if score <= 0:
            continue
        selected = _brief_object(obj)
        selected["category"] = str(obj.get("category", ""))
        selected["callable_use"] = _clean_text(obj.get("callable_use", ""), limit=220)
        selected["match_score"] = score
        selected["match_reasons"] = reasons
        matches.append(selected)

    matches.sort(
        key=lambda item: (
            -int(item.get("match_score", 0)),
            {"fresh": 0, "stale_or_limited": 1, "missing": 2}.get(str(item.get("status")), 3),
            str(item.get("source_path", "")),
        )
    )
    matched_source_categories = sorted({item["category"] for item in matches if item.get("category")})
    selected_matches = matches[: max(1, max_sources)]
    selected_source_categories = sorted({item["category"] for item in selected_matches if item.get("category")})

    expected_source_categories = list(alias_spec.get("source_categories", ())) if alias_spec else []
    suggested_brief_categories = list(alias_spec.get("brief_categories", ())) if alias_spec else []
    if not suggested_brief_categories:
        suggested_brief_categories = _brief_categories_for_source_categories(selected_source_categories)

    fail_closed_flags = [
        f"{item['source_path']}: {item['fail_closed_note']}"
        for item in selected_matches
        if item.get("fail_closed_note")
    ]
    if alias_spec:
        for category in expected_source_categories:
            if category not in matched_source_categories:
                fail_closed_flags.append(
                    f"{category}: no indexed topic match for query `{_clean_text(query, limit=80)}`"
                )
    if not selected_matches:
        fail_closed_flags.append(
            f"no indexed sources matched query `{_clean_text(query, limit=120)}`; open the shared-memory index manually"
        )

    source_paths = [item["source_path"] for item in selected_matches if item.get("source_path")]
    total_source_tokens = sum(_token_estimate(json.dumps(item, sort_keys=True)) for item in selected_matches)
    packet = {
        "schema": QUERY_PACKET_SCHEMA,
        "generated_date": DEFAULT_DATE,
        "generated_at_utc": generated_at or _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "source_index_schema": index.get("schema", ""),
        "source_index_generated_date": index.get("generated_date", ""),
        "provider": provider,
        "task": _clean_text(task, limit=260) if task else "",
        "query": _clean_text(query, limit=260),
        "normalized_query": normalized_query,
        "query_terms": query_terms,
        "recognized_topic": normalized_query if alias_spec else "",
        "purpose": (
            alias_spec.get("purpose")
            if alias_spec
            else "Compact source-linked packet over the shared-memory index for a narrow local topic query."
        ),
        "expected_source_categories": expected_source_categories,
        "matched_source_categories": matched_source_categories,
        "selected_source_categories": selected_source_categories,
        "suggested_brief_categories": suggested_brief_categories,
        "source_paths": source_paths,
        "sources": selected_matches,
        "fail_closed_flags": fail_closed_flags[:10],
        "rough_packet_tokens": 0,
        "rough_selected_source_tokens": total_source_tokens,
        "contract": [
            "Use this packet before opening full docs or reports for the topic.",
            "Treat fail_closed_flags as blockers, not permission to infer missing evidence.",
            "Escalate to the broader memory brief only when the selected source paths are insufficient.",
        ],
    }
    packet["rough_packet_tokens"] = _token_estimate(json.dumps(packet, sort_keys=True))
    return packet


def _objects_by_path(index: dict[str, Any]) -> dict[str, dict[str, Any]]:
    objects: dict[str, dict[str, Any]] = {}
    for obj in index.get("memory_objects", []):
        if not isinstance(obj, dict):
            continue
        source_path = str(obj.get("source_path", ""))
        if source_path and source_path not in objects:
            objects[source_path] = obj
    return objects


def _bootstrap_source(obj: dict[str, Any]) -> dict[str, Any]:
    source = _brief_object(obj)
    summary = obj.get("summary_fields") if isinstance(obj.get("summary_fields"), dict) else {}
    samples = summary.get("samples")
    if isinstance(samples, list) and samples:
        source["samples"] = [_compact_sample(item) for item in samples[:DEFAULT_MEMORY_BOOTSTRAP_MAX_ACTIONS]]
    source["category"] = str(obj.get("category", ""))
    source["callable_use"] = _clean_text(obj.get("callable_use", ""), limit=220)
    return source


def _bootstrap_action_from_sample(source: dict[str, Any], sample: dict[str, Any]) -> dict[str, Any] | None:
    action_text = sample.get("next_action") or sample.get("action") or sample.get("expected_next_action") or sample.get("suggested_next_action")
    if not action_text:
        return None
    action_id = sample.get("id") or sample.get("limitation_id") or sample.get("row_id") or sample.get("task_id")
    action = {
        "source_path": source.get("source_path", ""),
        "source_category": source.get("category", ""),
        "id": _clean_text(action_id, limit=80) if action_id else "",
        "lane": _clean_text(sample.get("dispatch_lane") or sample.get("owner_lane") or "", limit=80)
        if sample.get("dispatch_lane") or sample.get("owner_lane")
        else "",
        "status": _clean_text(sample.get("current_status") or sample.get("status") or "", limit=120),
        "priority": sample.get("priority", ""),
        "next_action_status": _clean_text(sample.get("next_action_status", ""), limit=120),
        "next_action": _clean_text(action_text, limit=220),
    }
    blockers = sample.get("blockers")
    if isinstance(blockers, list) and blockers:
        action["blockers"] = [_clean_text(item, limit=120) for item in blockers[:3]]
    missing_inputs = sample.get("missing_inputs")
    if isinstance(missing_inputs, list) and missing_inputs:
        action["missing_inputs"] = [_clean_text(item, limit=100) for item in missing_inputs[:4]]
    actionable_now_commands = sample.get("actionable_now_commands")
    if isinstance(actionable_now_commands, list) and actionable_now_commands:
        action["actionable_now_commands"] = [_clean_text(item, limit=180) for item in actionable_now_commands[:3]]
    blocked_command_templates = sample.get("blocked_command_templates")
    if isinstance(blocked_command_templates, list) and blocked_command_templates:
        action["blocked_command_templates"] = [
            {
                "command": _clean_text(item.get("command", ""), limit=180),
                "missing_inputs": [_clean_text(raw, limit=80) for raw in item.get("missing_inputs", [])[:3]]
                if isinstance(item.get("missing_inputs"), list)
                else [],
            }
            for item in blocked_command_templates[:2]
            if isinstance(item, dict)
        ]
    return action


def _bootstrap_actions(sources: list[dict[str, Any]], max_actions: int) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for source in sources:
        for sample in source.get("samples", []):
            if not isinstance(sample, dict):
                continue
            action = _bootstrap_action_from_sample(source, sample)
            if not action:
                continue
            key = (
                str(action.get("id", "")),
                str(action.get("source_path", "")),
                str(action.get("next_action", "")),
            )
            if key in seen:
                continue
            seen.add(key)
            actions.append(action)
            if len(actions) >= max_actions:
                return actions
    return actions


def _bootstrap_counts(sources: list[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, Any] = {}
    for source in sources:
        source_counts = source.get("counts")
        if not isinstance(source_counts, dict):
            continue
        prefix = str(source.get("category") or source.get("source_path") or "source")
        for key, value in source_counts.items():
            if len(counts) >= 18:
                return counts
            if isinstance(value, dict):
                counts[f"{prefix}.{key}"] = {
                    str(inner_key): value[inner_key]
                    for inner_key in sorted(value, key=str)[:4]
                    if isinstance(value[inner_key], (str, int, float, bool)) or value[inner_key] is None
                }
            elif isinstance(value, (str, int, float, bool)) or value is None:
                counts[f"{prefix}.{key}"] = value
    return counts


def build_bootstrap_packet(
    index: dict[str, Any],
    *,
    provider: str = "agent",
    task: str = "",
    max_actions: int = DEFAULT_MEMORY_BOOTSTRAP_MAX_ACTIONS,
    generated_at: str | None = None,
) -> dict[str, Any]:
    objects = _objects_by_path(index)
    sources: list[dict[str, Any]] = []
    missing_required_sources: list[str] = []
    for source_path in MEMORY_BOOTSTRAP_SOURCE_PATHS:
        obj = objects.get(source_path)
        if not obj:
            missing_required_sources.append(source_path)
            continue
        sources.append(_bootstrap_source(obj))

    source_paths = [source["source_path"] for source in sources if source.get("source_path")]
    fail_closed_flags = [
        f"{source['source_path']}: {source['fail_closed_note']}"
        for source in sources
        if source.get("fail_closed_note")
    ]
    fail_closed_flags.extend(
        f"{source_path}: required bootstrap source missing from shared-memory index"
        for source_path in missing_required_sources
    )

    broad_doc_tokens_avoided = 0
    broad_doc_paths_present: list[str] = []
    for path in BROAD_DOCS_AVOIDED_BY_MEMORY_BOOTSTRAP:
        obj = objects.get(path)
        if not obj:
            continue
        summary = obj.get("summary_fields") if isinstance(obj.get("summary_fields"), dict) else {}
        broad_doc_tokens_avoided += _token_estimate(int(summary.get("byte_size", 0) or 0))
        broad_doc_paths_present.append(path)

    packet = {
        "schema": MEMORY_BOOTSTRAP_PACKET_SCHEMA,
        "generated_date": DEFAULT_DATE,
        "generated_at_utc": generated_at or _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "source_index_schema": index.get("schema", ""),
        "source_index_generated_date": index.get("generated_date", ""),
        "provider": provider,
        "task": _clean_text(task, limit=260) if task else "",
        "purpose": "Single low-context bootstrap packet for current operational state without broad doc rereads.",
        "priority_order": ["MEMORY", "HARNESS", "KNOWN LIMITATION BURNDOWN"],
        "priority_lanes": [
            "memory_handoff",
            "harness_execution",
            "harness_binding",
            "known_limitations_burndown",
        ],
        "priority_lane_mapping": {
            "MEMORY": ["memory_handoff"],
            "HARNESS": ["harness_execution", "harness_binding"],
            "KNOWN LIMITATION BURNDOWN": ["known_limitations_burndown"],
        },
        "operating_contract": [
            "Start from this packet before opening narrative docs.",
            "Treat memory, harness, and known-limitation rows as routing and blocker state, not exploit proof.",
            "Open listed report source_paths only when the compact action list lacks required detail.",
            "Fail closed on missing or stale bootstrap sources.",
        ],
        "read_first_report_paths": source_paths,
        "sources": sources,
        "priority_actions": _bootstrap_actions(sources, max(1, max_actions)),
        "status_counts": _bootstrap_counts(sources),
        "fail_closed_flags": fail_closed_flags[:12],
        "broad_docs_avoided": broad_doc_paths_present,
        "rough_broad_doc_tokens_avoided": broad_doc_tokens_avoided,
        "rough_packet_tokens": 0,
        "closed_limitation": {
            "id": "memory-bootstrap-broad-doc-reread",
            "before": "Lower-context agents had to compose current state from several broad docs and category briefs before acting.",
            "after": "A single report-sourced bootstrap packet carries current memory, harness, and known-limitation routing state.",
            "benefit": "Agents can load operational state from bounded reports first and reserve broad docs for missing-detail follow-up.",
        },
    }
    packet["rough_packet_tokens"] = _token_estimate(json.dumps(packet, sort_keys=True))
    return packet


def render_bootstrap_markdown(packet: dict[str, Any]) -> str:
    lines = [
        f"# Memory Bootstrap - {packet['generated_date']}",
        "",
        f"- Schema: `{packet['schema']}`",
        f"- Source index date: `{packet['source_index_generated_date']}`",
        f"- Rough packet tokens: `{packet['rough_packet_tokens']}`",
        f"- Rough broad-doc tokens avoided: `{packet['rough_broad_doc_tokens_avoided']}`",
        "",
        packet["purpose"],
        "",
        "## Operating Contract",
        "",
    ]
    for rule in packet["operating_contract"]:
        lines.append(f"- {_clean_text(rule, limit=220)}")
    lines.extend(["", "## Read First Reports", ""])
    for source_path in packet["read_first_report_paths"]:
        lines.append(f"- `{source_path}`")
    if packet["fail_closed_flags"]:
        lines.extend(["", "## Fail-Closed Flags", ""])
        for flag in packet["fail_closed_flags"][:8]:
            lines.append(f"- {_clean_text(flag, limit=220)}")
    lines.extend(["", "## Priority Actions", ""])
    if not packet["priority_actions"]:
        lines.append("- No compact priority actions were available; open the read-first reports above.")
    for action in packet["priority_actions"]:
        ident = f"`{action['id']}` " if action.get("id") else ""
        lane = f" [{action['lane']}]" if action.get("lane") else ""
        status = f" ({action['status']})" if action.get("status") else ""
        lines.append(f"- {ident}{lane}{status}: {action['next_action']}")
        if action.get("missing_inputs"):
            lines.append(f"  - Missing inputs: {', '.join(action['missing_inputs'])}")
        if action.get("blockers"):
            lines.append(f"  - Blockers: {', '.join(action['blockers'])}")
        if action.get("next_action_status"):
            lines.append(f"  - Next-action status: `{action['next_action_status']}`")
        if action.get("actionable_now_commands"):
            lines.append(f"  - Actionable now: `{action['actionable_now_commands'][0]}`")
        if action.get("blocked_command_templates"):
            lines.append(f"  - Blocked template: `{action['blocked_command_templates'][0]['command']}`")
    lines.extend(["", "## Closed Limitation", ""])
    closed = packet["closed_limitation"]
    lines.append(f"- `{closed['id']}`: {closed['benefit']}")
    return "\n".join(lines).rstrip() + "\n"


def render_query_markdown(packet: dict[str, Any]) -> str:
    if packet.get("schema") == BOOTSTRAP_PACKET_SCHEMA:
        source_order = packet.get("live_state_source_order", [])
        lines = [
            "# Agent Bootstrap Packet",
            "",
            f"- Schema: `{packet['schema']}`",
            f"- Source index date: `{packet['source_index_generated_date']}`",
            f"- Rough packet tokens: `{packet['rough_packet_tokens']}`",
            f"- Rough token savings: `{packet['rough_token_savings']}`",
            "",
            packet["purpose"],
            "",
            "## Active Checkpoint Policy",
            "",
            f"- Status: `{packet['active_checkpoint_policy']['status']}`",
            f"- Terminal completion allowed: `{packet['active_checkpoint_policy']['terminal_completion_allowed']}`",
            f"- Loop-back phase: `{packet['active_checkpoint_policy']['loop_back_phase']}`",
            f"- Reason: {packet['active_checkpoint_policy']['reason']}",
            "",
            "## Live State Source Order",
            "",
        ]
        for source in source_order:
            live_hint = "live" if source.get("live_state_allowed") else "not-live"
            lines.append(
                f"- {source['order']}. `{source['source_path']}` ({source.get('status', 'unknown')}, {live_hint}): {source.get('why', '')}"
            )
        lines.extend(
            [
                "",
                "## Bug Bounty Decline Policy",
                "",
                f"- Classification: `{packet['bug_bounty_decline_policy']['classification']}`",
                f"- Memory effect: {packet['bug_bounty_decline_policy']['memory_effect']}",
                (
                    "- Forbid inference: "
                    + ", ".join(f"`{item}`" for item in packet["bug_bounty_decline_policy"]["forbid_inference"])
                ),
                "",
                "## Branch/Worktree Safety",
                "",
                f"- Branch: `{packet['branch_worktree_safety_warning']['branch']}`",
                f"- Worktree: `{packet['branch_worktree_safety_warning']['worktree']}`",
                f"- Warning: {packet['branch_worktree_safety_warning']['warning']}",
                "",
                "## Next-Work Categories",
                "",
            ]
        )
        for item in packet.get("next_work_categories", []):
            lines.append(
                f"- `{item.get('category', 'unknown')}`"
                + (f" [{item['packet_id']}]" if item.get("packet_id") else "")
                + f": {item.get('title', '')}"
            )
            for blocked in item.get("blocked_until", [])[:2]:
                lines.append(f"  - Blocked until: {blocked}")
        if packet.get("top_priority_titles"):
            lines.extend(["", "## Top Priorities", ""])
            for title in packet["top_priority_titles"]:
                lines.append(f"- {title}")
        if packet["fail_closed_flags"]:
            lines.extend(["", "## Fail-Closed Flags", ""])
            for flag in packet["fail_closed_flags"][:6]:
                lines.append(f"- {_clean_text(flag, limit=220)}")
        return "\n".join(lines).rstrip() + "\n"
    lines = [
        f"# Memory Topic Packet - {packet['query']}",
        "",
        f"- Schema: `{packet['schema']}`",
        f"- Source index date: `{packet['source_index_generated_date']}`",
        f"- Suggested brief categories: {', '.join(f'`{item}`' for item in packet['suggested_brief_categories']) or '`none`'}",
        f"- Matched source categories: {', '.join(f'`{item}`' for item in packet['matched_source_categories']) or '`none`'}",
        f"- Rough packet tokens: `{packet['rough_packet_tokens']}`",
        "",
        packet["purpose"],
        "",
    ]
    if packet["fail_closed_flags"]:
        lines.append("## Fail-Closed Flags")
        lines.append("")
        for flag in packet["fail_closed_flags"][:6]:
            lines.append(f"- {_clean_text(flag, limit=220)}")
        lines.append("")
    lines.append("## Sources")
    lines.append("")
    for source in packet["sources"]:
        lines.append(
            f"- `{source['source_path']}` [{source['category']}] ({source['status']} score={source['match_score']}): {source['label']}"
        )
        if source.get("match_reasons"):
            lines.append(f"  - Why: {', '.join(source['match_reasons'])}")
        if source.get("counts"):
            count_hint = ", ".join(
                f"{key}={len(value)} keys" if isinstance(value, dict) else f"{key}={value}"
                for key, value in list(source["counts"].items())[:4]
            )
            lines.append(f"  - Counts: {count_hint}")
        for point in source.get("key_points", [])[:2]:
            lines.append(f"  - {point}")
        for sample in source.get("samples", [])[:1]:
            sample_hint = ", ".join(f"{key}={value}" for key, value in sample.items())
            lines.append(f"  - Sample: {sample_hint}")
        for command in source.get("command_hints", [])[:1]:
            lines.append(f"  - Command: {command}")
    return "\n".join(lines).rstrip() + "\n"


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# Memory Brief - {report['generated_date']}",
        "",
        "Compact handoff surface over `reports/shared_memory_index_2026-05-05.json`.",
        "",
        f"- Schema: `{report['schema']}`",
        f"- Supported categories: {', '.join(f'`{item}`' for item in report['supported_categories'])}",
        f"- Rough source tokens if opened: `{report['total_rough_source_tokens_if_opened']}`",
        f"- Rough brief tokens: `{report['total_rough_brief_tokens']}`",
        f"- Rough token savings: `{report['total_rough_token_savings']}`",
        "",
        "## Use",
        "",
        "Paste only the matching category into Claude/Kimi/Minimax/Codex handoffs. Open listed source paths only when the brief is insufficient.",
        "",
    ]
    for brief in report["briefs"]:
        lines.extend(
            [
                f"## {brief['category']}",
                "",
                f"- Purpose: {brief['purpose']}",
                f"- Rule: {brief['handoff_rule']}",
                f"- Source categories: {', '.join(f'`{item}`' for item in brief['source_categories'])}",
                f"- Rough token savings: `{brief['rough_token_savings']}`",
            ]
        )
        if brief["fail_closed_flags"]:
            lines.append("- Fail-closed flags:")
            for flag in brief["fail_closed_flags"][:5]:
                lines.append(f"  - {_clean_text(flag, limit=220)}")
        lines.append("")
        for source_category, objects in brief["objects_by_source_category"].items():
            lines.append(f"### `{source_category}`")
            if not objects:
                lines.append("- No indexed objects selected.")
                continue
            for obj in objects:
                status = obj["status"]
                label = obj["label"]
                lines.append(f"- `{obj['source_path']}` ({status}): {label}")
                counts = obj.get("counts")
                if isinstance(counts, dict) and counts:
                    count_hint = ", ".join(
                        f"{key}={len(value)} keys" if isinstance(value, dict) else f"{key}={value}"
                        for key, value in list(counts.items())[:4]
                    )
                    lines.append(f"  - Counts: {count_hint}")
                for point in obj.get("key_points", [])[:2]:
                    lines.append(f"  - {point}")
                if obj.get("fail_closed_note"):
                    lines.append(f"  - Fail closed: {obj['fail_closed_note']}")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_json(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if report.get("schema") in {QUERY_PACKET_SCHEMA, BOOTSTRAP_PACKET_SCHEMA}:
        renderer = render_query_markdown
    elif report.get("schema") == MEMORY_BOOTSTRAP_PACKET_SCHEMA:
        renderer = render_bootstrap_markdown
    else:
        renderer = render_markdown
    path.write_text(renderer(report), encoding="utf-8")


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--index", default=DEFAULT_INDEX)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument("--markdown-output", default=DEFAULT_MARKDOWN_OUTPUT)
    parser.add_argument("--category", action="append", choices=SUPPORTED_CATEGORIES, help="Brief category to emit; repeatable.")
    parser.add_argument("--query", help="Topic query that emits a compact source-linked packet instead of the broad memory brief.")
    parser.add_argument("--agent-bootstrap", action="store_true", help="Emit the compact takeover bootstrap packet.")
    parser.add_argument("--max-query-sources", type=int, default=DEFAULT_QUERY_MAX_SOURCES)
    parser.add_argument("--bootstrap", action="store_true", help="Emit the low-context current-state bootstrap packet.")
    parser.add_argument("--max-bootstrap-actions", type=int, default=DEFAULT_MEMORY_BOOTSTRAP_MAX_ACTIONS)
    parser.add_argument("--provider", default="agent", help="Target handoff provider/model family.")
    parser.add_argument("--task", default="", help="Optional task label to stamp into the brief.")
    parser.add_argument("--max-objects-per-source-category", type=int, default=MAX_OBJECTS_PER_SOURCE_CATEGORY)
    parser.add_argument("--print-json", action="store_true", help="Print JSON instead of writing artifacts.")
    parser.add_argument("--print-markdown", action="store_true", help="Print Markdown to stdout instead of writing artifacts.")
    return parser.parse_args(argv)


def _resolve_under_root(root: Path, path_value: str) -> Path:
    path = Path(path_value)
    return path if path.is_absolute() else root / path


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    root = Path(args.root).resolve()
    try:
        index = _read_index(_resolve_under_root(root, args.index))
        if args.bootstrap and (args.query or args.agent_bootstrap):
            raise MemoryBriefError("--bootstrap is mutually exclusive with --query and --agent-bootstrap")
        if args.bootstrap:
            packet = build_bootstrap_packet(
                index,
                provider=args.provider,
                task=args.task,
                max_actions=max(1, args.max_bootstrap_actions),
            )
            explicit_output = args.output != DEFAULT_OUTPUT or args.markdown_output != DEFAULT_MARKDOWN_OUTPUT
            if args.print_json:
                print(json.dumps(packet, indent=2, sort_keys=True))
                return 0
            if args.print_markdown or not explicit_output:
                print(render_bootstrap_markdown(packet))
                return 0
            output = _resolve_under_root(root, args.output)
            markdown_output = _resolve_under_root(root, args.markdown_output)
            write_json(output, packet)
            write_markdown(markdown_output, packet)
            print(f"[memory-brief] wrote {output.relative_to(root)} and {markdown_output.relative_to(root)}")
            print(
                "[memory-brief] bootstrap_sources="
                f"{len(packet['read_first_report_paths'])} priority_actions={len(packet['priority_actions'])}"
            )
            return 0
        query_value = "agent bootstrap" if args.agent_bootstrap else args.query
        if query_value:
            packet = build_query_packet(
                index,
                query_value,
                root=root,
                provider=args.provider,
                task=args.task,
                max_sources=max(1, args.max_query_sources),
            )
            explicit_output = args.output != DEFAULT_OUTPUT or args.markdown_output != DEFAULT_MARKDOWN_OUTPUT
            if args.print_json:
                print(json.dumps(packet, indent=2, sort_keys=True))
                return 0
            if args.print_markdown or not explicit_output:
                print(render_query_markdown(packet))
                return 0
            output = _resolve_under_root(root, args.output)
            markdown_output = _resolve_under_root(root, args.markdown_output)
            write_json(output, packet)
            write_markdown(markdown_output, packet)
            print(f"[memory-brief] wrote {output.relative_to(root)} and {markdown_output.relative_to(root)}")
            print(
                "[memory-brief] query="
                f"{packet['query']} matched_categories={','.join(packet.get('matched_source_categories', packet.get('suggested_brief_categories', [])))}"
            )
            return 0
        report = build_report(
            index,
            categories=args.category or SUPPORTED_CATEGORIES,
            provider=args.provider,
            task=args.task,
            max_objects_per_source_category=max(1, args.max_objects_per_source_category),
        )
        if args.print_json:
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0
        output = _resolve_under_root(root, args.output)
        markdown_output = _resolve_under_root(root, args.markdown_output)
        if args.print_markdown:
            print(render_markdown(report))
            return 0
        write_json(output, report)
        write_markdown(markdown_output, report)
    except MemoryBriefError as exc:
        print(f"[memory-brief] error: {exc}", file=sys.stderr)
        return 1
    print(f"[memory-brief] wrote {output.relative_to(root)} and {markdown_output.relative_to(root)}")
    print(
        "[memory-brief] categories="
        f"{','.join(report['selected_categories'])} rough_token_savings={report['total_rough_token_savings']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
