#!/usr/bin/env python3
"""Build a bounded work queue from real-world recall gap priorities.

The prioritizer ranks weak attack classes. This tool turns that ranking into
concrete, closeable rows for workers: one row per next-task item, with the
miss examples, detector overlap, repo examples, suggested local commands, and
explicit closeout requirements needed to avoid false completion.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PRIORITIES = REPO_ROOT / "reports" / "realworld_recall_gap_priorities.json"
DEFAULT_OUT = REPO_ROOT / "reports" / "realworld_recall_work_queue.jsonl"
DEFAULT_QUALITY_GLOB = "external_recall_manifest_quality*.json"

PRIORITIES_SCHEMA = "auditooor.realworld_recall_gap_priorities.v1"
QUALITY_SCHEMA = "auditooor.external_recall_manifest_quality.v1"
ROW_SCHEMA = "auditooor.realworld_recall_work_queue.row.v2"
SUMMARY_SCHEMA = "auditooor.realworld_recall_work_queue_summary.v1"

OWN_DETECTOR_EVIDENCE_TASK_TYPES = {"detector-generalization", "sibling-detector-gap"}
EXTERNAL_REPLAY_TASK_TYPES = {"external-replay"}
SOURCE_ARTIFACT_TASK_TYPES = {
    "detector-generalization",
    "external-replay",
    "sibling-detector-gap",
    "source-state-validation",
}

OWN_DETECTOR_BACKED_RE = re.compile(r"(\d+)\s+own-detector-backed", re.IGNORECASE)
EXTERNAL_RECALL_PCT_RE = re.compile(
    r"(?:current\s+external\s+)?same-class\s+recall\s+is\s+([0-9]+(?:\.[0-9]+)?)\s*%",
    re.IGNORECASE,
)


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_slug(value: str, limit: int = 72) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip().lower()).strip("-._")
    text = re.sub(r"-{2,}", "-", text)
    return (text or "queue")[:limit].strip("-") or "queue"


def _sample_quality_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")


def _relpath(path: Path, root: Path = REPO_ROOT) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _existing_source_path(value: str) -> str:
    text = _string(value)
    if not text:
        return ""
    path = Path(text).expanduser()
    if path.is_absolute():
        return _relpath(path, REPO_ROOT) if path.exists() else ""
    candidate = REPO_ROOT / path
    if candidate.exists():
        return _relpath(candidate, REPO_ROOT)
    return ""


def _source_artifacts_for_miss(slug: str, source: str, explicit_path: Any = "") -> list[str]:
    """Return bounded local artifacts that can ground provider review.

    The recall scoreboard often carries only a slug, which is enough for local
    accounting but too thin for Kimi/MiniMax packets. Prefer exact explicit
    paths, then pattern YAML / fixture paths derived from the slug. These are
    evidence pointers, not proof of exploitability.
    """
    candidates: list[str] = []
    explicit = _existing_source_path(_string(explicit_path))
    if explicit:
        candidates.append(explicit)

    for value in (slug, source):
        existing = _existing_source_path(value)
        if existing:
            candidates.append(existing)

    slug_text = _string(slug)
    if slug_text:
        slug_file = _safe_slug(slug_text, limit=160)
        slug_dir = slug_file.replace("-", "_")
        likely_paths = [
            REPO_ROOT / "reference" / "patterns.dsl" / f"{slug_text}.yaml",
            REPO_ROOT / "reference" / "patterns.dsl" / f"{slug_file}.yaml",
            REPO_ROOT / "patterns" / "fixtures" / f"{slug_text}_vuln.sol",
            REPO_ROOT / "patterns" / "fixtures" / f"{slug_text}_clean.sol",
            REPO_ROOT / "patterns" / "fixtures" / f"{slug_file}_vuln.sol",
            REPO_ROOT / "patterns" / "fixtures" / f"{slug_file}_clean.sol",
        ]
        fixture_dirs = [
            REPO_ROOT / "detectors" / "fixtures" / slug_text,
            REPO_ROOT / "detectors" / "fixtures" / slug_file,
            REPO_ROOT / "detectors" / "fixtures" / slug_dir,
        ]
        for directory in fixture_dirs:
            if directory.is_dir():
                likely_paths.extend(sorted(directory.glob("*.sol"))[:4])
                likely_paths.extend(sorted(directory.glob("*manifest.json"))[:2])
        for path in likely_paths:
            if path.exists():
                candidates.append(_relpath(path, REPO_ROOT))

    # Stable de-duplication with a hard bound for provider packets.
    return list(dict.fromkeys(candidates))[:10]


def _quality_sample_source_path(value: Any, report_path: Path) -> str:
    text = _string(value)
    if not text:
        return ""
    path = Path(text).expanduser()
    if path.is_absolute():
        return _relpath(path, REPO_ROOT) if path.exists() else text

    repo_candidate = REPO_ROOT / path
    if repo_candidate.exists():
        return _relpath(repo_candidate, REPO_ROOT)

    report_candidate = report_path.parent / path
    if report_candidate.exists():
        return _relpath(report_candidate, REPO_ROOT)

    return text


def _float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _string(value: Any) -> str:
    return str(value or "").strip()


def _bounded_dicts(value: Any, *, limit: int) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    out: list[dict[str, Any]] = []
    for item in value:
        if isinstance(item, dict):
            out.append(item)
        if len(out) >= limit:
            break
    return out


def load_priorities(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON at line {exc.lineno} column {exc.colno}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: top-level JSON must be an object")
    if payload.get("schema") != PRIORITIES_SCHEMA:
        raise ValueError(f"{path}: schema must be {PRIORITIES_SCHEMA}")
    if not isinstance(payload.get("priorities"), list):
        raise ValueError(f"{path}: priorities must be a list")
    if payload.get("taxonomy_debt") is not None and not isinstance(payload.get("taxonomy_debt"), list):
        raise ValueError(f"{path}: taxonomy_debt must be a list when present")
    return payload, _sha256_bytes(raw)


def load_quality_reports(paths: list[Path]) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Aggregate external-manifest quality reports by attack class.

    Quality reports are advisory guards, not detector evidence. A class is
    marked quality-blocked only when every quality-gated sample for that class
    is ineligible and at least one blocker exists.
    """
    by_attack: dict[str, dict[str, Any]] = {}
    loaded_paths: list[str] = []
    for path in paths:
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict) or data.get("schema") != QUALITY_SCHEMA:
            continue
        generated_at = _string(data.get("generated_at"))
        loaded_paths.append(_relpath(path))
        rows = data.get("rows") if isinstance(data.get("rows"), list) else []
        manifest_errors = data.get("manifest_errors") if isinstance(data.get("manifest_errors"), list) else []
        for row in rows:
            if not isinstance(row, dict):
                continue
            attack_class = _string(row.get("attack_class"))
            if not attack_class:
                continue
            entry = by_attack.setdefault(
                attack_class,
                {
                    "schema": QUALITY_SCHEMA,
                    "quality_report_paths": [],
                    "sample_count": 0,
                    "gap_eligible": 0,
                    "blockers": 0,
                    "needs_source_state_validation": 0,
                    "disqualified_source_state": 0,
                    "manifest_errors": 0,
                    "sample_ids": [],
                    "sample_quality": {},
                    "required_actions": [],
                    "quality_blocked": False,
                },
            )
            if _relpath(path) not in entry["quality_report_paths"]:
                entry["quality_report_paths"].append(_relpath(path))
            entry["sample_count"] += 1
            if bool(row.get("gap_prioritization_eligible")):
                entry["gap_eligible"] += 1
            quality_state = _string(row.get("quality_state"))
            if quality_state == "needs_source_state_validation":
                entry["needs_source_state_validation"] += 1
            elif quality_state == "disqualified_source_state":
                entry["disqualified_source_state"] += 1
            if quality_state != "gap_eligible":
                entry["blockers"] += 1
            sample_id = _string(row.get("id"))
            if sample_id and len(entry["sample_ids"]) < 8:
                entry["sample_ids"].append(sample_id)
            sample_key = _sample_quality_key(sample_id)
            if sample_key:
                existing = entry["sample_quality"].get(sample_key)
                if not existing or generated_at >= _string(existing.get("generated_at")):
                    entry["sample_quality"][sample_key] = {
                        "id": sample_id,
                        "generated_at": generated_at,
                        "quality_state": quality_state,
                        "gap_prioritization_eligible": bool(row.get("gap_prioritization_eligible")),
                        "source_state": _string(row.get("source_state")),
                        "source": _string(row.get("source")),
                        "path": _quality_sample_source_path(row.get("path"), path),
                        "quality_report_path": _relpath(path),
                    }
            actions = row.get("required_actions")
            if isinstance(actions, list):
                for action in actions:
                    action_text = _string(action)
                    if action_text and action_text not in entry["required_actions"] and len(entry["required_actions"]) < 6:
                        entry["required_actions"].append(action_text)
        for attack_class, entry in by_attack.items():
            if _relpath(path) in entry["quality_report_paths"]:
                entry["manifest_errors"] += len(manifest_errors)
                entry["blockers"] += len(manifest_errors)
    for entry in by_attack.values():
        entry["quality_blocked"] = bool(
            entry["sample_count"] > 0 and entry["gap_eligible"] == 0 and entry["blockers"] > 0
        )
        entry["quality_state"] = "quality_blocked" if entry["quality_blocked"] else "gap_eligible_or_mixed"
        if entry["quality_blocked"] and entry["needs_source_state_validation"] > 0:
            entry["quality_blocked_reason"] = "needs_source_state_validation"
        elif (
            entry["quality_blocked"]
            and entry["disqualified_source_state"] > 0
            and entry["needs_source_state_validation"] == 0
        ):
            entry["quality_blocked_reason"] = "disqualified_source_state"
        elif entry["quality_blocked"]:
            entry["quality_blocked_reason"] = "mixed_ineligible"
        else:
            entry["quality_blocked_reason"] = ""
    return by_attack, loaded_paths


def discover_quality_reports(priorities_path: Path, *, auto: bool = True) -> list[Path]:
    if not auto:
        return []
    reports_dir = priorities_path.expanduser().resolve().parent
    return sorted(path for path in reports_dir.glob(DEFAULT_QUALITY_GLOB) if path.is_file())


def _quality_for_candidate_examples(
    quality: dict[str, Any] | None,
    candidate_miss_examples: list[dict[str, Any]],
) -> tuple[dict[str, Any], bool]:
    if not quality:
        return {}, False
    row_quality = dict(quality)
    sample_quality = quality.get("sample_quality") if isinstance(quality.get("sample_quality"), dict) else {}
    matched: list[dict[str, Any]] = []
    for example in candidate_miss_examples:
        sample_key = _sample_quality_key(_string(example.get("slug")))
        sample = sample_quality.get(sample_key)
        if isinstance(sample, dict):
            matched.append(sample)
    if matched:
        row_quality["candidate_sample_quality"] = matched[:8]
    all_visible_examples_quality_blocked = bool(
        candidate_miss_examples
        and len(matched) == len(candidate_miss_examples)
        and all(not bool(sample.get("gap_prioritization_eligible")) for sample in matched)
    )
    if all_visible_examples_quality_blocked:
        row_quality["quality_blocked"] = True
        row_quality["quality_state"] = "quality_blocked"
        states = {_string(sample.get("quality_state")) for sample in matched}
        if "needs_source_state_validation" in states:
            row_quality["quality_blocked_reason"] = "needs_source_state_validation"
        elif "disqualified_source_state" in states:
            row_quality["quality_blocked_reason"] = "disqualified_source_state"
        else:
            row_quality["quality_blocked_reason"] = "mixed_ineligible"
        return row_quality, True
    return row_quality, bool(row_quality.get("quality_blocked"))


def _eligible_quality_replacement_examples(
    quality: dict[str, Any] | None,
    candidate_miss_examples: list[dict[str, Any]],
    *,
    limit: int = 6,
) -> list[dict[str, Any]]:
    if not quality:
        return []
    sample_quality = quality.get("sample_quality") if isinstance(quality.get("sample_quality"), dict) else {}
    if not sample_quality:
        return []
    visible_keys = {
        _sample_quality_key(_string(example.get("slug")))
        for example in candidate_miss_examples
        if _string(example.get("slug"))
    }
    replacements: list[dict[str, Any]] = []
    for sample_key, sample in sorted(sample_quality.items()):
        if sample_key in visible_keys or not isinstance(sample, dict):
            continue
        if not bool(sample.get("gap_prioritization_eligible")):
            continue
        sample_id = _string(sample.get("id"))
        if not sample_id:
            continue
        replacements.append(
            {
                "slug": sample_id,
                "source": _string(sample.get("source")) or _string(sample.get("quality_report_path")),
                "sample_origin": "external_repo",
                "own_detector_fired": False,
                "independent_any_fired": False,
                "independent_firing_detectors": [],
                "source_state": _string(sample.get("source_state")),
                "source_path": _string(sample.get("path")),
                "quality_state": _string(sample.get("quality_state")),
                "quality_report_path": _string(sample.get("quality_report_path")),
            }
        )
        if len(replacements) >= limit:
            break
    return replacements


def _repo_examples(row: dict[str, Any]) -> list[dict[str, Any]]:
    external = row.get("external_evidence") if isinstance(row.get("external_evidence"), dict) else {}
    examples: list[dict[str, Any]] = []
    for item in _bounded_dicts(external.get("repo_examples"), limit=5):
        repo = _string(item.get("repo"))
        if not repo:
            continue
        examples.append({"repo": repo, "samples": _int(item.get("samples"))})
    return examples


def _miss_examples(row: dict[str, Any]) -> list[dict[str, Any]]:
    examples: list[dict[str, Any]] = []
    for item in _bounded_dicts(row.get("miss_examples"), limit=6):
        slug = _string(item.get("slug"))
        if not slug:
            continue
        source = _string(item.get("source"))
        example = {
            "slug": slug,
            "source": source,
            "sample_origin": _string(item.get("sample_origin")),
            "own_detector_fired": bool(item.get("own_detector_fired")),
            "independent_any_fired": bool(item.get("independent_any_fired")),
            "independent_firing_detectors": [
                _string(det)
                for det in (item.get("independent_firing_detectors") or [])
                if _string(det)
            ][:8],
        }
        # Pass through source_state when present; the Lane-2 completeness gate
        # reads it to detect NO_SOURCE_ARTIFACT justifications.
        source_state_raw = _string(item.get("source_state"))
        if source_state_raw:
            example["source_state"] = source_state_raw
        explicit_path = item.get("source_path") or item.get("path")
        source_artifacts = _source_artifacts_for_miss(slug, source, explicit_path)
        if source_artifacts:
            example["source_artifacts"] = source_artifacts
            example["source_path"] = source_artifacts[0]
        examples.append(example)
    return examples


def _top_detectors(row: dict[str, Any]) -> list[dict[str, Any]]:
    detectors: list[dict[str, Any]] = []
    for item in _bounded_dicts(row.get("top_cross_class_detectors_on_misses"), limit=6):
        detector = _string(item.get("detector"))
        if not detector:
            continue
        detectors.append({"detector": detector, "count": _int(item.get("count"))})
    return detectors


def _visible_own_detector_count(examples: list[dict[str, Any]]) -> int:
    return sum(1 for example in examples if bool(example.get("own_detector_fired")))


def _visible_source_artifact_count(examples: list[dict[str, Any]]) -> int:
    count = 0
    for example in examples:
        if _string(example.get("source_path")):
            count += 1
            continue
        artifacts = example.get("source_artifacts")
        if isinstance(artifacts, list) and any(_string(item) for item in artifacts):
            count += 1
    return count


def _collect_source_refs(examples: list[dict[str, Any]]) -> list[str]:
    """Return a stable, de-duplicated list of all source artifact paths present
    across the miss examples. Used to populate the row-level ``source_refs``
    field."""
    refs: list[str] = []
    for example in examples:
        path = _string(example.get("source_path"))
        if path:
            refs.append(path)
            continue
        artifacts = example.get("source_artifacts")
        if isinstance(artifacts, list):
            for item in artifacts:
                text = _string(item)
                if text:
                    refs.append(text)
                    break
    return list(dict.fromkeys(refs))


def _row_source_state(examples: list[dict[str, Any]], quality: dict[str, Any]) -> str:
    """Derive a row-level source_state from example and quality data.

    Priority:
    1. If the quality block carries a per-row ``quality_blocked_reason``
       related to source state, echo the authoritative quality signal.
    2. If every example that carries a ``source_state`` field agrees, return
       that value.
    3. If examples carry mixed or unknown states fall back to
       ``unknown`` so the gate can trigger mine-source.
    """
    quality_reason = _string(quality.get("quality_blocked_reason"))
    if quality_reason == "disqualified_source_state":
        return "disqualified"
    if quality_reason == "needs_source_state_validation":
        return "needs_validation"

    # Derive from sample-level source_state fields when quality is clean.
    sample_states: set[str] = set()
    for example in examples:
        state = _string(example.get("source_state"))
        if state:
            sample_states.add(state)
    if not sample_states:
        return "unknown"
    if len(sample_states) == 1:
        return next(iter(sample_states))
    return "mixed"


def _source_completeness_envelope(
    examples: list[dict[str, Any]],
    quality: dict[str, Any],
    quality_blocked: bool,
) -> dict[str, Any]:
    """Compute the 8 source-completeness fields required by Lane 2.

    The ``provider_allowed`` gate is the critical output: a row may only
    be dispatched to a provider when source artifacts are confirmed present
    OR when an explicit ``NO_SOURCE_ARTIFACT`` justification is recorded
    in at least one example's ``source_state``.

    The rule is intentionally strict: even a single missing artifact across
    the visible miss examples routes the row to ``mine-source`` and sets
    ``provider_allowed=False``.  The ``NO_SOURCE_ARTIFACT`` escape-hatch
    lets operators acknowledge rows where a source artifact genuinely cannot
    exist (e.g. proprietary / redacted code) while still letting the row
    reach a provider.
    """
    source_refs = _collect_source_refs(examples)
    visible_artifact_count = _visible_source_artifact_count(examples)
    total_examples = len(examples)

    # Derive coarse source state for the whole row.
    source_state = _row_source_state(examples, quality)

    # Determine whether every example is covered.
    has_no_source_artifact_justification = any(
        "NO_SOURCE_ARTIFACT" in _string(example.get("source_state")).upper()
        for example in examples
    )
    artifacts_complete = (
        has_no_source_artifact_justification
        or (total_examples > 0 and visible_artifact_count >= total_examples)
    )

    # External recall quality at the row level (mirrors the quality block).
    eq_state = _string(quality.get("quality_state")) or "no_quality_report"

    # Derive action and gate.
    if not examples:
        # No examples at all - cannot assess completeness, block provider.
        next_source_action = "mine-source"
        provider_allowed = False
        provider_block_reason = "no_miss_examples_present"
    elif quality_blocked:
        next_source_action = "mine-source"
        provider_allowed = False
        provider_block_reason = (
            "quality_blocked:" + _string(quality.get("quality_blocked_reason"))
            if quality.get("quality_blocked_reason")
            else "quality_blocked"
        )
    elif not source_refs and not has_no_source_artifact_justification:
        next_source_action = "mine-source"
        provider_allowed = False
        provider_block_reason = "no_source_refs_and_no_justification"
    elif not artifacts_complete:
        next_source_action = "mine-source"
        provider_allowed = False
        provider_block_reason = (
            f"source_artifacts_incomplete:{visible_artifact_count}of{total_examples}"
        )
    else:
        next_source_action = "none"
        provider_allowed = True
        provider_block_reason = ""

    return {
        "source_state": source_state,
        "source_artifacts_complete": artifacts_complete,
        "source_refs": source_refs,
        "quality_state": eq_state,
        "external_recall_quality": quality or {},
        "next_source_action": next_source_action,
        "provider_allowed": provider_allowed,
        "provider_block_reason": provider_block_reason,
    }


def _claimed_own_detector_count(summary: str) -> int:
    match = OWN_DETECTOR_BACKED_RE.search(summary or "")
    if not match:
        return 0
    return _int(match.group(1))


def _external_recall_pct(summary: str) -> float | None:
    match = EXTERNAL_RECALL_PCT_RE.search(summary or "")
    if not match:
        return None
    return _float(match.group(1), default=-1.0)


def _is_recall_saturated(value: float | None) -> bool:
    if value is None:
        return False
    # Inputs from scoreboards have appeared as both fractions (1.0) and
    # percentages (100.0). Treat both representations as saturated.
    if value <= 1.0:
        return value >= 0.995
    return value >= 99.5


def _workability_status(blockers: list[str]) -> str:
    if not blockers:
        return "ready_for_provider_dispatch"
    if "quality_blocked_needs_source_state_validation" in blockers:
        return "needs_source_state_validation"
    if "external_recall_already_saturated" in blockers:
        return "no_recall_lift_available"
    if "external_recall_quality_missing" in blockers:
        return "needs_external_recall_quality"
    if (
        "own_detector_summary_examples_missing" in blockers
        or "own_detector_summary_examples_subset" in blockers
    ):
        return "needs_full_miss_list"
    if (
        "visible_own_detector_evidence_missing" in blockers
        or "candidate_miss_examples_missing" in blockers
        or "candidate_source_artifacts_missing" in blockers
        or "candidate_source_artifacts_partial" in blockers
    ):
        return "needs_candidate_evidence"
    return "provider_dispatch_blocked"


def _assess_workability(
    *,
    task_type: str,
    summary: str,
    source_priority: dict[str, Any],
    candidate_miss_examples: list[dict[str, Any]],
    repo_examples: list[dict[str, Any]],
    quality: dict[str, Any],
    quality_blocked: bool,
) -> dict[str, Any]:
    blockers: list[str] = []
    if quality_blocked:
        blockers.append("quality_blocked_needs_source_state_validation")

    if not candidate_miss_examples and task_type != "source-state-validation":
        blockers.append("candidate_miss_examples_missing")

    visible_source_artifacts = _visible_source_artifact_count(candidate_miss_examples)
    if (
        task_type in SOURCE_ARTIFACT_TASK_TYPES
        and candidate_miss_examples
        and visible_source_artifacts == 0
    ):
        blockers.append("candidate_source_artifacts_missing")
    elif (
        task_type in SOURCE_ARTIFACT_TASK_TYPES
        and candidate_miss_examples
        and visible_source_artifacts < len(candidate_miss_examples)
    ):
        blockers.append("candidate_source_artifacts_partial")

    visible_own = _visible_own_detector_count(candidate_miss_examples)
    claimed_own = _claimed_own_detector_count(summary)

    if task_type in OWN_DETECTOR_EVIDENCE_TASK_TYPES:
        if visible_own == 0:
            blockers.append("visible_own_detector_evidence_missing")
        if claimed_own > 0 and visible_own == 0:
            blockers.append("own_detector_summary_examples_missing")
        elif claimed_own > visible_own:
            blockers.append("own_detector_summary_examples_subset")

    external_pct = _external_recall_pct(summary)
    source_recall = _float(source_priority.get("same_class_recall"), default=-1.0)
    if task_type in EXTERNAL_REPLAY_TASK_TYPES:
        if _is_recall_saturated(external_pct) or _is_recall_saturated(source_recall):
            blockers.append("external_recall_already_saturated")
        if not quality:
            blockers.append("external_recall_quality_missing")
        if not repo_examples:
            blockers.append("repo_examples_missing_for_external_replay")

    # De-duplicate while preserving priority order for stable output.
    blockers = list(dict.fromkeys(blockers))
    status = _workability_status(blockers)
    return {
        "provider_dispatch_ready": not blockers,
        "workability_status": status,
        "workability_blockers": blockers,
        "provider_dispatch_reason": (
            "ready: row has the bounded evidence needed for provider review"
            if not blockers
            else "blocked: " + ", ".join(blockers)
        ),
        "workability_evidence": {
            "visible_candidate_miss_examples": len(candidate_miss_examples),
            "visible_source_artifact_examples": visible_source_artifacts,
            "visible_own_detector_examples": visible_own,
            "claimed_own_detector_backed_misses": claimed_own,
            "external_same_class_recall_pct_from_summary": external_pct,
            "source_same_class_recall": source_recall,
            "repo_examples": len(repo_examples),
            "quality_report_present": bool(quality),
        },
    }


def _suggested_commands(attack_class: str, task_type: str, repo_examples: list[dict[str, Any]]) -> list[str]:
    attack_slug = _safe_slug(attack_class, limit=64)
    commands = [
        "python3 tools/audit/realworld-recall-gap-prioritizer.py --quiet",
        "python3 tools/audit/realworld-recall-scoreboard.py --help",
    ]
    if task_type in {"external-replay", "detector-generalization", "measurement", "mining"}:
        repo_hint = "<external-repo>"
        repo_id = "<repo-id>"
        if repo_examples:
            repo_label = _string(repo_examples[0].get("repo"))
            if repo_label:
                repo_id = repo_label
        commands.append(
            "make external-recall-select "
            f"REPO_ROOT={repo_hint} REPO_ID={repo_id} ATTACK_CLASS={attack_class} "
            f"OUT=reports/external_recall_samples_{attack_slug}.json JSON=1"
        )
    if task_type in {"detector-generalization", "sibling-detector-gap", "new-detector-authoring"}:
        commands.append("make hackerman-sidecar-refresh-check CHECK=1 JSON=1")
    if task_type == "taxonomy-backfill":
        commands.append(
            "python3 tools/audit/realworld-recall-gap-prioritizer.py "
            "--include-uncategorized --quiet"
        )
    if task_type == "source-state-validation":
        commands.append(
            "python3 tools/audit/external-recall-manifest-quality.py "
            "reports/external_recall_samples_<class>.json --out-json reports/external_recall_manifest_quality_<class>.json --warn-only"
        )
    return commands


def _closeout_requirements(task_type: str) -> list[str]:
    base = [
        "Attach changed artifact paths or a deliberate NO_ARTIFACT reason.",
        "Rerun the relevant recall scoreboard/prioritizer and link before/after output.",
        "Do not claim submit-readiness; this queue is capability work only.",
    ]
    by_task = {
        "detector-generalization": [
            "Show the same-class detector now fires on at least one previously missed sample.",
            "Include at least one adjacent negative/control sample or a documented no-control reason.",
        ],
        "external-replay": [
            "Materialize or reference the external recall manifest used for replay.",
            "Report same-class recall before/after for the replayed attack class.",
        ],
        "sibling-detector-gap": [
            "Name the own-detector-backed miss and the sibling detector that failed to generalize.",
            "Close as no-progress if the sibling detector cannot be generalized without false positives.",
        ],
        "new-detector-authoring": [
            "Add fixture-backed detector evidence and a non-matching control.",
            "Do not promote from internal fixtures alone; add or queue external replay evidence.",
        ],
        "measurement": [
            "Record every measured sample in a schema-valid scoreboard sidecar.",
            "Preserve compile/runtime failures instead of dropping them from the denominator.",
        ],
        "mining": [
            "Emit a manifest of candidate samples with source refs and uncertainty.",
            "Do not invent attack classes for ambiguous samples.",
        ],
        "taxonomy-backfill": [
            "Preserve uncertainty when the class cannot be proven from source evidence.",
            "Do not assign a concrete attack class from filename-only evidence.",
        ],
        "source-state-validation": [
            "Replace or annotate unvalidated external rows with vulnerable/pre-fix evidence before detector work.",
            "If every row is fixed/out-of-class, close this as quality-blocked rather than broadening detectors.",
        ],
    }
    return base + by_task.get(task_type, [])


def build_rows(
    payload: dict[str, Any],
    *,
    source_path: Path,
    source_sha256: str,
    top_n: int,
    include_taxonomy: bool,
    quality_by_attack_class: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    generated_at = _utc_now()
    source_report = _relpath(source_path)
    rows: list[dict[str, Any]] = []
    candidates = list(payload.get("priorities") or [])
    if top_n > 0:
        candidates = candidates[:top_n]
    if include_taxonomy:
        candidates.extend(payload.get("taxonomy_debt") or [])

    for priority in candidates:
        if not isinstance(priority, dict):
            continue
        attack_class = _string(priority.get("attack_class")) or "uncategorized"
        taxonomy_debt = attack_class == "uncategorized"
        tasks = priority.get("next_tasks")
        if not isinstance(tasks, list) or not tasks:
            tasks = [{"task_type": "review", "summary": "Review this attack class; no next_tasks were present."}]
        repo_examples = _repo_examples(priority)
        class_quality = (quality_by_attack_class or {}).get(attack_class)
        base_candidate_miss_examples = _miss_examples(priority)
        source_priority = {
            "rank": _int(priority.get("rank")),
            "attack_class": attack_class,
            "priority_band": _string(priority.get("priority_band")),
            "priority_score": _float(priority.get("priority_score")),
            "same_class_recall": _float(priority.get("same_class_recall")),
            "same_class_misses": _int(priority.get("same_class_misses")),
            "gap_vs_any_pp": _float(priority.get("gap_vs_any_pp")),
            "gap_vs_self_test_pp": _float(priority.get("gap_vs_self_test_pp")),
        }
        for task_index, task in enumerate(tasks, 1):
            if not isinstance(task, dict):
                continue
            task_type = _string(task.get("task_type")) or "review"
            summary = _string(task.get("summary"))
            row_candidate_miss_examples = list(base_candidate_miss_examples)
            quality, quality_blocked = _quality_for_candidate_examples(class_quality, row_candidate_miss_examples)
            replacement_examples = _eligible_quality_replacement_examples(quality, row_candidate_miss_examples)
            if quality_blocked and replacement_examples:
                quality = dict(quality or {})
                quality["replacement_candidate_examples"] = replacement_examples
                quality["replaced_blocked_candidate_examples"] = row_candidate_miss_examples
                quality["quality_blocked"] = False
                quality["quality_state"] = "gap_eligible_replacements_available"
                quality["quality_blocked_reason"] = ""
                row_candidate_miss_examples = replacement_examples
                quality_blocked = False
                task_type = "source-state-validation"
                summary = (
                    "Validated vulnerable/pre-fix replacement samples exist; use these replacement rows "
                    "instead of the fixed/out-of-class external rows before detector broadening."
                )
            if quality_blocked and task_type in {"detector-generalization", "external-replay", "sibling-detector-gap"}:
                task_type = "source-state-validation"
                if quality and quality.get("quality_blocked_reason") == "disqualified_source_state":
                    summary = (
                        "External recall rows are fixed or out-of-class; replace them with vulnerable/pre-fix "
                        "source snapshots before detector broadening."
                    )
                else:
                    summary = (
                        "External recall rows are quality-blocked; prove vulnerable/pre-fix source state "
                        "or remove/replace fixed and out-of-class rows before detector broadening."
                    )
            queue_key = "|".join(
                [
                    source_sha256,
                    attack_class,
                    str(priority.get("rank") or ""),
                    str(task_index),
                    task_type,
                    summary,
                ]
            )
            queue_id = f"rwrq-{_safe_slug(attack_class, 36)}-{hashlib.sha1(queue_key.encode()).hexdigest()[:12]}"
            workability = _assess_workability(
                task_type=task_type,
                summary=summary,
                source_priority=source_priority,
                candidate_miss_examples=row_candidate_miss_examples,
                repo_examples=repo_examples,
                quality=quality or {},
                quality_blocked=quality_blocked,
            )
            # Lane 2: compute source-completeness envelope AFTER the quality/
            # workability logic has settled (quality_blocked may have been
            # cleared by replacement substitution above).
            completeness = _source_completeness_envelope(
                examples=row_candidate_miss_examples,
                quality=quality or {},
                quality_blocked=quality_blocked,
            )
            # The envelope owns external_recall_quality; drop the duplicate key
            # that was previously written inline so the field appears once.
            rows.append(
                {
                    "schema": ROW_SCHEMA,
                    "queue_id": queue_id,
                    "status": "quality_blocked" if quality_blocked else "open",
                    "generated_at_utc": generated_at,
                    "source_report": source_report,
                    "source_report_generated_at": _string(payload.get("generated_at")),
                    "source_report_sha256": source_sha256,
                    "submission_posture": "NOT_SUBMIT_READY",
                    "taxonomy_debt": taxonomy_debt,
                    "priority_source": "taxonomy_debt" if taxonomy_debt else "attack_class_priority",
                    "source_priority": source_priority,
                    "work_item": {
                        "task_index": task_index,
                        "task_type": task_type,
                        "summary": summary,
                    },
                    "candidate_miss_examples": row_candidate_miss_examples,
                    "repo_examples": repo_examples,
                    "top_cross_class_detectors_on_misses": _top_detectors(priority),
                    # --- Lane 2: source-completeness envelope (8 fields) ---
                    "source_state": completeness["source_state"],
                    "source_artifacts_complete": completeness["source_artifacts_complete"],
                    "source_refs": completeness["source_refs"],
                    "quality_state": completeness["quality_state"],
                    "external_recall_quality": completeness["external_recall_quality"],
                    "next_source_action": completeness["next_source_action"],
                    "provider_allowed": completeness["provider_allowed"],
                    "provider_block_reason": completeness["provider_block_reason"],
                    # --- workability (existing, kept for backward compat) ---
                    **workability,
                    "suggested_commands": _suggested_commands(attack_class, task_type, repo_examples),
                    "closeout_requirements": _closeout_requirements(task_type),
                }
            )
    rows.sort(
        key=lambda row: (
            1 if row["taxonomy_debt"] else 0,
            row["source_priority"]["rank"] or 10**9,
            row["work_item"]["task_index"],
            row["queue_id"],
        )
    )
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def build_summary(
    *,
    rows: list[dict[str, Any]],
    source_path: Path,
    source_sha256: str,
    out_path: Path,
    dry_run: bool,
    quality_report_paths: list[str] | None = None,
) -> dict[str, Any]:
    by_attack_class = Counter(row["source_priority"]["attack_class"] for row in rows)
    by_task_type = Counter(row["work_item"]["task_type"] for row in rows)
    by_status = Counter(row["status"] for row in rows)
    by_workability_status = Counter(row.get("workability_status", "unknown") for row in rows)
    blocker_counts = Counter(
        blocker
        for row in rows
        for blocker in row.get("workability_blockers", [])
    )
    quality_blocked_rows = sum(1 for row in rows if row.get("status") == "quality_blocked")
    provider_dispatch_ready_rows = sum(1 for row in rows if bool(row.get("provider_dispatch_ready")))
    provider_dispatch_blocked_rows = len(rows) - provider_dispatch_ready_rows
    # Lane 2: count provider_allowed vs provider_blocked at the row level.
    provider_allowed_rows = sum(1 for row in rows if bool(row.get("provider_allowed")))
    provider_blocked_rows = len(rows) - provider_allowed_rows
    by_next_source_action = Counter(
        _string(row.get("next_source_action")) or "unknown" for row in rows
    )
    by_provider_block_reason = Counter(
        _string(row.get("provider_block_reason"))
        for row in rows
        if _string(row.get("provider_block_reason"))
    )
    quality_needs_validation_rows = 0
    quality_disqualified_only_rows = 0
    for row in rows:
        quality = row.get("external_recall_quality") if isinstance(row.get("external_recall_quality"), dict) else {}
        if row.get("status") != "quality_blocked" and not quality.get("quality_blocked"):
            continue
        if quality.get("quality_blocked_reason") == "disqualified_source_state":
            quality_disqualified_only_rows += 1
        elif int(quality.get("needs_source_state_validation") or 0) > 0:
            quality_needs_validation_rows += 1
    return {
        "schema": SUMMARY_SCHEMA,
        "queue_schema": ROW_SCHEMA,
        "generated_at_utc": _utc_now(),
        "source_report": _relpath(source_path),
        "source_report_sha256": source_sha256,
        "output_path": _relpath(out_path),
        "dry_run": dry_run,
        "rows_built": len(rows),
        "rows_written": 0 if dry_run else len(rows),
        "submission_posture": "NOT_SUBMIT_READY",
        "quality_report_paths": sorted(quality_report_paths or []),
        "quality_blocked_rows": quality_blocked_rows,
        "quality_needs_validation_rows": quality_needs_validation_rows,
        "quality_disqualified_only_rows": quality_disqualified_only_rows,
        "provider_dispatch_ready_rows": provider_dispatch_ready_rows,
        "provider_dispatch_blocked_rows": provider_dispatch_blocked_rows,
        # Lane 2: source-completeness gate summary.
        "provider_allowed_rows": provider_allowed_rows,
        "provider_blocked_rows": provider_blocked_rows,
        "by_next_source_action": dict(sorted(by_next_source_action.items())),
        "by_provider_block_reason": dict(sorted(by_provider_block_reason.items())),
        "by_attack_class": dict(sorted(by_attack_class.items())),
        "by_task_type": dict(sorted(by_task_type.items())),
        "by_status": dict(sorted(by_status.items())),
        "by_workability_status": dict(sorted(by_workability_status.items())),
        "workability_blocker_counts": dict(sorted(blocker_counts.items())),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--priorities", default=str(DEFAULT_PRIORITIES))
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--top-n", type=int, default=10)
    ap.add_argument("--include-taxonomy", action="store_true")
    ap.add_argument(
        "--quality-report",
        action="append",
        default=[],
        help=(
            "external-recall-manifest-quality JSON report; may be repeated. "
            "When omitted, reports/<external_recall_manifest_quality*.json> is auto-discovered."
        ),
    )
    ap.add_argument(
        "--no-auto-quality-reports",
        action="store_true",
        help="Disable default auto-discovery of reports/external_recall_manifest_quality*.json.",
    )
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--json-summary", action="store_true")
    args = ap.parse_args(argv)

    priorities_path = Path(args.priorities).expanduser()
    out_path = Path(args.out).expanduser()
    payload, source_sha256 = load_priorities(priorities_path)
    quality_report_paths = [Path(path).expanduser() for path in args.quality_report]
    quality_auto_discovered = False
    if not quality_report_paths and not args.no_auto_quality_reports:
        quality_report_paths = discover_quality_reports(priorities_path, auto=True)
        quality_auto_discovered = bool(quality_report_paths)
    quality_by_attack_class, quality_paths = load_quality_reports(
        quality_report_paths
    )
    rows = build_rows(
        payload,
        source_path=priorities_path,
        source_sha256=source_sha256,
        top_n=max(0, int(args.top_n)),
        include_taxonomy=bool(args.include_taxonomy),
        quality_by_attack_class=quality_by_attack_class,
    )
    if not args.dry_run:
        write_jsonl(out_path, rows)
    summary = build_summary(
        rows=rows,
        source_path=priorities_path,
        source_sha256=source_sha256,
        out_path=out_path,
        dry_run=bool(args.dry_run),
        quality_report_paths=quality_paths,
    )
    summary["quality_report_auto_discovered"] = quality_auto_discovered
    if args.json_summary:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(
            f"[realworld-recall-work-queue] rows_built={summary['rows_built']} "
            f"rows_written={summary['rows_written']} out={summary['output_path']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
