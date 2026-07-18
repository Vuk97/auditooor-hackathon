#!/usr/bin/env python3
"""Build bounded human-review packets from lesson-source coverage blockers.

The lesson-source inventory identifies sources that may contain useful lessons
but are not allowed to act as hard gates yet. This tool turns those blocker rows
into deterministic review packets. It never promotes a lesson, never edits gate
inputs, and keeps agent artifacts in an advisory review quarantine until a human
re-anchors a candidate to a curated source.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
COMPILER_PATH = Path(__file__).resolve().with_name("prose-to-lesson-compiler.py")
SCHEMA = "auditooor.lesson_promotion_review_queue.v1"
DECISIONS_SCHEMA = "auditooor.lesson_source_decisions.v1"
DEFAULT_INVENTORY = ROOT / ".auditooor" / "lesson_source_inventory.json"
DEFAULT_OUT_JSON = ROOT / ".auditooor" / "lesson_promotion_review_queue.json"
DEFAULT_OUT_MD = ROOT / ".auditooor" / "lesson_promotion_review_queue.md"
DEFAULT_DECISIONS = ROOT / ".auditooor" / "lesson_source_decisions.json"
DEFAULT_LIMIT = 100
MAX_LIMIT = 500
MAX_PROVENANCE = 6
TERMINAL_CASE_STUDY_DECISIONS = {"CURATED_LESSON", "NO_ACTION"}
TERMINAL_AGENT_ARTIFACT_DECISIONS = {"NO_ACTION", "NEEDS_HUMAN_PRIMARY_REVIEW"}
PLACEHOLDER_MARKERS = ("placeholder", "to be filled", "<to fill", "todo", "tbd")
PRIMARY_AGENT_ANCHOR_RE = re.compile(
    r"(^|/)(submissions/|SUBMISSIONS\.md$|poc_execution/|execution_manifest\.json$|"
    r"reference/outcomes\.jsonl$|reference/triager_patterns\.(?:json|md)$|"
    r"proof_artifact|impact[_-]?proof|exploit[_-]?proof)",
    re.IGNORECASE,
)


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected object JSON in {path}")
    return payload


def _load_compiler():
    spec = importlib.util.spec_from_file_location("prose_to_lesson_compiler_for_review_queue", COMPILER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load compiler from {COMPILER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path)


def _resolve_ref(ref: str, root: Path, workspace: Path | None = None) -> Path:
    path = Path(ref).expanduser()
    if path.is_absolute():
        return path
    candidate = root / path
    if candidate.exists() or workspace is None:
        return candidate
    workspace_candidate = workspace / path
    return workspace_candidate


def _safe_text(value: Any, *, max_chars: int = 500) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text[:max_chars]


def _short_hash(*parts: Any) -> str:
    text = "|".join(_safe_text(part, max_chars=800) for part in parts)
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:12]


def _frontmatter(text: str) -> str:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return ""
    for index, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            return "\n".join(lines[1:index])
    return ""


def _frontmatter_value(block: str, key: str) -> str:
    lines = block.splitlines()
    key_prefix = f"{key}:"
    for index, line in enumerate(lines):
        if not line.startswith(key_prefix):
            continue
        raw = line[len(key_prefix) :].strip()
        if raw in {">", "|", ">-", "|-"}:
            parts: list[str] = []
            for next_line in lines[index + 1 :]:
                if next_line and not next_line.startswith((" ", "\t")) and re.match(r"^[A-Za-z0-9_-]+:", next_line):
                    break
                stripped = next_line.strip()
                if stripped:
                    parts.append(stripped)
            return _safe_text(" ".join(parts), max_chars=1200)
        return _safe_text(raw.strip("'\""), max_chars=1200)
    return ""


def _case_study_decision_for_packet(packet: dict[str, Any], root: Path, generated_at: str) -> dict[str, Any] | None:
    if packet.get("source_kind") != "case_study":
        return None
    source_ref = str(packet.get("source_ref") or "")
    path = _resolve_ref(source_ref, root)
    if not path.is_file() or path.suffix.lower() not in {".md", ".markdown"}:
        return None
    try:
        rel = path.resolve().relative_to(root.resolve())
    except ValueError:
        return None
    if not rel.parts or rel.parts[0] != "case_study":
        return None

    text = path.read_text(encoding="utf-8", errors="replace")
    front = _frontmatter(text)
    case_id = _frontmatter_value(front, "case_id")
    lesson = _frontmatter_value(front, "extracted_lesson")
    stop = _frontmatter_value(front, "stop_criterion")
    first_lines = "\n".join(text.splitlines()[:80]).lower()
    has_placeholder = any(marker in first_lines for marker in PLACEHOLDER_MARKERS)

    predicates: list[str] = []
    lessons: list[dict[str, Any]] = []
    warnings: list[str] = []
    try:
        compiler = _load_compiler()
        compiled = compiler.compile_path(path, max_lessons=20, generated_at=generated_at, max_chars_per_source=80_000)
        lessons = [row for row in compiled.get("lessons") or [] if isinstance(row, dict)]
        predicates = sorted({str(row.get("predicate") or "") for row in lessons if row.get("predicate")})
        summary = compiled.get("summary") if isinstance(compiled.get("summary"), dict) else {}
        warnings = [str(item) for item in summary.get("warnings") or []][:8]
    except Exception as exc:  # noqa: BLE001 - a malformed source becomes a no-action decision.
        warnings = [f"compile failed: {exc}"]

    missing_fields = [
        name
        for name, value in (
            ("case_id", case_id),
            ("extracted_lesson", lesson),
            ("stop_criterion", stop),
        )
        if not value
    ]
    promotable = not missing_fields and not has_placeholder
    outcome = "CURATED_LESSON" if promotable else "NO_ACTION"
    reason = (
        "case-study frontmatter has case_id, extracted_lesson, and stop_criterion; recorded as curated lesson decision"
        if promotable
        else "case-study source is not mechanically promotable; recorded as explicit no-action for hard lesson coverage"
    )
    if missing_fields:
        reason += f" (missing: {', '.join(missing_fields)})"
    if has_placeholder:
        reason += " (placeholder markers present)"

    return {
        "schema": DECISIONS_SCHEMA,
        "decision_id": f"LSD-CS-{_short_hash(source_ref, case_id, outcome)}",
        "generated_at_utc": generated_at,
        "source_kind": "case_study",
        "source_ref": source_ref,
        "source_exists": True,
        "packet_id": packet.get("packet_id"),
        "decision_outcome": outcome,
        "terminal_for_source_coverage": outcome in TERMINAL_CASE_STUDY_DECISIONS,
        "review_basis": "repo_case_study_frontmatter",
        "case_id": case_id,
        "curated_lesson": {
            "lesson_statement": lesson if outcome == "CURATED_LESSON" else "",
            "stop_criterion": stop if outcome == "CURATED_LESSON" else "",
            "compiled_predicates": predicates if outcome == "CURATED_LESSON" else [],
            "compiled_predicate_count": len(predicates) if outcome == "CURATED_LESSON" else 0,
            "compiler_lesson_ids": [str(row.get("lesson_id") or "") for row in lessons[:8] if row.get("lesson_id")]
            if outcome == "CURATED_LESSON"
            else [],
        },
        "no_action_reason": "" if outcome == "CURATED_LESSON" else reason,
        "decision_reason": reason,
        "warnings": warnings,
        "offline_only": True,
        "network_access": False,
        "agent_artifact_claim_trusted": False,
        "promotion_authority": False,
        "hard_gate_changes": False,
        "requires_separate_gate_change": True,
        "submit_ready": False,
    }


def _agent_primary_anchor(candidate: dict[str, Any]) -> dict[str, str]:
    if str(candidate.get("evidence_tier") or "") != "primary":
        return {}
    provenance = candidate.get("provenance") if isinstance(candidate.get("provenance"), list) else []
    for item in provenance:
        if not isinstance(item, dict):
            continue
        if str(item.get("source_type") or "") == "agent_outputs_summary":
            continue
        refs = [
            str(item.get("artifact_provenance_ref") or ""),
            str(item.get("path") or ""),
        ]
        for ref in refs:
            if ref and PRIMARY_AGENT_ANCHOR_RE.search(ref):
                return {
                    "source_type": str(item.get("source_type") or ""),
                    "path": str(item.get("path") or ""),
                    "artifact_provenance_ref": str(item.get("artifact_provenance_ref") or ""),
                    "evidence_tier": str(item.get("evidence_tier") or candidate.get("evidence_tier") or ""),
                }
    return {}


def _agent_artifact_decision_for_packet(packet: dict[str, Any], generated_at: str) -> dict[str, Any] | None:
    if packet.get("source_kind") != "agent_artifacts":
        return None
    candidate = packet.get("candidate") if isinstance(packet.get("candidate"), dict) else {}
    candidate_id = str(candidate.get("candidate_id") or "")
    if not candidate_id:
        return None

    anchor = _agent_primary_anchor(candidate)
    if anchor:
        outcome = "NEEDS_HUMAN_PRIMARY_REVIEW"
        reason = (
            "agent-artifact candidate has a local primary-looking proof/outcome anchor; "
            "kept out of hard gates until a human writes a separate curated lesson"
        )
    else:
        outcome = "NO_ACTION"
        reason = (
            "agent-artifact candidate lacks an independently recognized primary exploit/outcome/proof anchor; "
            "agent claims remain secondary evidence and are not promoted"
        )

    return {
        "schema": DECISIONS_SCHEMA,
        "decision_id": f"LSD-AA-{_short_hash(candidate_id, outcome)}",
        "generated_at_utc": generated_at,
        "source_kind": "agent_artifacts",
        "source_ref": candidate_id,
        "source_exists": True,
        "packet_id": packet.get("packet_id"),
        "decision_outcome": outcome,
        "terminal_for_source_coverage": outcome in TERMINAL_AGENT_ARTIFACT_DECISIONS,
        "review_basis": "agent_artifact_candidate_quarantine_review",
        "agent_candidate": {
            "candidate_id": candidate_id,
            "lesson_kind": candidate.get("lesson_kind"),
            "title": candidate.get("title"),
            "evidence_tier": candidate.get("evidence_tier"),
            "confidence": candidate.get("confidence"),
            "source_artifact_types": candidate.get("source_artifact_types") or [],
        },
        "primary_anchor": anchor,
        "needs_human_reason": reason if outcome == "NEEDS_HUMAN_PRIMARY_REVIEW" else "",
        "no_action_reason": reason if outcome == "NO_ACTION" else "",
        "decision_reason": reason,
        "warnings": [],
        "offline_only": True,
        "network_access": False,
        "agent_artifact_claim_trusted": False,
        "promotion_authority": False,
        "hard_gate_changes": False,
        "direct_hard_gate_promotion_allowed": False,
        "requires_separate_gate_change": True,
        "submit_ready": False,
    }


def _bounded_limit(limit: int) -> int:
    return max(0, min(int(limit), MAX_LIMIT))


def _row_key(row: dict[str, Any]) -> tuple[str, str]:
    return (str(row.get("source_kind") or ""), str(row.get("path") or ""))


def _rows_by_blocker_key(rows: Iterable[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        if isinstance(row, dict):
            out[_row_key(row)] = row
    return out


def _base_packet(
    *,
    packet_id: str,
    blocker: dict[str, Any],
    source_row: dict[str, Any],
    source_ref: str,
    review_subject: str,
) -> dict[str, Any]:
    return {
        "packet_id": packet_id,
        "source_kind": blocker.get("source_kind"),
        "source_ref": source_ref,
        "review_subject": _safe_text(review_subject, max_chars=240),
        "coverage_blocker": {
            "code": blocker.get("code"),
            "path": blocker.get("path"),
            "lesson_candidates": blocker.get("lesson_candidates"),
            "admissibility": blocker.get("admissibility"),
            "gate_role": blocker.get("gate_role"),
            "reason": blocker.get("reason"),
        },
        "source_context": {
            "records_seen": source_row.get("records_seen", 0),
            "lesson_candidates": source_row.get("lesson_candidates", blocker.get("lesson_candidates", 0)),
            "compiled_predicates": list(source_row.get("compiled_predicates") or [])[:12],
            "compiled_predicate_count": source_row.get("compiled_predicate_count", 0),
            "compile_truncated": bool(source_row.get("compile_truncated")),
        },
        "review_state": "needs_human_review",
        "advisory_only": True,
        "required_human_review": True,
        "promotion_authority": False,
        "truth_claims_made": False,
        "submit_ready": False,
        "auto_promotion_allowed": False,
        "direct_hard_gate_promotion_allowed": False,
        "required_review_outputs": [
            "curated lesson statement",
            "exact source citation",
            "promotion decision: promote | keep_advisory | reject | needs_source",
            "target enforcement surface if promoted",
        ],
    }


def _case_study_packets(
    blocker: dict[str, Any],
    source_row: dict[str, Any],
    root: Path,
    *,
    start_ordinal: int,
) -> list[dict[str, Any]]:
    refs = list(source_row.get("source_refs") or [])
    source_dir = _resolve_ref(str(blocker.get("path") or source_row.get("path") or "case_study"), root)
    if source_dir.is_dir():
        refs.extend(
            _rel(path, root)
            for path in sorted(source_dir.rglob("*"))
            if path.is_file() and path.suffix.lower() in {".md", ".markdown"}
        )
    if not refs:
        refs = [str(blocker.get("path") or "case_study")]
    refs = list(dict.fromkeys(str(ref) for ref in refs))
    packets: list[dict[str, Any]] = []
    for index, ref in enumerate(refs, start=1):
        packet = _base_packet(
            packet_id=f"LPR-CS-{start_ordinal + index - 1:03d}",
            blocker=blocker,
            source_row=source_row,
            source_ref=ref,
            review_subject=Path(ref).name,
        )
        packet.update(
            {
                "packet_kind": "case_study_lesson_review",
                "candidate_promotion_path": "human may promote only by writing a curated lesson with exact source citation",
                "hard_gate_after_review_possible": True,
                "quarantine_boundary": "candidate_review_until_curated",
                "source_exists": _resolve_ref(ref, root).exists(),
                "suggested_local_review": [
                    f"sed -n '1,220p' {ref}",
                    "extract one bounded lesson statement and cite the exact source lines",
                    "run outcome-lesson-gate tests after any separate curated-gate change",
                ],
            }
        )
        packets.append(packet)
    return packets


def _candidate_reports(source_row: dict[str, Any], root: Path, workspace: Path | None) -> list[Path]:
    paths: list[Path] = []
    for ref in source_row.get("source_refs") or []:
        if str(ref).endswith("agent_artifact_lesson_candidates.json"):
            path = _resolve_ref(str(ref), root, workspace)
            if path.is_file():
                paths.append(path)
    default_paths = [
        root / ".auditooor" / "agent_artifact_lesson_candidates.json",
    ]
    if workspace is not None:
        default_paths.append(workspace / ".auditooor" / "agent_artifact_lesson_candidates.json")
    for path in default_paths:
        if path.is_file():
            paths.append(path)
    seen: set[Path] = set()
    out: list[Path] = []
    for path in paths:
        resolved = path.resolve()
        if resolved not in seen:
            seen.add(resolved)
            out.append(path)
    return out


def _load_agent_candidates(source_row: dict[str, Any], root: Path, workspace: Path | None) -> tuple[list[dict[str, Any]], list[str]]:
    candidates: list[dict[str, Any]] = []
    report_refs: list[str] = []
    for path in _candidate_reports(source_row, root, workspace):
        try:
            payload = _load_json(path)
        except (OSError, json.JSONDecodeError, ValueError):
            continue
        report_refs.append(_rel(path, root))
        rows = payload.get("candidates") or payload.get("lesson_candidates") or []
        if isinstance(rows, list):
            candidates.extend(row for row in rows if isinstance(row, dict))
    return candidates, report_refs


def _agent_artifact_packets(
    blocker: dict[str, Any],
    source_row: dict[str, Any],
    root: Path,
    workspace: Path | None,
    *,
    start_ordinal: int,
) -> list[dict[str, Any]]:
    candidates, report_refs = _load_agent_candidates(source_row, root, workspace)
    packets: list[dict[str, Any]] = []
    if not candidates:
        packet = _base_packet(
            packet_id=f"LPR-AA-{start_ordinal:03d}",
            blocker=blocker,
            source_row=source_row,
            source_ref=str(blocker.get("path") or ".auditooor"),
            review_subject="agent artifact candidate report missing or empty",
        )
        packet.update(
            {
                "packet_kind": "agent_artifact_source_review",
                "candidate_promotion_path": "regenerate agent-artifact-lesson-candidates, then review candidates manually",
                "hard_gate_after_review_possible": False,
                "agent_artifact_direct_hard_gate_promotion_allowed": False,
                "quarantine_boundary": "agent_artifact_review_quarantine",
                "suggested_local_review": ["make agent-artifact-lesson-candidates WS=<workspace> OUT=<path>"],
            }
        )
        return [packet]

    for index, candidate in enumerate(candidates, start=1):
        provenance = candidate.get("provenance") if isinstance(candidate.get("provenance"), list) else []
        source_ref = ""
        if provenance and isinstance(provenance[0], dict):
            source_ref = str(provenance[0].get("path") or "")
        source_ref = source_ref or ",".join(report_refs) or str(blocker.get("path") or ".auditooor")
        packet = _base_packet(
            packet_id=f"LPR-AA-{start_ordinal + index - 1:03d}",
            blocker=blocker,
            source_row=source_row,
            source_ref=source_ref,
            review_subject=candidate.get("title") or candidate.get("candidate_id") or "agent artifact lesson candidate",
        )
        packet.update(
            {
                "packet_kind": "agent_artifact_lesson_candidate_review",
                "candidate": {
                    "candidate_id": candidate.get("candidate_id"),
                    "lesson_kind": candidate.get("lesson_kind"),
                    "title": candidate.get("title"),
                    "lesson_statement": _safe_text(candidate.get("lesson_statement"), max_chars=700),
                    "evidence_tier": candidate.get("evidence_tier"),
                    "confidence": candidate.get("confidence"),
                    "confidence_score": candidate.get("confidence_score"),
                    "source_artifact_types": candidate.get("source_artifact_types") or [],
                    "provenance": provenance[:MAX_PROVENANCE],
                    "candidate_truth_claim": bool(candidate.get("candidate_truth_claim", False)),
                },
                "candidate_report_refs": report_refs,
                "candidate_promotion_path": (
                    "agent artifact remains advisory; human must re-anchor to a curated outcome, "
                    "triager pattern, or reviewed case-study source before any separate hard-gate change"
                ),
                "hard_gate_after_review_possible": False,
                "agent_artifact_direct_hard_gate_promotion_allowed": False,
                "quarantine_boundary": "agent_artifact_review_quarantine",
                "suggested_local_review": [
                    "open the cited provenance and confirm it is not provider-only or stale worker reasoning",
                    "collect primary outcome/source evidence before any separate curated lesson proposal",
                    "keep candidate advisory if primary evidence is absent",
                ],
            }
        )
        packets.append(packet)
    return packets


def _packets_for_blocker(
    blocker: dict[str, Any],
    source_row: dict[str, Any],
    root: Path,
    workspace: Path | None,
    *,
    start_ordinal: int,
) -> list[dict[str, Any]]:
    source_kind = str(blocker.get("source_kind") or "")
    if source_kind == "case_study":
        return _case_study_packets(blocker, source_row, root, start_ordinal=start_ordinal)
    if source_kind == "agent_artifacts":
        return _agent_artifact_packets(blocker, source_row, root, workspace, start_ordinal=start_ordinal)
    packet = _base_packet(
        packet_id=f"LPR-GEN-{start_ordinal:03d}",
        blocker=blocker,
        source_row=source_row,
        source_ref=str(blocker.get("path") or ""),
        review_subject=f"{source_kind} promotion review",
    )
    packet.update(
        {
            "packet_kind": "generic_lesson_source_review",
            "candidate_promotion_path": "human review required before any separate curated-gate change",
            "hard_gate_after_review_possible": False,
            "quarantine_boundary": "unclassified_candidate_review",
            "suggested_local_review": ["inspect source refs and write an explicit promotion/reject decision"],
        }
    )
    return [packet]


def build_queue(
    inventory: dict[str, Any],
    *,
    root: Path,
    inventory_path: Path | None = None,
    limit: int = DEFAULT_LIMIT,
) -> dict[str, Any]:
    root = root.expanduser().resolve()
    workspace_text = str(inventory.get("workspace") or "")
    workspace = Path(workspace_text).expanduser().resolve() if workspace_text else None
    blockers = [row for row in inventory.get("coverage_blockers") or [] if isinstance(row, dict)]
    rows = _rows_by_blocker_key(row for row in inventory.get("rows") or [] if isinstance(row, dict))

    unbounded_packets: list[dict[str, Any]] = []
    for blocker in blockers:
        key = _row_key(blocker)
        source_row = rows.get(key, blocker)
        kind = str(blocker.get("source_kind") or "generic")
        start = len([p for p in unbounded_packets if p.get("source_kind") == kind]) + 1
        packets = _packets_for_blocker(blocker, source_row, root, workspace, start_ordinal=start)
        unbounded_packets.extend(packets)

    bounded_limit = _bounded_limit(limit)
    packets = unbounded_packets[:bounded_limit]
    by_kind = Counter(str(packet.get("source_kind") or "unknown") for packet in packets)
    unbounded_by_kind = Counter(str(packet.get("source_kind") or "unknown") for packet in unbounded_packets)
    blocker_candidates: Counter[str] = Counter()
    for blocker in blockers:
        blocker_candidates[str(blocker.get("source_kind") or "unknown")] += int(blocker.get("lesson_candidates") or 0)
    return {
        "schema": SCHEMA,
        "generated_at_utc": _utc_now(),
        "root": str(root),
        "inventory_path": _rel(inventory_path, root) if inventory_path else "",
        "source_inventory_schema": inventory.get("schema"),
        "offline_only": True,
        "network_access": False,
        "advisory_only": True,
        "promotion_authority": False,
        "truth_claims_made": False,
        "hard_gate_changes": False,
        "agent_artifact_direct_hard_gate_promotion_allowed": False,
        "summary": {
            "coverage_blockers_seen": len(blockers),
            "coverage_blocker_candidates": dict(sorted(blocker_candidates.items())),
            "packets_unbounded": len(unbounded_packets),
            "packets_emitted": len(packets),
            "packet_limit": bounded_limit,
            "bounded": len(unbounded_packets) > len(packets),
            "remaining_unqueued_packets": max(0, len(unbounded_packets) - len(packets)),
            "coverage_blockers_resolved_by_queue": 0,
            "coverage_blockers_remaining": len(blockers),
            "by_source_kind": dict(sorted(by_kind.items())),
            "unbounded_by_source_kind": dict(sorted(unbounded_by_kind.items())),
        },
        "packets": packets,
        "policy": (
            "This queue is a review aid only. It preserves lesson-source blockers until a separate "
            "human-authored promotion edits curated enforcement inputs and passes gate tests. Agent "
            "artifacts may not be promoted directly into hard gates from this queue."
        ),
    }


def build_decisions(queue_payload: dict[str, Any], *, root: Path) -> dict[str, Any]:
    root = root.expanduser().resolve()
    generated_at = str(queue_payload.get("generated_at_utc") or _utc_now())
    decisions: list[dict[str, Any]] = []
    seen_refs: set[str] = set()
    for packet in queue_payload.get("packets") or []:
        if not isinstance(packet, dict):
            continue
        decision = _case_study_decision_for_packet(packet, root, generated_at)
        if decision is None:
            decision = _agent_artifact_decision_for_packet(packet, generated_at)
        if decision is None:
            continue
        source_ref = f"{decision.get('source_kind')}:{decision.get('source_ref')}"
        if source_ref in seen_refs:
            continue
        seen_refs.add(source_ref)
        decisions.append(decision)

    counts = Counter(str(row.get("decision_outcome") or "unknown") for row in decisions)
    return {
        "schema": DECISIONS_SCHEMA,
        "generated_at_utc": generated_at,
        "root": str(root),
        "offline_only": True,
        "network_access": False,
        "agent_artifact_claims_trusted": False,
        "promotion_authority": False,
        "hard_gate_changes": False,
        "summary": {
            "decisions": len(decisions),
            "terminal_case_study_decisions": sum(
                1 for row in decisions if row.get("terminal_for_source_coverage") and row.get("source_kind") == "case_study"
            ),
            "terminal_agent_artifact_decisions": sum(
                1 for row in decisions if row.get("terminal_for_source_coverage") and row.get("source_kind") == "agent_artifacts"
            ),
            "decision_counts": dict(sorted(counts.items())),
        },
        "decisions": decisions,
        "policy": (
            "Case-study decisions may capture reviewed frontmatter; agent-artifact decisions only record "
            "NO_ACTION or NEEDS_HUMAN_PRIMARY_REVIEW dispositions. Agent artifacts remain advisory-only and "
            "cannot directly alter hard gates."
        ),
    }


def _decision_key(row: dict[str, Any]) -> tuple[str, str]:
    return (str(row.get("source_kind") or ""), str(row.get("source_ref") or ""))


def _with_decision_summary(payload: dict[str, Any]) -> dict[str, Any]:
    decisions = [row for row in payload.get("decisions") or [] if isinstance(row, dict)]
    counts = Counter(str(row.get("decision_outcome") or "unknown") for row in decisions)
    payload = dict(payload)
    payload["decisions"] = decisions
    payload["summary"] = {
        "decisions": len(decisions),
        "terminal_case_study_decisions": sum(
            1 for row in decisions if row.get("terminal_for_source_coverage") and row.get("source_kind") == "case_study"
        ),
        "terminal_agent_artifact_decisions": sum(
            1 for row in decisions if row.get("terminal_for_source_coverage") and row.get("source_kind") == "agent_artifacts"
        ),
        "decision_counts": dict(sorted(counts.items())),
    }
    return payload


def merge_decisions(existing_payload: dict[str, Any], new_payload: dict[str, Any]) -> dict[str, Any]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for row in existing_payload.get("decisions") or []:
        if isinstance(row, dict) and all(_decision_key(row)):
            merged[_decision_key(row)] = row
    for row in new_payload.get("decisions") or []:
        if isinstance(row, dict) and all(_decision_key(row)):
            merged[_decision_key(row)] = row
    payload = dict(new_payload)
    payload["decisions"] = sorted(merged.values(), key=lambda row: _decision_key(row))
    return _with_decision_summary(payload)


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# Lesson Promotion Review Queue",
        "",
        "Advisory-only human review packets generated from lesson-source coverage blockers.",
        "",
        f"- coverage blockers: `{summary['coverage_blockers_seen']}`",
        f"- packets emitted: `{summary['packets_emitted']}` of `{summary['packets_unbounded']}`",
        f"- blockers resolved by queue: `{summary['coverage_blockers_resolved_by_queue']}`",
        f"- blockers remaining: `{summary['coverage_blockers_remaining']}`",
        f"- by source kind: `{summary['by_source_kind']}`",
        "",
        "| Packet | Source | Subject | Boundary |",
        "|---|---|---|---|",
    ]
    for packet in payload.get("packets") or []:
        lines.append(
            f"| `{packet['packet_id']}` | `{packet['source_kind']}` | "
            f"{_safe_text(packet.get('review_subject'), max_chars=120)} | "
            f"`{packet.get('quarantine_boundary')}` |"
        )
    lines.append("")
    return "\n".join(lines)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="Repository root.")
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY, help="lesson_source_inventory JSON.")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help=f"Maximum packets to emit (max {MAX_LIMIT}).")
    parser.add_argument("--out-json", type=Path, default=DEFAULT_OUT_JSON)
    parser.add_argument("--out-md", type=Path, default=DEFAULT_OUT_MD)
    parser.add_argument("--out-decisions", type=Path, default=DEFAULT_DECISIONS)
    parser.add_argument("--json", action="store_true", help="Print queue JSON to stdout.")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.root.expanduser().resolve()
    inventory_path = args.inventory.expanduser()
    if not inventory_path.is_file():
        print(f"ERROR: lesson-source inventory not found: {inventory_path}", file=sys.stderr)
        return 2
    inventory = _load_json(inventory_path)
    payload = build_queue(inventory, root=root, inventory_path=inventory_path, limit=args.limit)
    decisions = build_decisions(payload, root=root)
    if args.out_decisions.is_file():
        try:
            decisions = merge_decisions(_load_json(args.out_decisions), decisions)
        except (OSError, json.JSONDecodeError, ValueError):
            pass

    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.out_md.parent.mkdir(parents=True, exist_ok=True)
    args.out_md.write_text(render_markdown(payload), encoding="utf-8")
    args.out_decisions.parent.mkdir(parents=True, exist_ok=True)
    args.out_decisions.write_text(json.dumps(decisions, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        summary = payload["summary"]
        print(
            "lesson-promotion-review-queue: "
            f"{summary['packets_emitted']} packets from {summary['coverage_blockers_seen']} coverage blockers"
        )
        print(f"  json -> {args.out_json}")
        print(f"  md   -> {args.out_md}")
        print(f"  decisions -> {args.out_decisions}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
