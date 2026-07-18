#!/usr/bin/env python3
"""Normalize wave promotion-candidate artifacts for control-plane consumers.

The source-mining and capability-loop waves have emitted several candidate
shapes over time.  This module accepts those historical envelopes and returns a
single stable row schema so downstream gates can reason over one vocabulary.
Malformed files fail closed by producing blocked error rows instead of aborting
the whole workspace scan.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import re
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "auditooor.control.normalized_candidates.v1"
PROMOTION_CANDIDATE_GLOB = ".auditooor/wave-*/promotion_candidates.json"

_CONTAINER_KEYS = ("candidates", "items", "results", "rows", "survivors")
_GATE_KEYS = (
    "gate",
    "gates",
    "promotion_gate",
    "allocation_gate",
    "equivalent_gate",
    "equivalence_gate",
    "upstream_equivalent_gate",
    "upstream_equivalence_gate",
)


@dataclass(frozen=True)
class NormalizedCandidate:
    """Stable candidate row emitted by the control-plane normalizer."""

    schema: str = SCHEMA
    id: str = "candidate"
    title: str = "Untitled candidate"
    source_file: str = ""
    source_schema: str = ""
    severity: str = ""
    likelihood: str = ""
    impact: str = ""
    status: str = ""
    proof_state: str = ""
    source_paths: list[str] = field(default_factory=list)
    oos_risk: str = ""
    dupe_risk: str = ""
    gate: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_candidate_payload(
    payload: Any,
    *,
    source_file: str | Path = "",
    source_schema: str = "",
) -> list[NormalizedCandidate]:
    """Normalize any supported promotion-candidate payload into stable rows."""

    source = _string(source_file)
    discovered_schema = source_schema or _source_schema(payload)
    rows, errors = _extract_candidate_rows(payload)
    if not rows:
        return [
            _error_candidate(
                source_file=source,
                source_schema=discovered_schema or _shape_name(payload),
                errors=errors or [f"unsupported_candidate_payload:{_shape_name(payload)}"],
            )
        ]

    normalized: list[NormalizedCandidate] = []
    for idx, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            normalized.append(
                _error_candidate(
                    source_file=source,
                    source_schema=discovered_schema,
                    errors=[f"candidate_row_not_object:index={idx}"],
                    index=idx,
                )
            )
            continue
        normalized.append(
            _normalize_one(
                row,
                source_file=source,
                source_schema=_source_schema(row) or discovered_schema,
                index=idx,
            )
        )
    return normalized


def normalize_candidate_file(path: str | Path) -> list[NormalizedCandidate]:
    """Read and normalize one JSON file, returning blocked rows on errors."""

    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        return [
            _error_candidate(
                source_file=str(file_path),
                source_schema="unreadable",
                errors=[f"unreadable_candidate_file:{exc.__class__.__name__}"],
            )
        ]

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        return [
            _error_candidate(
                source_file=str(file_path),
                source_schema="malformed_json",
                errors=[f"invalid_json:{exc.msg}:line={exc.lineno}:col={exc.colno}"],
            )
        ]

    return normalize_candidate_payload(payload, source_file=file_path)


def discover_wave_promotion_candidates(workspace: str | Path) -> list[NormalizedCandidate]:
    """Discover ``.auditooor/wave-*/promotion_candidates.json`` rows."""

    ws = Path(workspace).expanduser()
    rows: list[NormalizedCandidate] = []
    for path in sorted(ws.glob(PROMOTION_CANDIDATE_GLOB)):
        rows.extend(normalize_candidate_file(path))
    return rows


def discover_normalized_candidate_rows(workspace: str | Path) -> list[dict[str, Any]]:
    """Dict-returning convenience wrapper for CLI/report consumers."""

    return [row.to_dict() for row in discover_wave_promotion_candidates(workspace)]


def _normalize_one(
    row: dict[str, Any],
    *,
    source_file: str,
    source_schema: str,
    index: int,
) -> NormalizedCandidate:
    candidate = _candidate_source(row)
    merged = _merge_overlay(candidate, row)
    gate = _gate_payload(row, candidate)

    candidate_id = _first_text(
        merged,
        (
            "id",
            "candidate_id",
            "slug",
            "finding_id",
            "angle_id",
            "name",
        ),
    )
    title = _first_text(
        merged,
        (
            "title",
            "claim",
            "bug_shape",
            "description",
            "summary",
            "finding",
            "name",
            "candidate_id",
            "id",
        ),
    )
    source_paths = _source_paths(row, candidate, merged)
    status = _status(row, candidate, merged, gate)
    proof_state = _proof_state(row, candidate, merged, gate)

    return NormalizedCandidate(
        id=_slug(candidate_id or title or f"candidate-{index}"),
        title=title or candidate_id or "Untitled candidate",
        source_file=source_file,
        source_schema=source_schema or _shape_name(row),
        severity=_severity(merged),
        likelihood=_likelihood(merged),
        impact=_impact(merged),
        status=status,
        proof_state=proof_state,
        source_paths=source_paths,
        oos_risk=_risk(merged, ("oos_risk", "oos", "oos_status", "scope_risk")),
        dupe_risk=_risk(merged, ("dupe_risk", "duplicate_risk", "variant_risk", "dupe")),
        gate=gate,
    )


def _extract_candidate_rows(payload: Any) -> tuple[list[Any], list[str]]:
    if isinstance(payload, list):
        return payload, []
    if not isinstance(payload, dict):
        return [], [f"candidate_payload_not_object_or_list:{_shape_name(payload)}"]

    for key in _CONTAINER_KEYS:
        value = payload.get(key)
        if isinstance(value, list):
            return value, []
        if isinstance(value, dict):
            nested_rows, nested_errors = _extract_candidate_rows(value)
            if nested_rows:
                return nested_rows, nested_errors

    for key in ("data", "payload", "promotion_candidates"):
        value = payload.get(key)
        if isinstance(value, (dict, list)):
            nested_rows, nested_errors = _extract_candidate_rows(value)
            if nested_rows:
                return nested_rows, nested_errors

    if _looks_like_candidate(payload):
        return [payload], []
    return [], ["candidate_container_missing_rows"]


def _looks_like_candidate(row: dict[str, Any]) -> bool:
    candidate_keys = {
        "id",
        "candidate_id",
        "title",
        "claim",
        "bug_shape",
        "finding_id",
        "source_files",
        "files",
        "source_paths",
        "status",
        "promotion_status",
        "severity",
        "impact",
        "candidate",
        "upstream_candidate",
    }
    return any(key in row for key in candidate_keys) or any(key in row for key in _GATE_KEYS)


def _candidate_source(row: dict[str, Any]) -> dict[str, Any]:
    candidate_keys = (
        "candidate",
        "candidate_row",
        "promotion_candidate",
        "upstream_candidate",
        "finding",
        "item",
        "result",
    )
    for key in candidate_keys:
        value = row.get(key)
        if isinstance(value, dict):
            return value
    for key in _GATE_KEYS:
        value = row.get(key)
        if not isinstance(value, dict):
            continue
        for nested_key in candidate_keys:
            nested = value.get(nested_key)
            if isinstance(nested, dict):
                return nested
        if _looks_like_candidate(value):
            return value
    return {}


def _merge_overlay(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in overlay.items():
        if key in {"candidate", "candidate_row", "promotion_candidate", "upstream_candidate"}:
            continue
        if key not in merged or merged.get(key) in (None, "", [], {}):
            merged[key] = value
    return merged


def _gate_payload(*rows: dict[str, Any]) -> dict[str, Any]:
    gate: dict[str, Any] = {}
    for row in rows:
        for key in _GATE_KEYS:
            if key not in row:
                continue
            value = row.get(key)
            if isinstance(value, dict):
                gate[key] = value
            elif isinstance(value, list):
                gate[key] = value
            elif value not in (None, ""):
                gate[key] = _string(value)
    for key in (
        "minimax_classification",
        "minimax_reason",
        "rejection_reason",
        "pending_reason",
        "submission_posture",
        "allocation_status",
    ):
        for row in rows:
            if key in row and row.get(key) not in (None, ""):
                gate.setdefault(key, row.get(key))
                break
    return gate


def _source_paths(*rows: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for row in rows:
        for key in ("source_paths", "source_files", "files", "file_paths", "paths", "sources"):
            paths.extend(_list_strings(row.get(key)))
        cite = row.get("line_cite") or row.get("line_citation") or row.get("source_cite")
        if cite is not None:
            paths.append(_string(cite))
    return _stable_unique(path for path in paths if path)


def _status(
    row: dict[str, Any],
    candidate: dict[str, Any],
    merged: dict[str, Any],
    gate: dict[str, Any],
) -> str:
    value = _first_text(merged, ("status", "promotion_status", "state", "classification"))
    if value:
        return value
    for key in ("rejection_reason", "pending_reason"):
        if _first_text(row, (key,)) or _first_text(candidate, (key,)):
            return "blocked" if key == "rejection_reason" else "pending_review"
    gate_status = _gate_status(gate)
    if gate_status:
        return gate_status
    return "candidate"


def _proof_state(
    row: dict[str, Any],
    candidate: dict[str, Any],
    merged: dict[str, Any],
    gate: dict[str, Any],
) -> str:
    value = _first_text(merged, ("proof_state", "proof_status", "evidence_class"))
    if value:
        return value
    if _first_text(merged, ("poc_result", "result", "final_result", "execution_result")):
        return "executed"
    if _first_text(merged, ("poc_command", "command", "replay_command")):
        return "scaffolded"
    gate_status = _gate_status(gate).lower()
    if gate_status in {"blocked", "rejected", "fail", "failed"}:
        return "blocked"
    if _first_text(row, ("rejection_reason",)) or _first_text(candidate, ("rejection_reason",)):
        return "blocked"
    if _first_text(row, ("pending_reason",)) or _first_text(candidate, ("pending_reason",)):
        return "pending"
    return "planned"


def _severity(row: dict[str, Any]) -> str:
    return _first_text(
        row,
        (
            "severity",
            "severity_lower_bound",
            "severity_claim",
            "risk",
            "risk_level",
        ),
    )


def _likelihood(row: dict[str, Any]) -> str:
    return _first_text(row, ("likelihood", "confidence", "probability"))


def _impact(row: dict[str, Any]) -> str:
    value = _first_text(row, ("impact", "selected_impact", "listed_impact", "impact_summary"))
    if value:
        return value
    impact_contract = row.get("impact_contract")
    if isinstance(impact_contract, dict):
        return _first_text(impact_contract, ("listed_impact", "impact", "selected_impact"))
    return ""


def _risk(row: dict[str, Any], keys: Iterable[str]) -> str:
    for key in keys:
        value = row.get(key)
        if isinstance(value, dict):
            risk = _first_text(
                value,
                ("risk", "status", "level", "verdict", "classification"),
            )
            return risk or json.dumps(value, sort_keys=True)
        if value not in (None, "", [], {}):
            return _string(value)
    return ""


def _gate_status(gate: dict[str, Any]) -> str:
    for value in gate.values():
        if isinstance(value, dict):
            status = _first_text(value, ("status", "state", "verdict", "classification", "result"))
            if status:
                return status
        elif value not in (None, "", [], {}):
            return _string(value)
    return ""


def _source_schema(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    return _first_text(
        payload,
        (
            "schema",
            "schema_version",
            "source_schema",
            "kind",
            "artifact_schema",
        ),
    )


def _error_candidate(
    *,
    source_file: str,
    source_schema: str,
    errors: list[str],
    index: int = 0,
) -> NormalizedCandidate:
    path = Path(source_file) if source_file else None
    if path is None:
        stem = "candidate"
    elif path.parent.name:
        stem = f"{path.parent.name}-{path.stem}"
    else:
        stem = path.stem
    suffix = f"-{index}" if index else ""
    return NormalizedCandidate(
        id=_slug(f"{stem}{suffix}"),
        title=stem or "Malformed candidate file",
        source_file=source_file,
        source_schema=source_schema,
        status="blocked",
        proof_state="blocked",
        gate={"status": "blocked", "errors": list(errors)},
        errors=list(errors),
    )


def _first_text(row: dict[str, Any], keys: Iterable[str]) -> str:
    for key in keys:
        value = row.get(key)
        if value in (None, "", [], {}):
            continue
        return _string(value)
    return ""


def _list_strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [_string(value)]
    if isinstance(value, Iterable):
        return [_string(item) for item in value if _string(item)]
    return [_string(value)]


def _stable_unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value).strip()


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._:-]+", "-", value.strip().lower()).strip("-")
    return slug or "candidate"


def _shape_name(value: Any) -> str:
    if isinstance(value, dict):
        return "dict"
    if isinstance(value, list):
        return "list"
    return type(value).__name__


__all__ = [
    "NormalizedCandidate",
    "PROMOTION_CANDIDATE_GLOB",
    "SCHEMA",
    "discover_normalized_candidate_rows",
    "discover_wave_promotion_candidates",
    "normalize_candidate_file",
    "normalize_candidate_payload",
]
