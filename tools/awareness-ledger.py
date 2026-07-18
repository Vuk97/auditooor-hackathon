#!/usr/bin/env python3
"""Manifest-driven semantic awareness ledger.

This module is intentionally independent of workspaces and pipeline stages.
It accepts normalized evidence rows and only emits a terminal awareness state
when the evidence is complete, bound to one audit pin, and semantically
reviewed by a named reviewer.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from typing import Any, Iterable, Mapping


SCHEMA = "auditooor.awareness_ledger.v1"
SOURCE_KINDS = frozenset(
    {
        "prior_audit",
        "commit",
        "pull_request",
        "issue",
        "discussion",
        "review_comment",
        "source_comment",
        "known_issue_list",
    }
)
TERMINAL_STATES = frozenset(
    {"team_aware", "accepted", "deferred", "known_fix", "marked_fixed_live"}
)
LIVE_FIX_MARKERS = frozenset(
    {"bypassable", "incomplete", "reverted", "absent", "live", "not_fixed"}
)
REQUIRED_FINDING_FIELDS = ("root_cause", "affected_path", "required_fix")
OBLIGATION_LOGICAL_FIELDS = (
    "target_unit",
    "asset_invariant",
    "violation_relation",
    "actor_model",
    "impact_class",
)


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _nonempty(value: Any) -> bool:
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return bool(_text(value))


def _pin_of(row: Mapping[str, Any]) -> str:
    binding = row.get("pin_binding", row.get("audit_pin"))
    if isinstance(binding, Mapping):
        return _text(binding.get("pin_id") or binding.get("pin"))
    return _text(binding)


def _source_ids(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if not isinstance(value, Iterable) or isinstance(value, (bytes, dict)):
        return []
    return [_text(item) for item in value if _text(item)]


def _content_sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def normalize_evidence_rows(
    rows: Iterable[Mapping[str, Any]], audit_pin: str
) -> tuple[list[dict[str, Any]], list[str]]:
    """Validate and normalize rows without inferring awareness semantics."""
    normalized: list[dict[str, Any]] = []
    errors: list[str] = []
    seen: set[str] = set()
    pin = _text(audit_pin)
    if not pin:
        errors.append("missing_audit_pin")
    for index, raw in enumerate(rows):
        if not isinstance(raw, Mapping):
            errors.append(f"row_{index}:not_object")
            continue
        row = dict(raw)
        source_id = _text(row.get("source_id"))
        kind = _text(row.get("source_kind"))
        row_pin = _pin_of(row)
        if not source_id:
            errors.append(f"row_{index}:missing_source_id")
        elif source_id in seen:
            errors.append(f"row_{index}:duplicate_source_id:{source_id}")
        else:
            seen.add(source_id)
        if kind not in SOURCE_KINDS:
            errors.append(f"row_{index}:invalid_source_kind:{kind or '<empty>'}")
        if not row_pin or row_pin != pin:
            errors.append(f"row_{index}:pin_mismatch:{source_id or '<empty>'}")
        content = row.get("content")
        if not isinstance(content, str) or not content:
            errors.append(f"row_{index}:missing_content:{source_id or '<empty>'}")
        source_ref = row.get("source_ref")
        if not isinstance(source_ref, str) or not source_ref.strip():
            errors.append(f"row_{index}:missing_source_ref:{source_id or '<empty>'}")
        content_sha256 = row.get("content_sha256")
        if not isinstance(content_sha256, str) or content_sha256 != _content_sha256(content if isinstance(content, str) else ""):
            errors.append(f"row_{index}:content_sha256_mismatch:{source_id or '<empty>'}")
        row["source_id"] = source_id
        row["source_kind"] = kind
        row["pin_binding"] = pin if row_pin == pin else row_pin
        normalized.append(row)
    return normalized, errors


def _coverage(rows: list[Mapping[str, Any]], required: set[str]) -> dict[str, Any]:
    present = {str(row.get("source_kind")) for row in rows}
    missing = sorted(required - present)
    return {
        "required_source_kinds": sorted(required),
        "covered_source_kinds": sorted(present & required),
        "missing_source_kinds": missing,
        "complete": not missing,
    }


def _expected_inventory(
    entries: Any, audit_pin: str
) -> tuple[dict[str, dict[str, str]], list[str]]:
    """Validate the discovered history inventory before semantic review.

    The inventory records what was discovered.  Evidence rows record what a
    reviewer actually read.  Keeping those sets separate makes an omitted
    commit, issue, comment, or audit finding a hard failure instead of letting
    one representative row satisfy an entire source kind.
    """
    if not isinstance(entries, list):
        return {}, ["expected_source_inventory_missing"]
    expected: dict[str, dict[str, str]] = {}
    errors: list[str] = []
    for index, raw in enumerate(entries):
        if not isinstance(raw, Mapping):
            errors.append(f"expected_source_{index}:not_object")
            continue
        source_id = _text(raw.get("source_id"))
        source_kind = _text(raw.get("source_kind"))
        source_ref = _text(raw.get("source_ref"))
        source_pin = _pin_of(raw)
        if not source_id:
            errors.append(f"expected_source_{index}:missing_source_id")
            continue
        if source_id in expected:
            errors.append(f"expected_source_{index}:duplicate_source_id:{source_id}")
            continue
        if source_kind not in SOURCE_KINDS:
            errors.append(f"expected_source_{index}:invalid_source_kind:{source_id}")
        if not source_ref:
            errors.append(f"expected_source_{index}:missing_source_ref:{source_id}")
        if source_pin != audit_pin:
            errors.append(f"expected_source_{index}:pin_mismatch:{source_id}")
        expected[source_id] = {
            "source_kind": source_kind,
            "source_ref": source_ref,
            "pin_binding": source_pin,
        }
    return expected, errors


def _inventory_coverage(
    expected: Mapping[str, Mapping[str, str]], rows: list[Mapping[str, Any]]
) -> dict[str, Any]:
    reviewed = {str(row.get("source_id")): row for row in rows}
    expected_ids = set(expected)
    reviewed_ids = set(reviewed)
    missing = sorted(expected_ids - reviewed_ids)
    unexpected = sorted(reviewed_ids - expected_ids)
    mismatched: list[str] = []
    for source_id in sorted(expected_ids & reviewed_ids):
        row = reviewed[source_id]
        planned = expected[source_id]
        if (
            _text(row.get("source_kind")) != planned["source_kind"]
            or _text(row.get("source_ref")) != planned["source_ref"]
            or _pin_of(row) != planned["pin_binding"]
        ):
            mismatched.append(source_id)
    return {
        "expected_count": len(expected_ids),
        "reviewed_count": len(reviewed_ids),
        "missing_source_ids": missing,
        "unexpected_source_ids": unexpected,
        "mismatched_source_ids": mismatched,
        "complete": not missing and not unexpected and not mismatched,
    }


def _exact_fields(candidate: Mapping[str, Any]) -> bool:
    return all(_nonempty(candidate.get(field)) for field in REQUIRED_FINDING_FIELDS)


def _obligation_logical(candidate: Mapping[str, Any]) -> dict[str, str] | None:
    """Preserve only an explicit reviewer-provided exact obligation binding.

    This module never derives a binding from prose, titles, file-name similarity,
    or a lexical suggestion. A later consumer can use this five-field identity to
    exclude the exact reasoner obligation, while missing bindings remain visible
    for fail-closed handling there.
    """
    raw = candidate.get("obligation_logical")
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        return {}
    logical = {field: _text(raw.get(field)) for field in OBLIGATION_LOGICAL_FIELDS}
    return logical if all(logical.values()) else {}


def _semantic_review(candidate: Mapping[str, Any], source_ids: set[str]) -> tuple[bool, str]:
    review = candidate.get("semantic_review")
    if not isinstance(review, Mapping):
        return False, "missing_semantic_review"
    required = ("reviewer_id", "reviewed_at", "rationale", "method")
    if not all(_nonempty(review.get(key)) for key in required):
        return False, "incomplete_semantic_review"
    reviewed_ids = set(_source_ids(review.get("source_ids")))
    if not reviewed_ids or reviewed_ids != source_ids:
        return False, "semantic_review_source_ids_unbound"
    return True, ""


def _terminal_preflight(
    candidate: Mapping[str, Any], rows: list[Mapping[str, Any]], audit_pin: str
) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if not _exact_fields(candidate):
        reasons.append("missing_exact_finding_fields")
    candidate_pin = _pin_of(candidate)
    if candidate_pin != audit_pin:
        reasons.append("candidate_pin_mismatch")
    ids = set(_source_ids(candidate.get("source_ids")))
    row_ids = {str(row.get("source_id")) for row in rows}
    if not ids:
        reasons.append("missing_source_ids")
    elif not ids <= row_ids:
        reasons.append("source_ids_not_in_manifest")
    reviewed, reason = _semantic_review(candidate, ids)
    if not reviewed:
        reasons.append(reason)
    if not _nonempty(candidate.get("reviewer_rationale")):
        reasons.append("missing_reviewer_rationale")
    if candidate.get("obligation_logical") is not None and not _obligation_logical(candidate):
        reasons.append("invalid_obligation_logical")
    return not reasons, reasons


def classify_candidate(
    candidate: Mapping[str, Any],
    rows: list[Mapping[str, Any]],
    audit_pin: str,
    coverage: Mapping[str, Any],
    rows_by_id: Mapping[str, Mapping[str, Any]],
    manifest_valid: bool,
) -> dict[str, Any]:
    """Return a terminal state only when all fail-closed requirements pass."""
    source_ids = set(_source_ids(candidate.get("source_ids")))
    result: dict[str, Any] = {
        "candidate_id": _text(candidate.get("candidate_id")),
        "state": "unknown",
        "terminal": False,
        "novelty_blocked": True,
        "reasons": [],
    }
    if not manifest_valid:
        result["reasons"].append("invalid_evidence_manifest")
    if not coverage.get("complete"):
        result["reasons"].append("partial_source_coverage")
    _, reasons = _terminal_preflight(candidate, rows, audit_pin)
    result["reasons"].extend(reasons)
    if result["reasons"]:
        return result

    states = {
        _text(rows_by_id.get(source_id, {}).get("awareness_state")).lower()
        for source_id in source_ids
    }
    states.discard("")
    if not states:
        result["reasons"].append("missing_awareness_state")
        return result
    if "marked_fixed" in states or "marked_fixed_but_live" in states:
        live_markers = {
            _text(rows_by_id.get(source_id, {}).get("fix_verification")).lower()
            for source_id in source_ids
        }
        if live_markers & LIVE_FIX_MARKERS:
            state = "marked_fixed_live"
        else:
            state = "known_fix"
    elif len(states) == 1 and next(iter(states)) in TERMINAL_STATES:
        state = next(iter(states))
    elif states <= {"team_aware", "accepted", "deferred", "known_issue"}:
        state = "team_aware"
    else:
        result["reasons"].append("unrecognized_or_conflicting_awareness_state")
        return result
    result.update(
        {
            "state": state,
            "terminal": True,
            "novelty_blocked": state != "marked_fixed_live",
            "source_ids": sorted(source_ids),
            "finding_identity": {field: candidate[field] for field in REQUIRED_FINDING_FIELDS},
        }
    )
    logical = _obligation_logical(candidate)
    if logical:
        result["obligation_logical"] = logical
    return result


def build_ledger(
    manifest: Mapping[str, Any], candidates: Iterable[Mapping[str, Any]] | None = None
) -> dict[str, Any]:
    """Build a deterministic ledger from one explicit manifest object."""
    audit_pin = _text(manifest.get("audit_pin"))
    required = set(manifest.get("required_source_kinds") or SOURCE_KINDS)
    invalid_required = sorted(required - SOURCE_KINDS)
    errors: list[str] = []
    if required != SOURCE_KINDS:
        errors.append("required_source_kinds_incomplete")
    rows, row_errors = normalize_evidence_rows(manifest.get("evidence_rows") or [], audit_pin)
    errors.extend(row_errors)
    expected, inventory_errors = _expected_inventory(manifest.get("expected_sources"), audit_pin)
    errors.extend(inventory_errors)
    if invalid_required:
        errors.append("invalid_required_source_kinds:" + ",".join(invalid_required))
        required -= set(invalid_required)
    coverage = _coverage(rows, required)
    inventory = _inventory_coverage(expected, rows)
    if not inventory["complete"]:
        errors.append("source_inventory_incomplete")
    by_id = {row.get("source_id"): row for row in rows}
    results = [
        classify_candidate(c, rows, audit_pin, coverage, by_id, not errors)
        for c in (candidates or manifest.get("candidates") or [])
    ]
    return {
        "schema": SCHEMA,
        "audit_pin": audit_pin,
        "validation_errors": errors,
        "coverage": coverage,
        "source_inventory": inventory,
        "row_count": len(rows),
        "source_kind_counts": dict(sorted(Counter(row["source_kind"] for row in rows).items())),
        "candidates": results,
        "fail_closed": bool(errors) or not coverage["complete"] or not inventory["complete"],
    }


def validate_ledger(ledger: Mapping[str, Any]) -> list[str]:
    """Validate a persisted ledger without reclassifying its evidence.

    This is intentionally stricter than JSON parsing. The canonical executor uses
    it when admitting the Step 0d artifact, so a hand-written or partial ledger
    cannot receive current-run credit merely because it is valid JSON.
    """
    if not isinstance(ledger, Mapping):
        return ["ledger_not_object"]
    errors: list[str] = []
    if ledger.get("schema") != SCHEMA:
        errors.append("invalid_schema")
    if not _text(ledger.get("audit_pin")):
        errors.append("missing_audit_pin")
    if ledger.get("fail_closed") is not False:
        errors.append("ledger_not_complete")
    validation_errors = ledger.get("validation_errors")
    if not isinstance(validation_errors, list) or validation_errors:
        errors.append("validation_errors_present")
    coverage = ledger.get("coverage")
    if not isinstance(coverage, Mapping) or coverage.get("complete") is not True:
        errors.append("source_coverage_incomplete")
    inventory = ledger.get("source_inventory")
    if not isinstance(inventory, Mapping) or inventory.get("complete") is not True:
        errors.append("source_inventory_incomplete")
    candidates = ledger.get("candidates")
    if not isinstance(candidates, list):
        errors.append("candidates_malformed")
    else:
        for index, candidate in enumerate(candidates):
            prefix = f"candidate_{index}"
            if not isinstance(candidate, Mapping):
                errors.append(f"{prefix}:not_object")
                continue
            if candidate.get("terminal") is not True:
                errors.append(f"{prefix}:not_terminal")
            if _text(candidate.get("state")) not in TERMINAL_STATES:
                errors.append(f"{prefix}:invalid_state")
            if not isinstance(candidate.get("novelty_blocked"), bool):
                errors.append(f"{prefix}:novelty_blocked_malformed")
            if not _source_ids(candidate.get("source_ids")):
                errors.append(f"{prefix}:missing_source_ids")
    return sorted(set(errors))


def suggest_candidates(text: str) -> list[dict[str, str]]:
    """Return lexical suggestions only; these are never classifications."""
    patterns = {
        "team_aware": r"\b(team aware|acknowledged|known issue|risk accepted)\b",
        "deferred": r"\b(todo|deferred|will wire|planned fix|follow[- ]up)\b",
        "marked_fixed": r"\b(fixed|resolved|patched|remediated)\b",
    }
    return [
        {"suggestion": state, "matched_text": re.search(pattern, text, re.I).group(0)}
        for state, pattern in patterns.items()
        if re.search(pattern, text, re.I)
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", help="path to an explicit JSON manifest")
    parser.add_argument("--output", help="optional JSON output path")
    args = parser.parse_args()
    with open(args.manifest, encoding="utf-8") as handle:
        manifest = json.load(handle)
    result = build_ledger(manifest)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(rendered)
    else:
        print(rendered, end="")
    return 1 if result["fail_closed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
