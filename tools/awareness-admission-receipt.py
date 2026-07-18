#!/usr/bin/env python3
"""Validate pin-bound semantic awareness receipts for downstream admission.

The validator is deliberately stdlib-only and treats every malformed or
incomplete receipt as non-admissible.  It validates the contract; it does not
infer semantic decisions from prose or source text.

Usage:
    python3 tools/awareness-admission-receipt.py receipt.json
    python3 tools/awareness-admission-receipt.py receipt.json --json
    python3 tools/awareness-admission-receipt.py receipt.json --require-promotion
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.awareness_admission_receipt.v1"
DISCOVERY_SCHEMA = "auditooor.awareness_source_discovery.v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40,64}$")

SOURCE_TYPES = frozenset(
    {
        "prior_audit",
        "commit_or_diff",
        "pull_request",
        "issue",
        "discussion_or_maintainer_comment",
        "source_comment_or_todo",
        "known_issue_list",
    }
)
CLASSIFICATIONS = frozenset(
    {
        "team_aware",
        "known",
        "accepted",
        "deferred",
        "verified_fixed",
        "fixed_bypass",
        "unknown",
        "incomplete",
    }
)
EXCLUDED = frozenset({"team_aware", "known", "accepted", "deferred"})


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    promotion_allowed: bool
    errors: list[str]
    excluded_decision_ids: list[str]
    closed_decision_ids: list[str]
    bypass_decision_ids: list[str]
    blocked_decision_ids: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {"schema": SCHEMA, **asdict(self)}


def canonical_sha256(value: Any) -> str:
    """Return the digest used for canonical JSON receipt components."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def _text(obj: Any, field: str, errors: list[str]) -> str:
    if not isinstance(obj, str) or not obj.strip():
        errors.append(f"{field}: required non-empty string")
        return ""
    return obj.strip()


def _hash(obj: Any, field: str, errors: list[str]) -> str:
    value = _text(obj, field, errors)
    if value and not SHA256_RE.fullmatch(value):
        errors.append(f"{field}: expected lowercase sha256 hex")
    return value


def _list(obj: Any, field: str, errors: list[str]) -> list[Any]:
    if not isinstance(obj, list):
        errors.append(f"{field}: expected array")
        return []
    return obj


def validate_receipt(receipt: Any, discovery: Any | None = None) -> ValidationResult:
    """Validate the complete receipt and return an admission decision."""
    errors: list[str] = []
    excluded: list[str] = []
    closed: list[str] = []
    bypass: list[str] = []
    blocked: list[str] = []

    if not isinstance(receipt, dict):
        errors.append("receipt: expected object")
        return ValidationResult(False, False, errors, excluded, closed, bypass, blocked)
    if receipt.get("schema") != SCHEMA:
        errors.append(f"schema: expected {SCHEMA}")
    _text(receipt.get("receipt_id"), "receipt_id", errors)

    pin = receipt.get("audit_pin")
    if not isinstance(pin, dict):
        errors.append("audit_pin: expected object")
        pin = {}
    commit = _text(pin.get("commit"), "audit_pin.commit", errors)
    if commit and not COMMIT_RE.fullmatch(commit):
        errors.append("audit_pin.commit: expected immutable 40-64 character hex commit")
    pin_hash = _hash(pin.get("pin_sha256"), "audit_pin.pin_sha256", errors)

    inventory = receipt.get("source_inventory")
    if not isinstance(inventory, dict):
        errors.append("source_inventory: expected object")
        inventory = {}
    if inventory.get("status") != "complete":
        errors.append("source_inventory.status: must be complete")
    if inventory.get("coverage_status") != "complete":
        errors.append("source_inventory.coverage_status: must be complete")
    expected = _list(inventory.get("expected_source_types"), "source_inventory.expected_source_types", errors)
    expected_set = set(expected)
    if not expected_set or expected_set != SOURCE_TYPES:
        errors.append("source_inventory.expected_source_types: must enumerate the canonical source types")
    if any(not isinstance(item, str) or item not in SOURCE_TYPES for item in expected):
        errors.append("source_inventory.expected_source_types: contains unknown source type")
    sources = _list(inventory.get("sources"), "source_inventory.sources", errors)
    source_ids: set[str] = set()
    covered_types: set[str] = set()
    for index, source in enumerate(sources):
        prefix = f"source_inventory.sources[{index}]"
        if not isinstance(source, dict):
            errors.append(f"{prefix}: expected object")
            continue
        source_id = _text(source.get("source_id"), f"{prefix}.source_id", errors)
        if source_id in source_ids:
            errors.append(f"{prefix}.source_id: duplicate stable ID")
        source_ids.add(source_id)
        source_type = _text(source.get("source_type"), f"{prefix}.source_type", errors)
        if source_type not in SOURCE_TYPES:
            errors.append(f"{prefix}.source_type: unknown source type")
        covered_types.add(source_type)
        if source.get("status") != "reviewed":
            errors.append(f"{prefix}.status: must be reviewed")
        awareness = _text(source.get("team_awareness"), f"{prefix}.team_awareness", errors)
        if awareness not in CLASSIFICATIONS:
            errors.append(f"{prefix}.team_awareness: malformed classification")
        _text(source.get("repository"), f"{prefix}.repository", errors)
        # Historical commits, prior audits, and issue discussions commonly predate
        # the audit pin.  The review is bound to the audit pin, while the source
        # itself retains its own immutable historical revision.
        source_commit = _text(source.get("source_commit"), f"{prefix}.source_commit", errors)
        if source_commit and not COMMIT_RE.fullmatch(source_commit):
            errors.append(f"{prefix}.source_commit: expected immutable 40-64 character hex commit")
        _text(source.get("stable_ref"), f"{prefix}.stable_ref", errors)
        _hash(source.get("snapshot_sha256"), f"{prefix}.snapshot_sha256", errors)
        source_pin = _hash(source.get("audit_pin_sha256"), f"{prefix}.audit_pin_sha256", errors)
        if source_pin and source_pin != pin_hash:
            errors.append(f"{prefix}.audit_pin_sha256: differs from audit pin")
        reviewer = source.get("review_receipt")
        if not isinstance(reviewer, dict):
            errors.append(f"{prefix}.review_receipt: expected object")
        else:
            _text(reviewer.get("receipt_id"), f"{prefix}.review_receipt.receipt_id", errors)
            _text(reviewer.get("reviewer"), f"{prefix}.review_receipt.reviewer", errors)
    if covered_types != SOURCE_TYPES:
        errors.append("source_inventory.sources: incomplete canonical source coverage")

    if not isinstance(discovery, dict) or discovery.get("schema") != DISCOVERY_SCHEMA:
        errors.append("source_inventory.discovery: canonical Step 0d discovery is required")
    else:
        discovered_pin = _text(discovery.get("audit_pin"), "discovery.audit_pin", errors)
        if discovered_pin and discovered_pin != commit:
            errors.append("discovery.audit_pin: differs from audit pin")
        discovered_sources = _list(discovery.get("sources"), "discovery.sources", errors)
        discovered_ids: set[str] = set()
        for index, source in enumerate(discovered_sources):
            if not isinstance(source, dict):
                errors.append(f"discovery.sources[{index}]: expected object")
                continue
            source_id = _text(source.get("source_id"), f"discovery.sources[{index}].source_id", errors)
            if source_id in discovered_ids:
                errors.append(f"discovery.sources[{index}].source_id: duplicate stable ID")
            discovered_ids.add(source_id)
        receipt_digest = _hash(inventory.get("discovery_sources_sha256"), "source_inventory.discovery_sources_sha256", errors)
        expected_digest = canonical_sha256(discovered_sources)
        if receipt_digest and receipt_digest != expected_digest:
            errors.append("source_inventory.discovery_sources_sha256: differs from canonical discovery")
        if source_ids != discovered_ids:
            errors.append("source_inventory.sources: must exactly cover canonical discovery source IDs")

    decisions = _list(receipt.get("semantic_decisions"), "semantic_decisions", errors)
    decision_ids: set[str] = set()
    for index, decision in enumerate(decisions):
        prefix = f"semantic_decisions[{index}]"
        if not isinstance(decision, dict):
            errors.append(f"{prefix}: expected object")
            continue
        decision_id = _text(decision.get("decision_id"), f"{prefix}.decision_id", errors)
        if decision_id in decision_ids:
            errors.append(f"{prefix}.decision_id: duplicate stable ID")
        decision_ids.add(decision_id)
        classification = _text(decision.get("classification"), f"{prefix}.classification", errors)
        if classification not in CLASSIFICATIONS:
            errors.append(f"{prefix}.classification: malformed classification")
            blocked.append(decision_id)
        source_refs = _list(decision.get("source_ids"), f"{prefix}.source_ids", errors)
        if not source_refs or any(not isinstance(item, str) or item not in source_ids for item in source_refs):
            errors.append(f"{prefix}.source_ids: must reference reviewed stable source IDs")
        _text(decision.get("rationale"), f"{prefix}.rationale", errors)
        _text(decision.get("root_cause"), f"{prefix}.root_cause", errors)
        _text(
            decision.get("affected_execution_path"),
            f"{prefix}.affected_execution_path",
            errors,
        )
        _text(
            decision.get("required_remediation"),
            f"{prefix}.required_remediation",
            errors,
        )
        evidence = decision.get("evidence")
        if not isinstance(evidence, dict):
            errors.append(f"{prefix}.evidence: expected object")
            evidence = {}
        if classification in EXCLUDED:
            excluded.append(decision_id)
        elif classification == "verified_fixed":
            if evidence.get("fix_verification") != "verified_at_current_pin":
                errors.append(f"{prefix}.evidence.fix_verification: must be verified_at_current_pin")
            fix_source_id = _text(evidence.get("fix_source_id"), f"{prefix}.evidence.fix_source_id", errors)
            if fix_source_id and fix_source_id not in source_ids:
                errors.append(f"{prefix}.evidence.fix_source_id: unknown source ID")
            closed.append(decision_id)
        elif classification == "fixed_bypass":
            if evidence.get("fix_verification") != "bypass_at_current_pin":
                errors.append(f"{prefix}.evidence.fix_verification: must be bypass_at_current_pin")
            _text(evidence.get("exact_source_ref"), f"{prefix}.evidence.exact_source_ref", errors)
            _text(evidence.get("exact_exploit_ref"), f"{prefix}.evidence.exact_exploit_ref", errors)
            bypass.append(decision_id)
        elif classification in {"unknown", "incomplete"}:
            blocked.append(decision_id)
            errors.append(f"{prefix}.classification: {classification} blocks promotion")

    if not decisions:
        errors.append("semantic_decisions: at least one decision is required")
    # Awareness receipts are useful exclusion/closure evidence too, but only
    # an explicitly evidenced current-pin bypass is eligible for promotion.
    promotion_allowed = not errors and not blocked and bool(bypass)
    return ValidationResult(not errors, promotion_allowed, errors, excluded, closed, bypass, blocked)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", type=Path)
    parser.add_argument("--discovery", type=Path, required=True, help="canonical Step 0d awareness discovery JSON")
    parser.add_argument("--json", action="store_true", dest="json_output")
    parser.add_argument(
        "--require-promotion",
        action="store_true",
        help="return nonzero unless the valid receipt authorizes fixed-bypass promotion",
    )
    args = parser.parse_args(argv)
    try:
        payload = json.loads(args.receipt.read_text(encoding="utf-8"))
        discovery = json.loads(args.discovery.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        result = ValidationResult(False, False, [f"input: {exc}"], [], [], [], [])
        if args.json_output:
            print(json.dumps(result.as_dict(), sort_keys=True))
        else:
            print(f"FAIL: {result.errors[0]}")
        return 2
    result = validate_receipt(payload, discovery)
    if args.json_output:
        print(json.dumps(result.as_dict(), sort_keys=True))
    else:
        if result.valid:
            print(
                "PASS: awareness receipt authorizes promotion"
                if result.promotion_allowed
                else "PASS: awareness receipt validated; promotion withheld"
            )
        else:
            print("FAIL: awareness receipt rejected")
        for error in result.errors:
            print(f"- {error}")
    return 0 if result.valid and (result.promotion_allowed or not args.require_promotion) else 1


if __name__ == "__main__":
    raise SystemExit(main())
