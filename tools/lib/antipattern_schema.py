"""Anti-pattern catalog schema + validator (PLAN-P3 prescaffold).

This module is the single source of truth for the v2 anti-pattern record shape
used by `tools/antipattern-catalog-build.py` and consumed (in future P3-MVP-FULL
work) by P5's live-target intelligence reports.

Schema id: `auditooor.antipattern_catalog.v1`

The format is intentionally lossy at the bug-instance level and crisp at the
bug-CLASS level - see `reports/v3_iter_2026-05-23_iter17/plan_swarm_hacker_brain/
PLAN_P3_antipattern_catalog.md` §2 for the design rationale.

Records live on disk as YAML at:
  obsidian-vault/anti-patterns/v2/<language>/<pattern-id>.yaml

This module does NOT pull yaml at import time (yaml is an optional dependency
in the auditooor environment); callers that need YAML loading import yaml
themselves and pass parsed dicts in.
"""
from __future__ import annotations

import re
from typing import Any


SCHEMA_VERSION = "auditooor.antipattern_catalog.v1"

# Allowed enum values. The catalog stays small + crisp on purpose; extending
# these requires a Wave-N migration, not a per-pattern override.
ALLOWED_CATEGORIES = frozenset({
    "access-control",
    "reentrancy",
    "bounds-and-bounds-checks",
    "randomness-and-determinism",
    "authorization",
    "arithmetic-and-precision",
    "external-call-handling",
    "oracle-and-pricing",
    "upgradeability",
    "signature-and-replay",
    "custody-and-accounting",
    "freshness-and-staleness",
    "atomicity-and-ordering",
})

ALLOWED_LANGUAGES = frozenset({
    "solidity",
    "rust",
    "rust-solana-anchor",
    "go",
    "go-cosmos-sdk",
    "move",
    "vyper",
    "cairo",
    "substrate-rust",
    "circom",
    "halo2",
    "any",
})

ALLOWED_SEVERITY_TIERS = frozenset({
    "informational",
    "low",
    "medium",
    "high",
    "critical",
})

ALLOWED_QUERY_TYPES = frozenset({
    "ast",
    "grep",
    "semgrep",
    "slither-detector",
    "tree-sitter",
})

# Severity ordering for floor <= ceiling check.
_SEV_RANK = {tier: rank for rank, tier in enumerate([
    "informational", "low", "medium", "high", "critical"
])}

# pattern_id format: <language-prefix>.<dotted-slug> where slug uses
# kebab-case-with-dashes inside dotted segments. The prescaffold patterns
# all begin with `solidity.` per the §2 spec sample.
_PATTERN_ID_RE = re.compile(
    r"^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+$"
)


# Mandatory top-level keys. Optional keys (e.g. `fp_budget`, `triage_cost`,
# `recall_priority`) are accepted but not required at the pre-scaffold stage;
# they belong to P3-MVP-FULL.
REQUIRED_KEYS = (
    "schema_version",
    "pattern_id",
    "category",
    "language",
    "severity_floor",
    "severity_ceiling",
    "query_type",
    "query_source",
    "description",
    "false_positive_rate_estimate",
    "source_finding_ids",
    "target_invariants",
)


class AntipatternValidationError(ValueError):
    """Raised when an anti-pattern record fails schema validation."""


def validate_record(record: Any) -> dict[str, Any]:
    """Validate a single anti-pattern record and return it unchanged on success.

    Pure function; never touches the filesystem.

    Raises ``AntipatternValidationError`` with a precise message on first
    structural problem. Callers that want multi-error collection should wrap
    repeated calls themselves.
    """
    if not isinstance(record, dict):
        raise AntipatternValidationError(
            f"record must be a dict, got {type(record).__name__}"
        )

    for key in REQUIRED_KEYS:
        if key not in record:
            raise AntipatternValidationError(f"missing required key: {key!r}")

    schema_v = record["schema_version"]
    if schema_v != SCHEMA_VERSION:
        raise AntipatternValidationError(
            f"schema_version must be {SCHEMA_VERSION!r}, got {schema_v!r}"
        )

    pattern_id = record["pattern_id"]
    if not isinstance(pattern_id, str) or not _PATTERN_ID_RE.match(pattern_id):
        raise AntipatternValidationError(
            f"pattern_id must be dotted-lowercase-slug, got {pattern_id!r}"
        )

    category = record["category"]
    if category not in ALLOWED_CATEGORIES:
        raise AntipatternValidationError(
            f"category {category!r} not in {sorted(ALLOWED_CATEGORIES)}"
        )

    language = record["language"]
    if language not in ALLOWED_LANGUAGES:
        raise AntipatternValidationError(
            f"language {language!r} not in {sorted(ALLOWED_LANGUAGES)}"
        )

    floor = record["severity_floor"]
    ceiling = record["severity_ceiling"]
    if floor not in ALLOWED_SEVERITY_TIERS:
        raise AntipatternValidationError(
            f"severity_floor {floor!r} not in {sorted(ALLOWED_SEVERITY_TIERS)}"
        )
    if ceiling not in ALLOWED_SEVERITY_TIERS:
        raise AntipatternValidationError(
            f"severity_ceiling {ceiling!r} not in {sorted(ALLOWED_SEVERITY_TIERS)}"
        )
    if _SEV_RANK[floor] > _SEV_RANK[ceiling]:
        raise AntipatternValidationError(
            f"severity_floor {floor!r} > severity_ceiling {ceiling!r}"
        )

    query_type = record["query_type"]
    if query_type not in ALLOWED_QUERY_TYPES:
        raise AntipatternValidationError(
            f"query_type {query_type!r} not in {sorted(ALLOWED_QUERY_TYPES)}"
        )

    query_source = record["query_source"]
    if not isinstance(query_source, str) or not query_source.strip():
        raise AntipatternValidationError(
            "query_source must be a non-empty string (file:line or inline expression)"
        )

    description = record["description"]
    if not isinstance(description, str) or len(description.strip()) < 16:
        raise AntipatternValidationError(
            "description must be a non-empty string of at least 16 characters"
        )

    fpr = record["false_positive_rate_estimate"]
    if not isinstance(fpr, (int, float)) or isinstance(fpr, bool):
        raise AntipatternValidationError(
            f"false_positive_rate_estimate must be a number in [0, 1], got {fpr!r}"
        )
    if not (0.0 <= float(fpr) <= 1.0):
        raise AntipatternValidationError(
            f"false_positive_rate_estimate must be in [0, 1], got {fpr}"
        )

    source_ids = record["source_finding_ids"]
    if (
        not isinstance(source_ids, list)
        or len(source_ids) < 2
        or not all(isinstance(x, str) and x.strip() for x in source_ids)
    ):
        raise AntipatternValidationError(
            "source_finding_ids must be a list of >=2 non-empty strings (corpus citations)"
        )

    invariants = record["target_invariants"]
    if not isinstance(invariants, list) or not all(
        isinstance(x, str) and x.strip() for x in invariants
    ):
        raise AntipatternValidationError(
            "target_invariants must be a list of non-empty invariant_id strings (may be empty)"
        )

    return record


def is_valid_record(record: Any) -> bool:
    """Boolean shorthand around :func:`validate_record`."""
    try:
        validate_record(record)
    except AntipatternValidationError:
        return False
    return True


def severity_rank(tier: str) -> int:
    """Return the integer ordering used by :func:`validate_record`."""
    if tier not in _SEV_RANK:
        raise AntipatternValidationError(
            f"unknown severity tier {tier!r}; expected one of {sorted(_SEV_RANK)}"
        )
    return _SEV_RANK[tier]
