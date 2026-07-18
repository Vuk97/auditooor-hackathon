#!/usr/bin/env python3
"""Shared schema for the ``evidence_class`` field on closeout artifacts.

Background
----------
KNOWN_LIMITATIONS item #14: closeout consumers must NEVER treat generated
candidates (Kimi/Minimax LLM outputs, swarm brief candidates, PoC scaffolds
without execution manifests) as proof. This module defines a compact ordered
schema so every artifact (briefs, deep-counterexample queue rows, swarm
candidate plans, source-mining survivor records) can declare what kind of
evidence it represents, and downstream consumers (audit-closeout-check.py,
the evidence-class-validator) can reject anything below
``executed_with_manifest`` from "verified" totals.

Ordering (lowest to highest evidence weight):

1. ``generated_hypothesis``       Raw LLM output / candidate plan / Kimi or
                                  Minimax claim. Has not been turned into a
                                  test or replay yet.
2. ``scaffolded_unverified``      A PoC scaffold or Forge replay file exists
                                  (e.g. produced by ``poc-scaffold.py`` or
                                  ``deep-counterexample-replay-scaffold.py``)
                                  but it has not executed end-to-end with an
                                  execution manifest.
3. ``executed_with_manifest``     A ``poc_execution/**/execution_manifest.json``
                                  exists and records an executed run. It is
                                  not proof by itself; strict proof gates also
                                  require ``final_result=proved``,
                                  ``impact_assertion=exploit_impact``, and a
                                  structured passing command row.
4. ``external_pof_reproduced``    The reported behaviour reproduces an
                                  externally documented PoF (audit report,
                                  bug-bounty disclosure, on-chain incident).
                                  Used when an audit report or a public
                                  exploit transaction is the proof of fact and
                                  the local replay matches it.
5. ``human_verified``             A reviewer (typically Codex / Opus) has
                                  inspected production-path, replay output,
                                  and impact, and signed off the row.

Closeout rule of thumb
----------------------
Counts of ``executed_with_manifest``, ``external_pof_reproduced``, and
``human_verified`` may be reported as "verified". Anything at or below
``scaffolded_unverified`` is queue work, not proof. A missing
``evidence_class`` field is treated as a legacy row and surfaces a WARN, not
a silent demotion.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping


SCHEMA_VERSION = "auditooor.evidence_class.v1"

GENERATED_HYPOTHESIS = "generated_hypothesis"
SCAFFOLDED_UNVERIFIED = "scaffolded_unverified"
EXECUTED_WITH_MANIFEST = "executed_with_manifest"
EXTERNAL_POF_REPRODUCED = "external_pof_reproduced"
HUMAN_VERIFIED = "human_verified"

# Ordered low -> high evidence weight. Index is the rank.
EVIDENCE_CLASSES: tuple[str, ...] = (
    GENERATED_HYPOTHESIS,
    SCAFFOLDED_UNVERIFIED,
    EXECUTED_WITH_MANIFEST,
    EXTERNAL_POF_REPRODUCED,
    HUMAN_VERIFIED,
)

# Anything in this set may be reported as "verified" by the closeout summary.
VERIFIED_CLASSES: frozenset[str] = frozenset({
    EXECUTED_WITH_MANIFEST,
    EXTERNAL_POF_REPRODUCED,
    HUMAN_VERIFIED,
})

# Sentinel for legacy rows that did not carry the field. Closeout consumers
# emit a WARN row when they encounter this; they must not silently bucket it
# as "generated_hypothesis" because that is a real evidence-class value.
MISSING = "missing"

# One-line description used by the validator's per-class report.
DESCRIPTIONS: dict[str, str] = {
    GENERATED_HYPOTHESIS: (
        "Raw LLM/swarm output or candidate plan. No scaffold, no execution."
    ),
    SCAFFOLDED_UNVERIFIED: (
        "PoC/replay scaffold exists but has not run end-to-end."
    ),
    EXECUTED_WITH_MANIFEST: (
        "execution_manifest.json present with real commands and final_result."
    ),
    EXTERNAL_POF_REPRODUCED: (
        "Reproduces a documented external PoF (audit/bounty/on-chain incident)."
    ),
    HUMAN_VERIFIED: (
        "Reviewer signed off on production-path, replay output, and impact."
    ),
    MISSING: "Legacy artifact: no evidence_class field recorded.",
}


def is_known(value: object) -> bool:
    """Return True iff ``value`` is a recognised ``evidence_class`` string."""
    return isinstance(value, str) and value in EVIDENCE_CLASSES


def rank(value: object) -> int:
    """Return the 0-based ordered rank of ``value``.

    Unknown / missing values return ``-1`` so callers can compare against
    ``rank(EXECUTED_WITH_MANIFEST)`` without crashing on legacy rows.
    """
    if isinstance(value, str) and value in EVIDENCE_CLASSES:
        return EVIDENCE_CLASSES.index(value)
    return -1


def is_at_least(value: object, minimum: str) -> bool:
    """Return True iff ``value`` is a known class at or above ``minimum``."""
    if minimum not in EVIDENCE_CLASSES:
        raise ValueError(f"Unknown minimum evidence_class: {minimum!r}")
    r = rank(value)
    return r >= 0 and r >= EVIDENCE_CLASSES.index(minimum)


def is_verified(value: object) -> bool:
    """Return True iff ``value`` is in the verified set."""
    return isinstance(value, str) and value in VERIFIED_CLASSES


def stamp(record: dict[str, Any], default: str = GENERATED_HYPOTHESIS) -> dict[str, Any]:
    """Return ``record`` with ``evidence_class`` set if not already present.

    The function mutates and returns the same dict for chaining. ``default``
    must be a recognised class. Existing values are preserved as-is so the
    helper is safe to call repeatedly during enrichment.
    """
    if default not in EVIDENCE_CLASSES:
        raise ValueError(f"Unknown default evidence_class: {default!r}")
    if not isinstance(record, dict):
        raise TypeError("stamp() expects a dict")
    existing = record.get("evidence_class")
    if not is_known(existing):
        record["evidence_class"] = default
    return record


def empty_counts() -> dict[str, int]:
    """Return a fresh count map keyed by every known class plus ``missing``."""
    counts = {name: 0 for name in EVIDENCE_CLASSES}
    counts[MISSING] = 0
    return counts


def count_records(records: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    """Tally ``evidence_class`` over an iterable of mapping-like records.

    Records without a recognised ``evidence_class`` are counted under
    ``missing``. The return value is mutable so callers can merge multiple
    artifact tallies.
    """
    counts = empty_counts()
    for rec in records:
        if not isinstance(rec, Mapping):
            counts[MISSING] += 1
            continue
        value = rec.get("evidence_class")
        if is_known(value):
            counts[value] += 1
        else:
            counts[MISSING] += 1
    return counts


def merge_counts(*tallies: Mapping[str, int]) -> dict[str, int]:
    """Sum per-class counts across multiple tallies."""
    out = empty_counts()
    for tally in tallies:
        if not isinstance(tally, Mapping):
            continue
        for key, val in tally.items():
            if key in out and isinstance(val, int):
                out[key] += val
    return out


def verified_total(counts: Mapping[str, int]) -> int:
    """Return the sum of counts in ``VERIFIED_CLASSES``."""
    if not isinstance(counts, Mapping):
        return 0
    total = 0
    for name in VERIFIED_CLASSES:
        val = counts.get(name, 0)
        if isinstance(val, int):
            total += val
    return total


def hypothesis_total(counts: Mapping[str, int]) -> int:
    """Return the sum of counts strictly below ``executed_with_manifest``."""
    if not isinstance(counts, Mapping):
        return 0
    total = 0
    for name in (GENERATED_HYPOTHESIS, SCAFFOLDED_UNVERIFIED):
        val = counts.get(name, 0)
        if isinstance(val, int):
            total += val
    return total
