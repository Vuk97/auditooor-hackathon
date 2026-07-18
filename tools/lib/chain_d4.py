"""Shared Hackerman V3 chain D4 proof predicates.

Only the attacker-control predicate is centralized here. Source anchors,
negative controls, and proof-artifact checks are intentionally left in their
callers because each tool has different local context for those facts.
"""

from __future__ import annotations

import re
from typing import Any


MISSING_ATTACKER_CONTROL_VALUES = {
    "",
    "missing",
    "unknown",
    "none",
    "n/a",
    "na",
    "not_yet_run",
    "pending",
    "todo",
    "not_assessed",
}

GENERIC_ATTACKER_CONTROL_VALUES = {
    "partial",
    "partial-privilege",
    "needs_review_privileged_surface",
}


def has_chain_attacker_control_evidence(value: Any) -> bool:
    """Return true only for explicit, non-generic chain attacker control.

    D4 chain promotion requires evidence that the attacker controls the path
    across all hops. Generic placeholders like ``partial`` or plan-level
    blocker prose are not evidence and must keep the chain blocked.
    """

    text = str(value or "").strip().lower()
    if text in MISSING_ATTACKER_CONTROL_VALUES:
        return False
    if text in GENERIC_ATTACKER_CONTROL_VALUES:
        return False
    if re.match(r"all \d+ plan-level blockers? must be resolved before filing", text):
        return False
    if "partial attacker control" in text:
        return False
    if "missing" in text or "unknown" in text or "needs_review" in text:
        return False
    if "privileged-role-required" in text:
        return False
    if "privilege" in text and "unprivileged" not in text:
        return False
    return True
