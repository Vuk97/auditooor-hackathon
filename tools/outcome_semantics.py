#!/usr/bin/env python3
"""Shared outcome semantics for telemetry and calibration consumers.

Unknown-reason terminal declines are real platform/base-rate rejections, but
they must not teach downstream systems a synthetic rejection class.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Mapping

LEARNING_SCOPE_FULL = "full"
LEARNING_SCOPE_PLATFORM_BASE_RATE_ONLY = "platform_base_rate_only"
MEMORY_ACTION_PLATFORM_BASE_RATE = "platform_base_rate_calibration"
MEMORY_ACTION_SELF_LEARNING = "self_learning_followup"
FOLLOW_UP_CUE_PLATFORM_BASE_RATE = "platform-base-rate:update_terminal_decline_baseline"
FOLLOW_UP_CUE_SELF_LEARNING = "self-learning:review_no_reason_decline_without_causal_label"
UNKNOWN_REASON_DECLINE_CODE = "unknown:no-decline-reason"
UNKNOWN_REASON_DECLINE_REASON = "unknown:no decline reason provided by platform"
UNKNOWN_REASON_DECLINE_REASON_ALIASES = {
    UNKNOWN_REASON_DECLINE_CODE,
    UNKNOWN_REASON_DECLINE_REASON,
    "unknown:no decline reason",
    "unknown:no_reason_decline",
    "unknown:no-reason-decline",
}
UNKNOWN_REASON_STATUS_RE = re.compile(
    r"\b(no|without|unknown|unspecified|not\s+provided|missing)\b.*\b(reason|rationale|explanation)\b"
    r"|\b(reason|rationale|explanation)\b.*\b(no|without|unknown|unspecified|not\s+provided|missing)\b",
    re.I,
)


@dataclass(frozen=True)
class OutcomeSemantics:
    outcome: str
    rejection_reason: str
    learning_scope: str
    memory_action_routes: tuple[str, ...] = ()
    follow_up_cues: tuple[str, ...] = ()

    @property
    def base_rate_only_rejection(self) -> bool:
        return self.learning_scope == LEARNING_SCOPE_PLATFORM_BASE_RATE_ONLY

    @property
    def eligible_for_learning(self) -> bool:
        return self.learning_scope == LEARNING_SCOPE_FULL

    @property
    def unknown_reason_decline(self) -> bool:
        return self.outcome == "rejected" and self.base_rate_only_rejection


def normalize_outcome(raw: str) -> str:
    """Normalize a free-form outcome/status string into a canonical bucket."""
    low = raw.lower()
    tokens = set(re.findall(r"[a-z0-9]+", low.replace("_", " ")))
    if tokens & {"paid", "accepted"}:
        return "accepted"
    if (
        "out of scope" in low
        or "not valid" in low
        or tokens & {"rejected", "invalid", "oos", "declined"}
    ):
        return "rejected"
    if "review" in low:
        return "in_review"
    if tokens & {"valid", "validated", "confirmed"}:
        return "accepted"
    if tokens & {"duplicate", "dupe"}:
        return "duplicate"
    if "withdrawn" in tokens:
        return "withdrawn"
    if tokens & {"pending", "submitted", "triage"}:
        return "pending"
    outcome_class_map = {
        "real": "accepted",
        "dupe": "duplicate",
        "pending": "pending",
    }
    return outcome_class_map.get(low, "unknown")


def normalize_rejection_reason(raw: Any) -> str:
    if raw is None:
        return ""
    return str(raw).strip().lower()


def rejection_reason_is_unknown_no_reason(raw: Any) -> bool:
    reason = normalize_rejection_reason(raw)
    if not reason:
        return False
    return reason in UNKNOWN_REASON_DECLINE_REASON_ALIASES or text_says_unknown_reason(reason)


def text_says_unknown_reason(raw: Any) -> bool:
    """Return true when free text explicitly says no reason exists."""
    if raw is None:
        return False
    text = str(raw).strip()
    if not text:
        return False
    return bool(UNKNOWN_REASON_STATUS_RE.search(text))


def status_says_unknown_reason_decline(raw: Any) -> bool:
    """Return true when one status field is both terminal decline and no-reason."""
    if raw is None:
        return False
    text = str(raw).strip()
    if not text:
        return False
    if normalize_outcome(text) != "rejected":
        return False
    return text_says_unknown_reason(text)


def derive_outcome_semantics(row: Mapping[str, Any]) -> OutcomeSemantics:
    """Return shared calibration semantics for one outcome/telemetry row."""
    outcome_raw = (
        row.get("outcome")
        or row.get("outcome_class")
        or row.get("status")
        or row.get("final_triager_outcome")
        or ""
    )
    outcome = normalize_outcome(str(outcome_raw))
    rejection_reason = normalize_rejection_reason(row.get("rejection_reason"))
    learning_scope = LEARNING_SCOPE_FULL
    explicit_scope = normalize_rejection_reason(row.get("learning_scope"))
    explicit_base_rate_only = bool(row.get("base_rate_only_rejection"))
    blank_reason_with_unknown_status = (
        not rejection_reason
        and (
            any(
                status_says_unknown_reason_decline(row.get(key))
                for key in ("status", "final_triager_outcome", "outcome", "outcome_class")
            )
            or (
                outcome == "rejected"
                and any(
                    text_says_unknown_reason(row.get(key))
                    for key in ("status", "final_triager_outcome", "outcome", "outcome_class")
                )
            )
        )
    )
    if outcome == "rejected" and (
        rejection_reason_is_unknown_no_reason(rejection_reason)
        or explicit_scope == LEARNING_SCOPE_PLATFORM_BASE_RATE_ONLY
        or explicit_base_rate_only
        or blank_reason_with_unknown_status
    ):
        learning_scope = LEARNING_SCOPE_PLATFORM_BASE_RATE_ONLY
    memory_action_routes: tuple[str, ...] = ()
    follow_up_cues: tuple[str, ...] = ()
    if outcome == "rejected" and learning_scope == LEARNING_SCOPE_PLATFORM_BASE_RATE_ONLY:
        memory_action_routes = (
            MEMORY_ACTION_PLATFORM_BASE_RATE,
            MEMORY_ACTION_SELF_LEARNING,
        )
        follow_up_cues = (
            FOLLOW_UP_CUE_PLATFORM_BASE_RATE,
            FOLLOW_UP_CUE_SELF_LEARNING,
        )
    return OutcomeSemantics(
        outcome=outcome,
        rejection_reason=rejection_reason,
        learning_scope=learning_scope,
        memory_action_routes=memory_action_routes,
        follow_up_cues=follow_up_cues,
    )
