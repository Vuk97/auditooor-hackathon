#!/usr/bin/env python3
"""Distill post-filing outcomes into replayable pre-submit gate lessons.

This tool is intentionally standalone and stdlib-only. It reads accepted,
rejected, and disputed outcome records from JSONL/JSON streams, then emits
advisory replay patterns that a static pre-submit gate can later codify.

It does not mutate the outcome ledger. Foreign JSONL rows are reported as
preserved/skipped input so heterogeneous streams can be inspected without
clobbering adjacent telemetry schemas.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "auditooor.post_filing_outcome_replay_pattern_distiller.v1"
SCHEMA_VERSION = "1.0"
TOOL_VERSION = "1.0.0"
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTCOMES = REPO_ROOT / "reference" / "outcomes.jsonl"

TERMINAL_OUTCOMES = {"accepted", "rejected", "disputed"}
OUTCOME_KEYS = (
    "outcome",
    "outcome_class",
    "status",
    "final_triager_outcome",
    "dispute_outcome",
)
IDENTITY_KEYS = (
    "report_id",
    "submission_id",
    "finding_id",
    "draft_id",
    "id",
)
TEXT_KEYS = (
    "title",
    "status",
    "outcome",
    "outcome_class",
    "final_triager_outcome",
    "rejection_reason",
    "triager_comment",
    "platform_comment",
    "operator_note",
    "notes",
    "dispute_reason",
    "dispute_outcome",
    "lesson",
    "learning_note",
    "gate_feedback",
    "static_gate_feedback",
    "pre_submit_gate_result",
    "pre_submit_gate_results",
    "gate_result",
    "gate_results",
    "scope_rationale",
    "severity_reason",
    "production_path_blockers_cleared",
)


@dataclass(frozen=True)
class LoadedRecord:
    row: dict[str, Any]
    source_path: str
    line: int | None
    ordinal: int


@dataclass(frozen=True)
class MalformedRow:
    source_path: str
    line: int | None
    error: str
    raw_preview: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_path": self.source_path,
            "line": self.line,
            "error": self.error,
            "raw_preview": self.raw_preview,
        }


@dataclass(frozen=True)
class ForeignRow:
    source_path: str
    line: int | None
    schema: str
    keys: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_path": self.source_path,
            "line": self.line,
            "schema": self.schema,
            "keys": list(self.keys),
        }


@dataclass(frozen=True)
class Rule:
    gate_id: str
    missed_signal: str
    proposed_check: str
    question: str
    triggering_outcomes: frozenset[str]
    field_regexes: tuple[re.Pattern[str], ...]
    context_regexes: tuple[re.Pattern[str], ...] = ()
    base_score: float = 0.55


@dataclass
class Candidate:
    rule: Rule
    triggering_outcome: str
    row: dict[str, Any]
    source_path: str
    line: int | None
    matched_fields: list[str]


@dataclass
class PatternBucket:
    rule: Rule
    triggering_outcome: str
    candidates: list[Candidate] = field(default_factory=list)


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


RULES: tuple[Rule, ...] = (
    Rule(
        gate_id="pre_submit_duplicate_root_gate",
        missed_signal="duplicate_or_prior_root_not_cleared",
        triggering_outcomes=frozenset({"rejected"}),
        proposed_check=(
            "Hold filing until the candidate has an explicit duplicate-root search "
            "result across prior contest reports, public disclosures, and local "
            "submission history."
        ),
        question=(
            "Before submitting, can we show this is not the same root cause and "
            "impact vector as a prior accepted or pending report?"
        ),
        field_regexes=(
            _rx(r"\b(duplicate|dupe|already\s+(reported|known)|prior\s+(submission|report)|same\s+root)\b"),
        ),
        base_score=0.68,
    ),
    Rule(
        gate_id="pre_submit_scope_oos_gate",
        missed_signal="scope_or_oos_boundary_not_resolved",
        triggering_outcomes=frozenset({"rejected"}),
        proposed_check=(
            "Require a scope verdict with concrete in-scope assets, actors, and "
            "excluded-condition checks before the finding can be filed."
        ),
        question=(
            "Before submitting, which exact in-scope asset or protocol invariant "
            "is affected, and which scope exclusion has been ruled out?"
        ),
        field_regexes=(
            _rx(r"\b(out\s+of\s+scope|oos|not\s+in\s+scope|scope\s+exclusion|excluded\s+by\s+scope)\b"),
            _rx(r"\b(by\s+design|intended\s+behavior|documented\s+mechanics|expected\s+behavior)\b"),
        ),
        base_score=0.66,
    ),
    Rule(
        gate_id="pre_submit_proof_artifact_gate",
        missed_signal="proof_artifact_missing_or_not_reproducible",
        triggering_outcomes=frozenset({"rejected"}),
        proposed_check=(
            "Require a runnable proof artifact or an explicit no-code proof rationale "
            "before filing; rejected reproduction gaps should become hard blockers."
        ),
        question=(
            "Before submitting, can a reviewer reproduce the exploit path from the "
            "attached artifact without filling in missing assumptions?"
        ),
        field_regexes=(
            _rx(r"\b(no|missing|insufficient)\s+(poc|proof|repro|reproduction|artifact)\b"),
            _rx(r"\b(could\s+not\s+reproduce|not\s+reproducible|no\s+runnable|missing\s+proof)\b"),
        ),
        base_score=0.69,
    ),
    Rule(
        gate_id="pre_submit_impact_economics_gate",
        missed_signal="impact_or_economic_viability_not_proven",
        triggering_outcomes=frozenset({"rejected"}),
        proposed_check=(
            "Require concrete loss, profit, or invariant-break accounting before "
            "filing claims that depend on economic viability."
        ),
        question=(
            "Before submitting, what is the attacker-controlled profit or victim "
            "loss after fees, liquidity, gas, and protocol constraints?"
        ),
        field_regexes=(
            _rx(r"\b(no|missing|insufficient)\s+(impact|loss|profit|economic|funds?\s+at\s+risk)\b"),
            _rx(r"\b(not\s+exploitable|cannot\s+exploit|unprofitable|negative\s+ev|gas\s+cost\s+exceeds)\b"),
            _rx(r"\b(dust\s+only|no\s+material\s+loss|bounded\s+impact)\b"),
        ),
        base_score=0.65,
    ),
    Rule(
        gate_id="pre_submit_severity_calibration_gate",
        missed_signal="severity_claim_overstated_or_uncalibrated",
        triggering_outcomes=frozenset({"rejected"}),
        proposed_check=(
            "Require severity to be justified against the program rubric and the "
            "proved impact ceiling before filing High/Critical framing."
        ),
        question=(
            "Before submitting, does the proved impact satisfy the claimed severity "
            "bucket, or should the report be downgraded or held?"
        ),
        field_regexes=(
            _rx(r"\b(severity\s+(overclaim|overstated|too\s+high)|downgraded?|not\s+(high|critical))\b"),
            _rx(r"\b(low|informational|info)\s+(severity|cap|only)\b"),
            _rx(r"\b(does\s+not\s+meet|fails\s+to\s+meet)\s+(high|critical|severity)\b"),
        ),
        base_score=0.62,
    ),
    Rule(
        gate_id="pre_submit_actor_prerequisite_gate",
        missed_signal="trusted_or_privileged_actor_prerequisite",
        triggering_outcomes=frozenset({"rejected"}),
        proposed_check=(
            "Require the exploit actor to be permissionless or explicitly in-scope; "
            "trusted-party setup requirements must block submission-grade framing."
        ),
        question=(
            "Before submitting, can the reported attacker execute the path without "
            "owner, admin, team, governance, multisig, or other trusted-party action?"
        ),
        field_regexes=(
            _rx(r"\b(admin|owner|team|governance|multisig|trusted\s+party|privileged|onlyowner)\b"),
        ),
        context_regexes=(
            _rx(r"\b(required|requires|prerequisite|must|needs|only\s+if|depends\s+on)\b"),
        ),
        base_score=0.6,
    ),
    Rule(
        gate_id="pre_submit_production_path_gate",
        missed_signal="production_reachability_not_demonstrated",
        triggering_outcomes=frozenset({"rejected"}),
        proposed_check=(
            "Require a production reachability path for the affected code and state "
            "before a candidate can leave the draft queue."
        ),
        question=(
            "Before submitting, is the vulnerable path deployed, reachable, and "
            "connected to production assets or protocol accounting?"
        ),
        field_regexes=(
            _rx(r"\b(not\s+deployed|not\s+production|test\s+only|dead\s+code|unreachable|no\s+production\s+path)\b"),
        ),
        base_score=0.63,
    ),
    Rule(
        gate_id="pre_submit_scope_oos_gate",
        missed_signal="accepted_static_gate_false_positive_scope",
        triggering_outcomes=frozenset({"accepted"}),
        proposed_check=(
            "Do not hard-block scope findings when the draft includes concrete "
            "production-path evidence tying the impact to in-scope assets."
        ),
        question=(
            "Before a scope/OOS gate blocks this draft, does the evidence establish "
            "an in-scope production path that the gate is ignoring?"
        ),
        field_regexes=(
            _rx(r"\b(out\s+of\s+scope|oos|scope)\b"),
        ),
        context_regexes=(
            _rx(r"\b(pre[-_\s]?submit|static|gate|check)\b.{0,80}\b(blocked|failed|warned|flagged|held|rejected)\b"),
        ),
        base_score=0.57,
    ),
    Rule(
        gate_id="pre_submit_severity_calibration_gate",
        missed_signal="accepted_static_gate_false_positive_severity",
        triggering_outcomes=frozenset({"accepted"}),
        proposed_check=(
            "Treat accepted outcomes as positive controls for severity gates that "
            "previously blocked or downgraded the same evidence shape."
        ),
        question=(
            "Before blocking on severity, does the draft carry the same rubric and "
            "impact evidence that triage later accepted?"
        ),
        field_regexes=(
            _rx(r"\b(severity|high|critical|medium|low|rubric)\b"),
        ),
        context_regexes=(
            _rx(r"\b(pre[-_\s]?submit|static|gate|check)\b.{0,80}\b(blocked|failed|warned|flagged|downgraded|held)\b"),
        ),
        base_score=0.55,
    ),
    Rule(
        gate_id="pre_submit_static_gate_false_positive_review",
        missed_signal="accepted_static_gate_false_positive_generic",
        triggering_outcomes=frozenset({"accepted"}),
        proposed_check=(
            "Queue accepted findings that were blocked by static gates for operator "
            "review before turning the gate into a hard blocker."
        ),
        question=(
            "Before this static gate blocks future filings, is there an accepted "
            "post-filing outcome showing the gate is overbroad?"
        ),
        field_regexes=(
            _rx(r"\b(pre[-_\s]?submit|static|gate|check)\b.{0,80}\b(blocked|failed|warned|flagged|held|rejected)\b"),
        ),
        base_score=0.5,
    ),
    Rule(
        gate_id="pre_submit_dispute_packet_gate",
        missed_signal="triager_objection_not_prebutted",
        triggering_outcomes=frozenset({"disputed"}),
        proposed_check=(
            "Require a pre-submit objection matrix for findings likely to draw "
            "triager pushback, including scope, duplicate, impact, and proof rebuttals."
        ),
        question=(
            "Before submitting, what triager objection is most likely, and which "
            "evidence would rebut it without relying on post-filing improvisation?"
        ),
        field_regexes=(
            _rx(r"\b(dispute|appeal|contested|challenge|pushback|triager\s+objection)\b"),
        ),
        base_score=0.52,
    ),
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _preview(raw: str, limit: int = 160) -> str:
    text = " ".join(str(raw).split())
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _json_scalar(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool)) or value is None


def _flatten_value(value: Any) -> str:
    if value is None:
        return ""
    if _json_scalar(value):
        return str(value)
    if isinstance(value, list):
        return " ".join(_flatten_value(item) for item in value)
    if isinstance(value, dict):
        return " ".join(f"{key}: {_flatten_value(val)}" for key, val in sorted(value.items()))
    return str(value)


def _text_for_row(row: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in TEXT_KEYS:
        if key in row:
            parts.append(_flatten_value(row.get(key)))
    if not parts:
        parts = [_flatten_value(row)]
    return " ".join(part for part in parts if part)


def _fields_matching(row: dict[str, Any], regexes: Iterable[re.Pattern[str]]) -> list[str]:
    matched: list[str] = []
    for key, value in sorted(row.items()):
        if key not in TEXT_KEYS and key not in OUTCOME_KEYS:
            continue
        text = _flatten_value(value)
        if text and any(rx.search(text) for rx in regexes):
            matched.append(key)
    return matched


def _is_outcome_like(row: dict[str, Any]) -> bool:
    if any(key in row for key in OUTCOME_KEYS):
        return True
    if any(key in row for key in IDENTITY_KEYS) and any(key in row for key in ("title", "severity", "workspace")):
        return True
    return False


def _record_id(row: dict[str, Any], fallback: str) -> str:
    for key in IDENTITY_KEYS:
        value = row.get(key)
        if value not in (None, ""):
            return str(value)
    title = str(row.get("title") or "").strip()
    if title:
        slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
        if slug:
            return slug[:80]
    return fallback


def _workspace_id(row: dict[str, Any]) -> str:
    return str(row.get("workspace") or row.get("engagement") or row.get("contest") or "")


def _latest_key(record: LoadedRecord) -> tuple[str, str]:
    row = record.row
    fallback = f"{record.source_path}:{record.line or record.ordinal}"
    return (_workspace_id(row), _record_id(row, fallback))


def normalize_outcome(row: dict[str, Any]) -> str:
    """Normalize post-filing status into accepted/rejected/disputed/pending/unknown."""
    values = " ".join(str(row.get(key) or "") for key in OUTCOME_KEYS)
    low = values.lower().replace("_", " ")
    tokens = set(re.findall(r"[a-z0-9]+", low))

    if tokens & {"disputed", "dispute", "appeal", "appealed", "contested", "challenge", "challenged"}:
        return "disputed"
    if "duplicate of accepted" in low or "duplicate_of_accepted" in values.lower():
        return "accepted"
    if tokens & {"paid", "accepted", "valid", "validated", "confirmed"}:
        return "accepted"
    if (
        "out of scope" in low
        or "not valid" in low
        or "duplicate" in tokens
        or "dupe" in tokens
        or tokens & {"rejected", "invalid", "oos", "declined", "withdrawn"}
    ):
        return "rejected"
    if "review" in tokens or tokens & {"pending", "submitted", "triage", "unknown"}:
        return "pending"
    if low.strip() == "real":
        return "accepted"
    if low.strip() == "dupe":
        return "rejected"
    return "unknown"


def _read_jsonl(path: Path, ordinal_start: int) -> tuple[list[LoadedRecord], list[ForeignRow], list[MalformedRow], int]:
    records: list[LoadedRecord] = []
    foreign: list[ForeignRow] = []
    malformed: list[MalformedRow] = []
    ordinal = ordinal_start
    source = str(path)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        malformed.append(MalformedRow(source, None, f"read failed: {exc}", ""))
        return records, foreign, malformed, ordinal

    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        ordinal += 1
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError as exc:
            malformed.append(MalformedRow(source, lineno, f"json decode error: {exc.msg}", _preview(stripped)))
            continue
        if not isinstance(obj, dict):
            malformed.append(
                MalformedRow(source, lineno, f"expected JSON object, got {type(obj).__name__}", _preview(stripped))
            )
            continue
        if _is_outcome_like(obj):
            records.append(LoadedRecord(obj, source, lineno, ordinal))
        else:
            foreign.append(ForeignRow(source, lineno, str(obj.get("schema") or "unknown"), tuple(sorted(obj.keys()))))
    return records, foreign, malformed, ordinal


def _rows_from_json_payload(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("rows", "outcomes", "records", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
        return [payload]
    return [payload]


def _read_json(path: Path, ordinal_start: int) -> tuple[list[LoadedRecord], list[ForeignRow], list[MalformedRow], int]:
    records: list[LoadedRecord] = []
    foreign: list[ForeignRow] = []
    malformed: list[MalformedRow] = []
    ordinal = ordinal_start
    source = str(path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except OSError as exc:
        malformed.append(MalformedRow(source, None, f"read failed: {exc}", ""))
        return records, foreign, malformed, ordinal
    except json.JSONDecodeError as exc:
        malformed.append(MalformedRow(source, exc.lineno, f"json decode error: {exc.msg}", ""))
        return records, foreign, malformed, ordinal

    for idx, obj in enumerate(_rows_from_json_payload(payload)):
        ordinal += 1
        line = idx + 1
        if not isinstance(obj, dict):
            malformed.append(
                MalformedRow(source, line, f"expected JSON object, got {type(obj).__name__}", _preview(str(obj)))
            )
            continue
        if _is_outcome_like(obj):
            records.append(LoadedRecord(obj, source, line, ordinal))
        else:
            foreign.append(ForeignRow(source, line, str(obj.get("schema") or "unknown"), tuple(sorted(obj.keys()))))
    return records, foreign, malformed, ordinal


def load_inputs(paths: Iterable[Path]) -> tuple[list[LoadedRecord], list[ForeignRow], list[MalformedRow]]:
    records: list[LoadedRecord] = []
    foreign: list[ForeignRow] = []
    malformed: list[MalformedRow] = []
    ordinal = 0
    for raw_path in paths:
        path = raw_path.expanduser().resolve()
        if path.suffix.lower() == ".jsonl":
            new_records, new_foreign, new_malformed, ordinal = _read_jsonl(path, ordinal)
        else:
            new_records, new_foreign, new_malformed, ordinal = _read_json(path, ordinal)
        records.extend(new_records)
        foreign.extend(new_foreign)
        malformed.extend(new_malformed)
    return records, foreign, malformed


def latest_terminal_records(records: Iterable[LoadedRecord]) -> tuple[list[LoadedRecord], dict[str, int]]:
    latest: dict[tuple[str, str], LoadedRecord] = {}
    outcome_counts: dict[str, int] = {}
    for record in records:
        outcome = normalize_outcome(record.row)
        outcome_counts[outcome] = outcome_counts.get(outcome, 0) + 1
        key = _latest_key(record)
        prior = latest.get(key)
        if prior is None or record.ordinal >= prior.ordinal:
            latest[key] = record
    terminal = [record for record in latest.values() if normalize_outcome(record.row) in TERMINAL_OUTCOMES]
    terminal.sort(key=lambda rec: (rec.source_path, rec.line or 0, rec.ordinal))
    return terminal, outcome_counts


def _rule_matches(rule: Rule, row: dict[str, Any]) -> tuple[bool, list[str]]:
    text = _text_for_row(row)
    if not any(rx.search(text) for rx in rule.field_regexes):
        return False, []
    if rule.context_regexes and not any(rx.search(text) for rx in rule.context_regexes):
        return False, []
    matched_fields = _fields_matching(row, rule.field_regexes + rule.context_regexes)
    return True, matched_fields


def build_candidates(records: Iterable[LoadedRecord]) -> list[Candidate]:
    candidates: list[Candidate] = []
    for record in records:
        outcome = normalize_outcome(record.row)
        for rule in RULES:
            if outcome not in rule.triggering_outcomes:
                continue
            matched, matched_fields = _rule_matches(rule, record.row)
            if matched:
                candidates.append(
                    Candidate(
                        rule=rule,
                        triggering_outcome=outcome,
                        row=record.row,
                        source_path=record.source_path,
                        line=record.line,
                        matched_fields=matched_fields,
                    )
                )
    return candidates


def _evidence_ref(candidate: Candidate) -> dict[str, Any]:
    row = candidate.row
    fallback = f"{candidate.source_path}:{candidate.line or '?'}"
    ref: dict[str, Any] = {
        "source_path": candidate.source_path,
        "line": candidate.line,
        "record_id": _record_id(row, fallback),
        "workspace": _workspace_id(row),
        "title": str(row.get("title") or ""),
        "outcome": normalize_outcome(row),
        "matched_fields": sorted(set(candidate.matched_fields)),
    }
    if row.get("outcome_evidence_path"):
        ref["outcome_evidence_path"] = str(row.get("outcome_evidence_path"))
    if "new_rule_codified" in row:
        ref["new_rule_codified"] = bool(row.get("new_rule_codified") is True)
    return ref


def _confidence_label(score: float) -> str:
    if score >= 0.76:
        return "high"
    if score >= 0.55:
        return "medium"
    return "low"


def _score(rule: Rule, evidence_refs: list[dict[str, Any]]) -> float:
    score = rule.base_score
    support = len(evidence_refs)
    score += min(0.16, max(0, support - 1) * 0.05)
    explicit_fields = {
        field
        for ref in evidence_refs
        for field in ref.get("matched_fields", [])
    }
    if explicit_fields & {"rejection_reason", "triager_comment", "platform_comment", "final_triager_outcome"}:
        score += 0.06
    if explicit_fields & {"static_gate_feedback", "gate_feedback", "pre_submit_gate_result", "pre_submit_gate_results"}:
        score += 0.05
    return round(min(score, 0.91), 2)


def _codification_recommendation(evidence_refs: list[dict[str, Any]]) -> dict[str, Any]:
    codified = sum(1 for ref in evidence_refs if ref.get("new_rule_codified") is True)
    support = len(evidence_refs)
    if support and codified == support:
        return {
            "recommended": False,
            "state": "already_codified",
            "reason": "Every supporting outcome row already carries new_rule_codified=true.",
        }
    if codified:
        return {
            "recommended": True,
            "state": "review_existing_rule",
            "reason": "Some supporting rows are already codified; review whether the static gate covers the remaining evidence.",
        }
    return {
        "recommended": True,
        "state": "needs_codification",
        "reason": "Supporting outcomes expose a replayable pre-submit lesson that is not marked codified in the ledger.",
    }


def distill_patterns(candidates: Iterable[Candidate]) -> list[dict[str, Any]]:
    buckets: dict[tuple[str, str, str], PatternBucket] = {}
    seen_evidence: dict[tuple[str, str, str], set[tuple[str, str, str, int | None]]] = {}
    for candidate in candidates:
        key = (
            candidate.rule.gate_id,
            candidate.rule.missed_signal,
            candidate.triggering_outcome,
        )
        bucket = buckets.setdefault(
            key,
            PatternBucket(rule=candidate.rule, triggering_outcome=candidate.triggering_outcome),
        )
        record_id = _record_id(candidate.row, f"{candidate.source_path}:{candidate.line or '?'}")
        evidence_key = (candidate.source_path, _workspace_id(candidate.row), record_id, candidate.line)
        bucket_seen = seen_evidence.setdefault(key, set())
        if evidence_key in bucket_seen:
            continue
        bucket_seen.add(evidence_key)
        bucket.candidates.append(candidate)

    patterns: list[dict[str, Any]] = []
    for key, bucket in buckets.items():
        evidence_refs = [_evidence_ref(candidate) for candidate in bucket.candidates]
        evidence_refs.sort(
            key=lambda ref: (
                ref.get("workspace") or "",
                ref.get("record_id") or "",
                ref.get("source_path") or "",
                ref.get("line") or 0,
            )
        )
        score = _score(bucket.rule, evidence_refs)
        patterns.append(
            {
                "gate_id": bucket.rule.gate_id,
                "proposed_check": bucket.rule.proposed_check,
                "triggering_outcome": bucket.triggering_outcome,
                "missed_signal": bucket.rule.missed_signal,
                "counterfactual_pre_submit_question": bucket.rule.question,
                "confidence": _confidence_label(score),
                "confidence_score": score,
                "support_count": len(evidence_refs),
                "evidence_refs": evidence_refs,
                "new_rule_codified": _codification_recommendation(evidence_refs),
                "advisory_only": True,
            }
        )

    patterns.sort(
        key=lambda row: (
            -float(row["confidence_score"]),
            row["gate_id"],
            row["missed_signal"],
            row["triggering_outcome"],
        )
    )
    return patterns


def _excluded_terminal_rows(records: Iterable[LoadedRecord], candidates: Iterable[Candidate]) -> list[dict[str, Any]]:
    covered = {
        (_workspace_id(c.row), _record_id(c.row, f"{c.source_path}:{c.line or '?'}"))
        for c in candidates
    }
    excluded: list[dict[str, Any]] = []
    for record in records:
        row = record.row
        key = (_workspace_id(row), _record_id(row, f"{record.source_path}:{record.line or '?'}"))
        if key in covered:
            continue
        outcome = normalize_outcome(row)
        reason = "no_explicit_replay_signal"
        if outcome == "rejected" and not str(row.get("rejection_reason") or "").strip():
            reason = "terminal_rejection_without_causal_reason"
        excluded.append(
            {
                "source_path": record.source_path,
                "line": record.line,
                "record_id": key[1],
                "workspace": key[0],
                "outcome": outcome,
                "reason": reason,
            }
        )
    excluded.sort(key=lambda row: (row["source_path"], row["line"] or 0, row["record_id"]))
    return excluded


def build_report(
    paths: list[Path],
    *,
    generated_at: str | None = None,
    include_foreign_rows: bool = False,
) -> dict[str, Any]:
    records, foreign, malformed = load_inputs(paths)
    terminal_records, raw_outcome_counts = latest_terminal_records(records)
    candidates = build_candidates(terminal_records)
    patterns = distill_patterns(candidates)
    excluded = _excluded_terminal_rows(terminal_records, candidates)

    latest_outcome_counts: dict[str, int] = {}
    for record in terminal_records:
        outcome = normalize_outcome(record.row)
        latest_outcome_counts[outcome] = latest_outcome_counts.get(outcome, 0) + 1

    report: dict[str, Any] = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "tool_version": TOOL_VERSION,
        "generated_at": generated_at or _utc_now(),
        "input_summary": {
            "paths": [str(path.expanduser().resolve()) for path in paths],
            "rows_loaded": len(records),
            "foreign_rows_preserved": len(foreign),
            "malformed_rows": len(malformed),
            "latest_terminal_rows": len(terminal_records),
            "candidate_signals": len(candidates),
            "patterns_emitted": len(patterns),
            "raw_outcome_distribution": dict(sorted(raw_outcome_counts.items())),
            "latest_terminal_distribution": dict(sorted(latest_outcome_counts.items())),
        },
        "patterns": patterns,
        "excluded_terminal_rows": excluded,
        "malformed_rows": [row.as_dict() for row in malformed],
        "foreign_rows_preserved": [row.as_dict() for row in foreign] if include_foreign_rows else [],
        "limitations": [
            "Advisory only: this tool recommends static-gate lessons but never mutates gates or ledgers.",
            "Causal lessons are emitted only when terminal rows contain explicit rejection, dispute, or gate-feedback signals.",
            "Unknown-reason terminal declines are counted but excluded from causal pattern learning.",
        ],
    }
    return report


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Distill post-filing outcomes into replayable pre-submit gate lessons."
    )
    parser.add_argument(
        "--outcomes",
        type=Path,
        action="append",
        default=None,
        help=f"Outcome JSONL/JSON path. Repeatable. Default: {DEFAULT_OUTCOMES}",
    )
    parser.add_argument(
        "--out-json",
        type=Path,
        default=None,
        help="Optional path to write the JSON report.",
    )
    parser.add_argument(
        "--include-foreign-rows",
        action="store_true",
        help="Include summaries of non-outcome JSONL rows in the report.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 when any malformed input row is encountered.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    paths = args.outcomes or [DEFAULT_OUTCOMES]
    report = build_report(paths, include_foreign_rows=args.include_foreign_rows)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.out_json:
        out_path = args.out_json.expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if args.strict and report["input_summary"]["malformed_rows"]:
        print(
            "[post-filing-outcome-replay-pattern-distiller] malformed input rows encountered",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
