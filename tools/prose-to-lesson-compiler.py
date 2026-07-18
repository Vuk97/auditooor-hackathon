#!/usr/bin/env python3
"""Compile triager/outcome/lesson prose into typed lesson predicates.

The compiler is deterministic and offline-only. It accepts JSON, JSONL,
Markdown, or plain text and emits bounded lesson predicate rows suitable for
later gate wiring. It never asserts acceptance, exploitability, or reward
eligibility.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


SCHEMA = "auditooor.prose_to_lesson_compiler.v1"
ROW_SCHEMA = "auditooor.lesson_predicate.v1"
SCHEMA_VERSION = "1.0"
TOOL_VERSION = "1.0.0"
DEFAULT_MAX_LESSONS = 100
DEFAULT_MAX_CHARS_PER_SOURCE = 200_000
MAX_SNIPPET_CHARS = 240
SUPPORTED_SUFFIXES = {".json", ".jsonl", ".md", ".markdown", ".txt", ".text"}


@dataclass(frozen=True)
class Signal:
    name: str
    regex: re.Pattern[str]


@dataclass(frozen=True)
class PredicateSpec:
    key: str
    description: str
    enforcement_level: str
    gate_phase: str
    signals: tuple[Signal, ...]
    output_type: str = "triager_objection"  # J2 typed-output vocabulary


# J2 typed-output vocabulary (verbatim from plan item J2):
#   hackerman_record | detector_hypothesis | hacker_question_template
#   triager_objection | kill_rubric | economic_viability_rule
#   harness_requirement | stop_criterion | scope_oos_rule | known_limitation
J2_OUTPUT_TYPES: frozenset[str] = frozenset({
    "hackerman_record",
    "detector_hypothesis",
    "hacker_question_template",
    "triager_objection",
    "kill_rubric",
    "economic_viability_rule",
    "harness_requirement",
    "stop_criterion",
    "scope_oos_rule",
    "known_limitation",
})


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


PREDICATES: tuple[PredicateSpec, ...] = (
    PredicateSpec(
        key="economic_viability_missing",
        description="Lesson says the draft lacks attacker-profit, capital, cost, or value-extraction proof.",
        enforcement_level="hard_pre_poc",
        gate_phase="require_economic_viability_model",
        output_type="economic_viability_rule",
        signals=(
            Signal("no_attacker_profit", _rx(r"\b(no|without|lacks?|missing)\b.{0,50}\b(attacker\s+)?profit\b")),
            Signal("unprofitable", _rx(r"\b(unprofitable|negative\s+ev|economically\s+infeasible|not\s+economically\s+viable)\b")),
            Signal("cost_exceeds_value", _rx(r"\b(gas|capital|borrow|liquidity|cost)\b.{0,50}\b(exceeds?|outweighs?|more\s+than)\b.{0,50}\b(value|gain|profit|impact)\b")),
            Signal("value_extraction_missing", _rx(r"\b(no|without|missing)\b.{0,50}\b(value\s+extraction|extractable\s+value|funds?\s+at\s+risk)\b")),
        ),
    ),
    PredicateSpec(
        key="future_reward_eligibility_not_accrued_reward_loss",
        description="Lesson says future reward-stream eligibility is not proof of accrued reward dilution.",
        enforcement_level="hard_pre_poc",
        gate_phase="require_accrued_reward_dilution_proof",
        output_type="economic_viability_rule",
        signals=(
            Signal(
                "future_emissions_only",
                _rx(
                    r"\b(late\s+(?:depositor|entrant|staker|user)[^.\n]{0,120}"
                    r"future[^.\n]{0,80}(?:reward|stream|emissions?)|"
                    r"future[^.\n]{0,80}(?:reward|stream|emissions?)[^.\n]{0,80}"
                    r"(?:alone|only|mere(?:ly)?|expected|not\s+proof))\b"
                ),
            ),
            Signal(
                "accrued_reward_loss_not_proven",
                _rx(
                    r"\b(?:does\s+not|doesn't|fails?\s+to|without|no)\s+prove[^.\n]{0,120}"
                    r"(?:unintended\s+loss|accrued\s+reward|pre[-\s]?entry|dilution|diluted)\b"
                ),
            ),
            Signal(
                "expected_live_supply_reward_stream",
                _rx(
                    r"\b(live[-\s]?supply\s+reward[-\s]?stream|"
                    r"expected[^.\n]{0,120}later\s+entrants?[^.\n]{0,120}later\s+emissions?)\b"
                ),
            ),
        ),
    ),
    PredicateSpec(
        key="intended_actor_mismatch",
        description="Lesson says the reported actor/capability does not match the protocol-intended actor.",
        enforcement_level="hard_pre_poc",
        gate_phase="require_actor_capability_binding",
        output_type="triager_objection",
        signals=(
            Signal("intended_actor", _rx(r"\bintended\s+actor\b|\bauthorized\s+actor\b|\bdesignated\s+(caller|actor|role)\b")),
            Signal("wrong_actor", _rx(r"\b(attacker|user|reporter)\b.{0,50}\b(is|was)\b.{0,30}\b(wrong|not\s+the|not\s+an)\b.{0,30}\b(actor|caller|role)\b")),
            Signal("capability_mismatch", _rx(r"\b(actor|caller|role|capability)\b.{0,50}\b(mismatch|mis-match|does\s+not\s+match|cannot\s+perform)\b")),
        ),
    ),
    PredicateSpec(
        key="ambient_mev_not_protocol_bug",
        description="Lesson distinguishes ordinary MEV/market activity from a protocol bug.",
        enforcement_level="hard_pre_poc",
        gate_phase="require_protocol_fault_not_ambient_mev",
        output_type="scope_oos_rule",
        signals=(
            Signal("ambient_mev", _rx(r"\bambient\s+mev\b|\bordinary\s+mev\b|\bnormal\s+(arbitrage|market\s+activity|trading)\b")),
            Signal("not_protocol_bug", _rx(r"\bnot\s+(a\s+)?protocol\s+bug\b|\bno\s+protocol\s+(fault|defect|invariant\s+break)\b")),
            Signal("mempool_only", _rx(r"\b(mempool|front[-\s]?run|sandwich|back[-\s]?run)\b.{0,70}\b(only|alone|external|ambient)\b")),
        ),
    ),
    PredicateSpec(
        key="protocol_bug_amplified_by_mev",
        description="Lesson says MEV is only the amplifier; the underlying fault is in protocol logic.",
        enforcement_level="advisory_worker_context",
        gate_phase="preserve_protocol_fault_when_mev_amplifies",
        output_type="known_limitation",
        signals=(
            Signal("mev_amplifies", _rx(r"\bmev\b.{0,60}\b(amplif(?:y|ies|ied)|magnif(?:y|ies|ied)|worsens?)\b")),
            Signal("protocol_root_cause", _rx(r"\b(protocol|contract)\b.{0,60}\b(root\s+cause|bug|fault|invariant\s+break|allows?|fails?)\b")),
            Signal("not_merely_mev", _rx(r"\bnot\s+(merely|just|only)\s+(ambient\s+)?mev\b")),
        ),
    ),
    PredicateSpec(
        key="documented_mechanics_no_stronger_intent",
        description="Lesson says documented mechanics or expected behavior do not prove stronger design intent.",
        enforcement_level="hard_pre_submit",
        gate_phase="require_stronger_than_documented_mechanics_intent",
        output_type="kill_rubric",
        signals=(
            Signal("documented_mechanics", _rx(r"\b(documented\s+mechanics?|as\s+documented|documented\s+behavior|docs?\s+(say|state|describe))\b")),
            Signal("no_stronger_intent", _rx(r"\b(no|without|lacks?|missing)\b.{0,50}\b(stronger\s+)?(design\s+)?intent\b")),
            Signal("expected_behavior", _rx(r"\b(expected|intended|by\s+design)\s+behavior\b")),
        ),
    ),
    PredicateSpec(
        key="low_severity_cap_triggered",
        description="Lesson says the impact is deterministically capped at low/informational severity.",
        enforcement_level="hard_pre_submit",
        gate_phase="cap_severity_or_block_overclaim",
        output_type="kill_rubric",
        signals=(
            Signal("low_cap", _rx(r"\b(low|informational|info)\b.{0,35}\b(severity\s+)?cap(?:ped|s|)?\b|\bseverity\s+(is\s+)?capped\s+(at|to)\s+(low|informational|info)\b")),
            Signal("limited_impact", _rx(r"\b(no\s+funds?\s+at\s+risk|dust\s+only|bounded\s+impact|limited\s+impact|no\s+material\s+loss)\b")),
            Signal("downgrade_low", _rx(r"\bdowngrad(?:e|ed|ing)\b.{0,40}\b(low|informational|info)\b")),
        ),
    ),
    PredicateSpec(
        key="admin_or_team_action_prerequisite",
        description="Lesson says the path depends on privileged admin/team/governance action.",
        enforcement_level="hard_pre_poc",
        gate_phase="require_non_privileged_or_routine_trigger",
        output_type="kill_rubric",
        signals=(
            Signal("admin_prereq", _rx(r"\b(admin|owner|governance|team|multisig|privileged)\b.{0,60}\b(action|prerequisite|must|needs?|required|only)\b")),
            Signal("only_role", _rx(r"\bonly(admin|owner|governance|team|role|multisig)\b|\bonly\s+(the\s+)?(admin|owner|team|governance|multisig)\b")),
            Signal("trusted_party", _rx(r"\btrusted\s+(party|operator|admin|team)\b.{0,50}\b(required|needed|acts?|chooses?)\b")),
        ),
    ),
    PredicateSpec(
        key="generic_dos_scope_risk",
        description="Lesson says the finding risks being generic DoS/griefing rather than in-scope protocol impact.",
        enforcement_level="hard_pre_submit",
        gate_phase="require_specific_in_scope_dos_impact",
        output_type="scope_oos_rule",
        signals=(
            Signal("generic_dos", _rx(r"\bgeneric\s+do[ss]\b|\bgeneric\s+denial\s+of\s+service\b|\bgeneric\s+grief(?:ing)?\b")),
            Signal("temporary_dos", _rx(r"\btemporary\s+do[ss]\b|\btransient\s+do[ss]\b|\bblock\s+stuffing\b|\bgas\s+grief(?:ing)?\b")),
            Signal("dos_scope", _rx(r"\bdo[ss]\b.{0,70}\b(out\s+of\s+scope|oos|scope\s+risk|not\s+in\s+scope)\b|\bscope\s+risk\b.{0,50}\bdo[ss]\b")),
        ),
    ),
)

PREDICATE_BY_KEY = {spec.key: spec for spec in PREDICATES}

JSON_TEXT_KEYS = {
    "body",
    "content",
    "description",
    "details",
    "feedback",
    "finding",
    "lesson",
    "lessons",
    "notes",
    "outcome",
    "outcome_prose",
    "reason",
    "rejection_reason",
    "summary",
    "text",
    "title",
    "triager_feedback",
    "triager_quote",
    "verdict",
}

POSITIVE_REWARD_PATTERNS: tuple[re.Pattern[str], ...] = (
    _rx(r"\b(paid|awarded|received|earned|won|got)\s+\$?\d[\d,]*(?:\.\d+)?\s*(?:usd|usdc|dollars?)?\b"),
    _rx(r"\b(payout|reward|bounty)\s+(?:of|was|is|=|:)\s+\$?\d[\d,]*(?:\.\d+)?\s*(?:usd|usdc|dollars?)?\b"),
    _rx(r"\$\d[\d,]*(?:\.\d+)?\s*(?:usd|usdc|dollars?)?\s+\b(payout|reward|bounty|paid|award)\b"),
)


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def stable_id(text: str, source_ref: str, predicate_key: str) -> str:
    digest = hashlib.sha256(f"{source_ref}\n{predicate_key}\n{text}".encode("utf-8")).hexdigest()
    return f"lesson-{digest[:16]}"


def source_ref(path: Path | None, label: str | None = None) -> str:
    if label:
        return label
    if path is None:
        return "<stdin>"
    return str(path)


def detect_format(path: Path | None, text: str) -> str:
    suffix = path.suffix.lower() if path is not None else ""
    if suffix == ".json":
        return "json"
    if suffix == ".jsonl":
        return "jsonl"
    if suffix in {".md", ".markdown"}:
        return "markdown"
    if suffix in {".txt", ".text"}:
        return "text"
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        return "json"
    return "text"


def _clean_ws(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _positive_reward_line(line: str) -> bool:
    lower = line.lower()
    if any(neg in lower for neg in ("no payout", "no reward", "without payout", "not paid", "no bounty")):
        return False
    return any(rx.search(line) for rx in POSITIVE_REWARD_PATTERNS)


def sanitize_for_output(text: str) -> tuple[str, int]:
    """Strip positive reward assertions from surfaced prose."""
    suppressed = 0
    kept: list[str] = []
    for line in text.splitlines() or [text]:
        if _positive_reward_line(line):
            suppressed += 1
            continue
        kept.append(line)
    sanitized = "\n".join(kept)
    return sanitized, suppressed


def make_snippet(text: str) -> tuple[str, int]:
    sanitized, suppressed = sanitize_for_output(text)
    snippet = _clean_ws(sanitized)
    if len(snippet) > MAX_SNIPPET_CHARS:
        snippet = snippet[: MAX_SNIPPET_CHARS - 3].rstrip() + "..."
    return snippet, suppressed


def _json_text_from_value(value: Any, key_hint: str = "") -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value) if key_hint.lower() in JSON_TEXT_KEYS else ""
    if isinstance(value, list):
        return "\n".join(filter(None, (_json_text_from_value(item, key_hint) for item in value)))
    if isinstance(value, dict):
        parts: list[str] = []
        for key, item in value.items():
            key_text = str(key)
            if key_text.lower() in JSON_TEXT_KEYS:
                text = _json_text_from_value(item, key_text)
                if text:
                    parts.append(f"{key_text}: {text}")
            elif isinstance(item, (dict, list)):
                nested = _json_text_from_value(item, key_text)
                if nested:
                    parts.append(nested)
        return "\n".join(parts)
    return ""


def iter_json_records(payload: Any, source: str) -> Iterable[dict[str, Any]]:
    if isinstance(payload, list):
        for idx, item in enumerate(payload):
            yield from iter_json_records(item, f"{source}#{idx}")
        return
    if isinstance(payload, dict):
        rows = payload.get("rows")
        if isinstance(rows, list):
            for idx, item in enumerate(rows):
                yield from iter_json_records(item, f"{source}#rows[{idx}]")
            return
        lessons = payload.get("lessons")
        if isinstance(lessons, list):
            for idx, item in enumerate(lessons):
                yield from iter_json_records(item, f"{source}#lessons[{idx}]")
            return
        text = _json_text_from_value(payload)
        if text:
            record_id = payload.get("id") or payload.get("finding_id") or payload.get("submission_id")
            yield {
                "source_ref": f"{source}#{record_id}" if record_id else source,
                "text": text,
                "metadata": {
                    "input_record_id": record_id,
                    "outcome": payload.get("outcome") or payload.get("status"),
                    "severity": payload.get("severity"),
                },
            }
        return
    if isinstance(payload, str) and payload.strip():
        yield {"source_ref": source, "text": payload, "metadata": {}}


def iter_text_records(text: str, source: str) -> Iterable[dict[str, Any]]:
    current: list[str] = []
    start_line = 1

    def flush(end_line: int) -> dict[str, Any] | None:
        nonlocal current
        raw = "\n".join(current).strip()
        current = []
        if not raw:
            return None
        return {
            "source_ref": f"{source}:{start_line}",
            "text": raw,
            "metadata": {"line_start": start_line, "line_end": end_line},
        }

    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        is_bullet = bool(re.match(r"^([-*]|\d+[.)])\s+", stripped))
        if not stripped:
            row = flush(line_no - 1)
            if row:
                yield row
            start_line = line_no + 1
            continue
        if is_bullet and current:
            row = flush(line_no - 1)
            if row:
                yield row
            start_line = line_no
        elif not current:
            start_line = line_no
        current.append(stripped)

    row = flush(len(text.splitlines()) or 1)
    if row:
        yield row


def parse_input_text(text: str, path: Path | None = None, label: str | None = None) -> tuple[list[dict[str, Any]], str, list[str]]:
    fmt = detect_format(path, text)
    src = source_ref(path, label)
    warnings: list[str] = []
    if fmt == "json":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            warnings.append(f"{src}: JSON parse failed; treated as text: {exc}")
            return list(iter_text_records(text, src)), "text", warnings
        return list(iter_json_records(payload, src)), "json", warnings
    if fmt == "jsonl":
        rows: list[dict[str, Any]] = []
        for line_no, raw in enumerate(text.splitlines(), start=1):
            if not raw.strip():
                continue
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError as exc:
                warnings.append(f"{src}:{line_no}: JSONL parse failed; skipped: {exc}")
                continue
            rows.extend(iter_json_records(payload, f"{src}:{line_no}"))
        return rows, "jsonl", warnings
    return list(iter_text_records(text, src)), fmt, warnings


def classify_text(text: str) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for spec in PREDICATES:
        signals = [signal.name for signal in spec.signals if signal.regex.search(text)]
        if not signals:
            continue
        matches.append(
            {
                "predicate": spec.key,
                "description": spec.description,
                "enforcement_level": spec.enforcement_level,
                "gate_phase": spec.gate_phase,
                "output_type": spec.output_type,
                "matched_signals": signals[:8],
                "confidence": "high" if len(signals) >= 2 else "medium",
            }
        )
    return matches


def compile_records(
    records: Iterable[dict[str, Any]],
    *,
    generated_at: str,
    max_lessons: int = DEFAULT_MAX_LESSONS,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    lessons: list[dict[str, Any]] = []
    predicate_counts: dict[str, int] = {}
    reward_lines_suppressed = 0
    records_seen = 0
    records_with_predicates = 0
    truncated = False

    seen_keys: set[tuple[str, str, str]] = set()
    for record in records:
        records_seen += 1
        text = str(record.get("text") or "")
        _, suppressed_for_record = sanitize_for_output(text)
        reward_lines_suppressed += suppressed_for_record
        predicates = classify_text(text)
        if not predicates:
            continue
        records_with_predicates += 1
        snippet, _ = make_snippet(text)
        for pred in predicates:
            key = (str(record.get("source_ref") or ""), pred["predicate"], snippet)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            predicate_counts[pred["predicate"]] = predicate_counts.get(pred["predicate"], 0) + 1
            row = {
                "schema": ROW_SCHEMA,
                "schema_version": SCHEMA_VERSION,
                "tool_version": TOOL_VERSION,
                "lesson_id": stable_id(text, str(record.get("source_ref") or ""), pred["predicate"]),
                "predicate": pred["predicate"],
                "description": pred["description"],
                "enforcement_level": pred["enforcement_level"],
                "gate_phase": pred["gate_phase"],
                "output_type": pred["output_type"],
                "confidence": pred["confidence"],
                "matched_signals": pred["matched_signals"],
                "source_ref": record.get("source_ref"),
                "source_metadata": record.get("metadata") or {},
                "snippet": snippet,
                "generated_at_utc": generated_at,
                "advisory_only": pred["enforcement_level"] == "advisory_worker_context",
                "promotion_authority": False,
                "submit_ready": False,
                "severity": "none",
            }
            lessons.append(row)
            if len(lessons) >= max_lessons:
                truncated = True
                return lessons, {
                    "records_seen": records_seen,
                    "records_with_predicates": records_with_predicates,
                    "predicate_counts": predicate_counts,
                    "positive_reward_claim_lines_suppressed": reward_lines_suppressed,
                    "truncated": truncated,
                }

    return lessons, {
        "records_seen": records_seen,
        "records_with_predicates": records_with_predicates,
        "predicate_counts": predicate_counts,
        "positive_reward_claim_lines_suppressed": reward_lines_suppressed,
        "truncated": truncated,
    }


def compile_text(
    text: str,
    *,
    path: Path | None = None,
    label: str | None = None,
    max_lessons: int = DEFAULT_MAX_LESSONS,
    max_chars_per_source: int = DEFAULT_MAX_CHARS_PER_SOURCE,
    generated_at: str | None = None,
) -> dict[str, Any]:
    generated = generated_at or utc_now_iso()
    truncated_input = len(text) > max_chars_per_source
    bounded_text = text[:max_chars_per_source]
    records, input_format, warnings = parse_input_text(bounded_text, path=path, label=label)
    lessons, summary = compile_records(records, generated_at=generated, max_lessons=max_lessons)
    summary["input_truncated"] = truncated_input
    summary["warnings"] = warnings
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "tool_version": TOOL_VERSION,
        "generated_at_utc": generated,
        "offline_only": True,
        "network_access": False,
        "input": {
            "source_ref": source_ref(path, label),
            "format": input_format,
            "chars_seen": min(len(text), max_chars_per_source),
            "chars_truncated": max(0, len(text) - max_chars_per_source),
        },
        "predicate_catalog": [
            {
                "predicate": spec.key,
                "enforcement_level": spec.enforcement_level,
                "gate_phase": spec.gate_phase,
                "output_type": spec.output_type,
            }
            for spec in PREDICATES
        ],
        "summary": summary,
        "lessons": lessons,
        "positive_reward_claim_policy": "positive reward assertions are not surfaced as lesson evidence",
    }


def compile_path(
    path: Path,
    *,
    max_lessons: int = DEFAULT_MAX_LESSONS,
    max_chars_per_source: int = DEFAULT_MAX_CHARS_PER_SOURCE,
    generated_at: str | None = None,
) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8", errors="replace")
    return compile_text(
        raw,
        path=path,
        max_lessons=max_lessons,
        max_chars_per_source=max_chars_per_source,
        generated_at=generated_at,
    )


def merge_compilations(compilations: Sequence[dict[str, Any]], *, generated_at: str | None = None) -> dict[str, Any]:
    generated = generated_at or (compilations[0].get("generated_at_utc") if compilations else utc_now_iso())
    lessons: list[dict[str, Any]] = []
    predicate_counts: dict[str, int] = {}
    warnings: list[str] = []
    reward_lines_suppressed = 0
    records_seen = 0
    records_with_predicates = 0
    truncated = False
    input_sources: list[dict[str, Any]] = []

    for payload in compilations:
        input_sources.append(payload.get("input", {}))
        for row in payload.get("lessons", []):
            if isinstance(row, dict):
                lessons.append(row)
                key = str(row.get("predicate") or "")
                if key:
                    predicate_counts[key] = predicate_counts.get(key, 0) + 1
        summary = payload.get("summary", {}) if isinstance(payload.get("summary"), dict) else {}
        records_seen += int(summary.get("records_seen") or 0)
        records_with_predicates += int(summary.get("records_with_predicates") or 0)
        reward_lines_suppressed += int(summary.get("positive_reward_claim_lines_suppressed") or 0)
        truncated = truncated or bool(summary.get("truncated")) or bool(summary.get("input_truncated"))
        warnings.extend(str(item) for item in summary.get("warnings") or [])

    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "tool_version": TOOL_VERSION,
        "generated_at_utc": generated,
        "offline_only": True,
        "network_access": False,
        "input": {"sources": input_sources, "source_count": len(input_sources)},
        "predicate_catalog": [
            {
                "predicate": spec.key,
                "enforcement_level": spec.enforcement_level,
                "gate_phase": spec.gate_phase,
                "output_type": spec.output_type,
            }
            for spec in PREDICATES
        ],
        "summary": {
            "records_seen": records_seen,
            "records_with_predicates": records_with_predicates,
            "predicate_counts": predicate_counts,
            "positive_reward_claim_lines_suppressed": reward_lines_suppressed,
            "truncated": truncated,
            "warnings": warnings,
        },
        "lessons": lessons,
        "positive_reward_claim_policy": "positive reward assertions are not surfaced as lesson evidence",
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="*", type=Path, help="JSON, JSONL, Markdown, or text files. Reads stdin when omitted.")
    parser.add_argument("--out-json", type=Path, default=None)
    parser.add_argument("--max-lessons", type=int, default=DEFAULT_MAX_LESSONS)
    parser.add_argument("--max-chars-per-source", type=int, default=DEFAULT_MAX_CHARS_PER_SOURCE)
    parser.add_argument("--print-json", action="store_true", help="Print JSON. Default when --out-json is omitted.")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    generated = utc_now_iso()
    compilations: list[dict[str, Any]] = []
    if args.inputs:
        for path in args.inputs:
            src = path.expanduser().resolve()
            if not src.is_file():
                raise SystemExit(f"[prose-to-lesson-compiler] input not found: {src}")
            compilations.append(
                compile_path(
                    src,
                    max_lessons=args.max_lessons,
                    max_chars_per_source=args.max_chars_per_source,
                    generated_at=generated,
                )
            )
    else:
        compilations.append(
            compile_text(
                sys.stdin.read(),
                label="<stdin>",
                max_lessons=args.max_lessons,
                max_chars_per_source=args.max_chars_per_source,
                generated_at=generated,
            )
        )

    payload = compilations[0] if len(compilations) == 1 else merge_compilations(compilations, generated_at=generated)
    if args.out_json:
        out = args.out_json.expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.print_json or not args.out_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
