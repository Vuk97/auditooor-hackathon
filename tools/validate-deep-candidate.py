#!/usr/bin/env python3
"""
validate-deep-candidate.py — schema validator for V5 deep-lane candidates.

Companion to ``docs/schemas/deep_candidate.v1.json``. Stdlib-only (no jsonschema
pip dep) so it runs in any worktree without bootstrapping. Encodes the
allOf transition rules from the schema explicitly because draft-07 if/then
branches are too easy to misread when a candidate is rejected for the wrong
reason.

Exit codes:
    0   candidate is schema-valid AND passes the V5 advisory-floor rules
    1   candidate is invalid (errors printed to stderr, one per line)
    2   bad CLI / IO / JSON parse error

The validator is intentionally strict on a small set of advisory-floor rules
that the JSON Schema keywords cannot express cleanly:

* ``claim`` must be plain text — no markdown headings, code fences, or HTML
  tags. (Minimax pre-review #1: severity-smuggling via markdown.)
* ``reproduction`` must not be a placeholder ("TBD", "todo", "n/a"). An empty
  reproduction is already caught by the ``minLength`` keyword.
* ``confidence: low`` with ``promotion_status`` in {hold, investigate,
  poc_ready} requires at least one ``blocking_questions`` entry.
* ``confidence: high`` requires ``promotion_status: poc_ready``.
* ``promotion_status: rejected`` caps confidence at ``medium``.
* ``files`` entries must be workspace-relative (no leading ``/`` or drive
  letter, no ``..``).

Schema emission is opt-in. This validator is the only gate that lane wiring
trusts; ``make audit`` does not invoke it.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

SCHEMA_VERSION = "deep_candidate.v1"
LANES = {"math", "crypto", "econ", "symbolic", "fuzz", "source_mine"}
CONFIDENCES = {"low", "medium", "high"}
PROMOTIONS = {"rejected", "hold", "investigate", "poc_ready"}

# Plain-text claim guard. Reject markdown headings, code fences, HTML tags,
# and severity-smuggling tokens nested inside `claim`. We are deliberately
# narrow: legitimate prose containing the word "high" is fine; the regex
# fires only on standalone severity markers that look like Markdown.
#
# Minimax pre-review surfaced two bypasses that the initial regex missed:
#   - blockquote prefix ("> Severity: high")
#   - markdown table cells ("| Severity | high |")
# Both are now caught explicitly.
_MARKDOWN_HEADING_RE = re.compile(r"(?m)^\s{0,3}#{1,6}\s+\S")
_CODE_FENCE_RE = re.compile(r"```|~~~")
_HTML_TAG_RE = re.compile(r"<\s*[a-zA-Z][^>]*>")
_SEVERITY_SMUGGLE_RE = re.compile(
    r"(?im)^\s*(?:>+\s*)?(?:\*\*|__)?\s*severity\s*[:\-]\s*"
    r"(?:critical|high|medium|low)\b"
)
# Markdown-table cell carrying a severity verdict, e.g. `| severity | high |`.
_SEVERITY_TABLE_RE = re.compile(
    r"(?im)\|\s*severity\s*\|\s*(?:critical|high|medium|low)\s*\|"
)
# Standalone blockquote heading ("> Severity") even without trailing colon.
_BLOCKQUOTE_SEVERITY_RE = re.compile(
    r"(?im)^\s*>\s+(?:critical|high|medium|low)(?:\s|$)"
)

# Reproduction placeholders that snuck through size-based checks in past
# Tier-B work. Add patterns conservatively — false positives here cost real
# signal because they reject otherwise good emissions.
_REPRO_PLACEHOLDERS = re.compile(
    r"(?im)^\s*(?:tbd|todo|t\.b\.d\.?|n/?a|none|pending|fixme|xxx)\s*\.?\s*$"
)


class ValidationError(Exception):
    """Aggregates one or more validation messages."""

    def __init__(self, errors: List[str]):
        super().__init__("; ".join(errors))
        self.errors = list(errors)


def _add(errors: List[str], msg: str) -> None:
    errors.append(msg)


def _is_str(v: Any) -> bool:
    return isinstance(v, str)


def _check_required(doc: Dict[str, Any], errors: List[str]) -> None:
    required = (
        "schema_version",
        "lane",
        "candidate_id",
        "files",
        "claim",
        "trigger",
        "impact",
        "reproduction",
        "confidence",
        "blocking_questions",
        "promotion_status",
    )
    for key in required:
        if key not in doc:
            _add(errors, f"missing required field: {key}")


def _check_schema_version(doc: Dict[str, Any], errors: List[str]) -> None:
    sv = doc.get("schema_version")
    if sv != SCHEMA_VERSION:
        _add(errors, f"schema_version must equal '{SCHEMA_VERSION}', got {sv!r}")


def _check_lane(doc: Dict[str, Any], errors: List[str]) -> None:
    lane = doc.get("lane")
    if lane not in LANES:
        _add(errors, f"lane must be one of {sorted(LANES)}, got {lane!r}")


def _check_candidate_id(doc: Dict[str, Any], errors: List[str]) -> None:
    cid = doc.get("candidate_id")
    if not _is_str(cid) or not cid:
        _add(errors, "candidate_id must be a non-empty string")
        return
    if len(cid) > 200:
        _add(errors, "candidate_id exceeds 200 chars")
    if not re.fullmatch(r"[A-Za-z0-9._:-]+", cid):
        _add(errors, "candidate_id must match [A-Za-z0-9._:-]+ (no markdown / spaces)")


def _check_files(doc: Dict[str, Any], errors: List[str]) -> None:
    files = doc.get("files")
    if not isinstance(files, list) or not files:
        _add(errors, "files must be a non-empty list")
        return
    for idx, entry in enumerate(files):
        if not _is_str(entry) or not entry:
            _add(errors, f"files[{idx}] must be a non-empty string")
            continue
        if entry.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", entry):
            _add(errors, f"files[{idx}] must be workspace-relative (got absolute: {entry!r})")
        if ".." in Path(entry).parts:
            _add(errors, f"files[{idx}] must not traverse parent dirs (got: {entry!r})")
        if len(entry) > 1024:
            _add(errors, f"files[{idx}] exceeds 1024 chars")


def _check_text_field(
    doc: Dict[str, Any],
    errors: List[str],
    field: str,
    *,
    max_len: int,
    plain_text: bool = False,
) -> str:
    val = doc.get(field, "")
    if not _is_str(val) or not val.strip():
        _add(errors, f"{field} must be a non-empty plain-text string")
        return ""
    if len(val) > max_len:
        _add(errors, f"{field} exceeds {max_len} chars (got {len(val)})")
    if plain_text:
        if _MARKDOWN_HEADING_RE.search(val):
            _add(errors, f"{field} must not contain markdown headings")
        if _CODE_FENCE_RE.search(val):
            _add(errors, f"{field} must not contain code fences (``` or ~~~)")
        if _HTML_TAG_RE.search(val):
            _add(errors, f"{field} must not contain HTML tags")
        if (
            _SEVERITY_SMUGGLE_RE.search(val)
            or _SEVERITY_TABLE_RE.search(val)
            or _BLOCKQUOTE_SEVERITY_RE.search(val)
        ):
            _add(
                errors,
                f"{field} must not embed standalone severity markers — "
                "promotion is decided by the validator + gate, not free text",
            )
    return val


def _check_reproduction(doc: Dict[str, Any], errors: List[str]) -> None:
    val = _check_text_field(doc, errors, "reproduction", max_len=8000, plain_text=False)
    if val and _REPRO_PLACEHOLDERS.match(val.strip()):
        _add(
            errors,
            "reproduction must be a runnable command / fixture path / replay "
            "spec; placeholder tokens (TBD/TODO/N/A/...) are rejected",
        )


def _check_confidence(doc: Dict[str, Any], errors: List[str]) -> None:
    conf = doc.get("confidence")
    if conf not in CONFIDENCES:
        _add(errors, f"confidence must be one of {sorted(CONFIDENCES)}, got {conf!r}")


def _check_promotion(doc: Dict[str, Any], errors: List[str]) -> None:
    promo = doc.get("promotion_status")
    if promo not in PROMOTIONS:
        _add(
            errors,
            f"promotion_status must be one of {sorted(PROMOTIONS)}, got {promo!r}",
        )


def _check_blocking_questions(doc: Dict[str, Any], errors: List[str]) -> None:
    bqs = doc.get("blocking_questions")
    if not isinstance(bqs, list):
        _add(errors, "blocking_questions must be a list")
        return
    if len(bqs) > 50:
        _add(errors, "blocking_questions exceeds 50 entries")
    for idx, q in enumerate(bqs):
        if not _is_str(q) or not q.strip():
            _add(errors, f"blocking_questions[{idx}] must be a non-empty string")
        elif len(q) > 500:
            _add(errors, f"blocking_questions[{idx}] exceeds 500 chars")


def _check_cross_field(doc: Dict[str, Any], errors: List[str]) -> None:
    """Encode the schema's allOf rules in plain Python for clearer errors."""
    conf = doc.get("confidence")
    promo = doc.get("promotion_status")
    bqs = doc.get("blocking_questions") or []

    # Acceptance test 3: low + active promo => non-empty blocking_questions.
    if (
        conf == "low"
        and promo in {"hold", "investigate", "poc_ready"}
        and not bqs
    ):
        errors.append(
            "advisory floor: confidence=low with promotion_status="
            f"{promo} requires at least one blocking_questions entry "
            "(symbolic counterexamples / source-mining hits without replay "
            "must surface what would unblock them)"
        )

    # high confidence only allowed for poc_ready.
    if conf == "high" and promo != "poc_ready":
        errors.append(
            f"confidence=high requires promotion_status=poc_ready; got {promo!r}"
        )

    # rejected caps confidence at medium.
    if promo == "rejected" and conf == "high":
        errors.append("promotion_status=rejected cannot carry confidence=high")

    # Minimax bypass #2: `poc_ready` at confidence != high without any
    # blocking question is a "claim PoC without proof" smuggle. Either the
    # candidate has high confidence (a real PoC) OR it must surface what is
    # blocking the upgrade. Empty blocking_questions at poc_ready+medium/low
    # is the gap.
    if promo == "poc_ready" and conf != "high" and not bqs:
        errors.append(
            "promotion_status=poc_ready below high confidence requires at "
            "least one blocking_questions entry (what is preventing the "
            "high-confidence promotion?); empty list lets a candidate claim "
            "PoC-readiness without proof"
        )


def _check_unknown_keys(doc: Dict[str, Any], errors: List[str]) -> None:
    allowed = {
        "schema_version",
        "lane",
        "candidate_id",
        "files",
        "claim",
        "trigger",
        "impact",
        "reproduction",
        "confidence",
        "blocking_questions",
        "promotion_status",
        "lane_payload",
        "tool",
        "generated_at",
        "workspace",
    }
    for key in doc.keys():
        if key not in allowed:
            _add(errors, f"unexpected field: {key}")


def validate(doc: Any) -> Tuple[bool, List[str]]:
    """Validate ``doc`` against deep_candidate.v1. Returns (ok, errors)."""
    errors: List[str] = []

    if not isinstance(doc, dict):
        return False, ["candidate JSON must be an object"]

    _check_required(doc, errors)
    _check_unknown_keys(doc, errors)

    # Short-circuit on missing required fields — secondary checks would noise
    # the error list with cascade failures otherwise.
    if errors:
        return False, errors

    _check_schema_version(doc, errors)
    _check_lane(doc, errors)
    _check_candidate_id(doc, errors)
    _check_files(doc, errors)
    _check_text_field(doc, errors, "claim", max_len=4000, plain_text=True)
    _check_text_field(doc, errors, "trigger", max_len=4000, plain_text=False)
    _check_text_field(doc, errors, "impact", max_len=4000, plain_text=False)
    _check_reproduction(doc, errors)
    _check_confidence(doc, errors)
    _check_promotion(doc, errors)
    _check_blocking_questions(doc, errors)

    if not errors:
        _check_cross_field(doc, errors)

    return (not errors), errors


def _load(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate a deep-lane candidate JSON file against "
            f"docs/schemas/{SCHEMA_VERSION}.json plus the V5 advisory floor."
        ),
    )
    parser.add_argument(
        "candidates",
        nargs="+",
        type=Path,
        help="One or more candidate JSON files to validate.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress OK lines on success; still prints errors on failure.",
    )
    args = parser.parse_args(argv)

    rc = 0
    for path in args.candidates:
        try:
            doc = _load(path)
        except FileNotFoundError:
            print(f"[validate-deep-candidate] {path}: not found", file=sys.stderr)
            return 2
        except json.JSONDecodeError as exc:
            print(f"[validate-deep-candidate] {path}: invalid JSON: {exc}",
                  file=sys.stderr)
            return 2
        ok, errors = validate(doc)
        if ok:
            if not args.quiet:
                print(f"[validate-deep-candidate] OK {path}")
        else:
            rc = 1
            print(f"[validate-deep-candidate] INVALID {path}", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main())
