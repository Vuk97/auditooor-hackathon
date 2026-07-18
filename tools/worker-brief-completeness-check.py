#!/usr/bin/env python3
"""worker-brief-completeness-check.py — validate a worker brief artifact.

# This tool emits no corpus record.

A worker brief (the enriched prompt artifact produced by
``tools/spawn-worker.sh`` / ``tools/dispatch-agent-with-prebriefing.py`` and
handed to a dispatched Agent) is only safe to dispatch when it carries the
five load-bearing sections a hunt/drill/dispute worker needs to operate
WITHOUT re-deriving context the harness already computed:

  1. MCP-recall evidence  - a recorded ``context_pack_id`` (and ideally the
                            Layer-1 ``vault_*`` recall commands) so the worker
                            grounds in cached knowledge before any source read.
  2. Hunt-definition      - an explicit task / hunt-definition section telling
                            the worker WHAT it is hunting (scope, target,
                            attack class, or task body).
  3. Skip-set             - a skip-set / known-dead-ends reference so the
                            worker skips already-filed / killed / cooled-down
                            candidates instead of re-deriving them.
  4. Brain-prime          - a brain-prime / mindset-priming section seeding the
                            attack-class hints for the target before source
                            reads.
  5. Hacker-question reqs - a hacker-questions requirement section so the
                            worker traverses the per-attack-class question
                            library against the target.

Trigger: any worker-brief artifact (``.md`` / ``.txt``) intended for dispatch.

Verdict vocabulary:
  pass-brief-complete               - all five sections present
  fail-missing-mcp-recall           - no context_pack_id / MCP-recall evidence
  fail-missing-hunt-definition      - no hunt-definition / task section
  fail-missing-skip-set             - no skip-set / known-dead-ends reference
  fail-missing-brain-prime          - no brain-prime / mindset section
  fail-missing-hacker-questions     - no hacker-questions requirement section
  ok-rebuttal                       - valid wbc-rebuttal marker present
  error                             - input error (missing / empty file)

When more than one section is missing the verdict reports the first missing
section in canonical order (mcp-recall, hunt-definition, skip-set,
brain-prime, hacker-questions) and lists ALL missing sections in
``missing_sections`` so the caller sees the full gap.

Override marker: a visible bounded line ``wbc-rebuttal: <reason>`` (<=200
chars) OR the HTML-comment form ``<!-- wbc-rebuttal: <reason> -->``. An empty
or oversized reason (>200 chars) is ignored; the original fail verdict stands.

Exit codes:
  0 - pass or accepted rebuttal
  1 - brief incomplete (at least one section missing)
  2 - input error

Schema: auditooor.worker_brief_completeness.v1

Usage:
  python3 tools/worker-brief-completeness-check.py <brief.md> [--json]
                                                    [--strict-recall]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.worker_brief_completeness.v1"
REBUTTAL_MAX = 200

# Canonical section order. The verdict reports the FIRST missing section in
# this order, but `missing_sections` enumerates all gaps.
SECTION_ORDER = [
    "mcp-recall",
    "hunt-definition",
    "skip-set",
    "brain-prime",
    "hacker-questions",
]

VERDICT_FOR_SECTION = {
    "mcp-recall": "fail-missing-mcp-recall",
    "hunt-definition": "fail-missing-hunt-definition",
    "skip-set": "fail-missing-skip-set",
    "brain-prime": "fail-missing-brain-prime",
    "hacker-questions": "fail-missing-hacker-questions",
}

# --- detection patterns (case-insensitive) ---------------------------------
# MCP-recall evidence: a recorded context_pack_id is the canonical proof that
# the worker (or the enrichment step) ran the MCP-first recall. The vault_
# recall commands are a secondary signal.
_MCP_RECALL_PATTERNS = [
    re.compile(r"context[_\-\s]?pack[_\-\s]?id", re.IGNORECASE),
    re.compile(r"\bvault_resume_context\b", re.IGNORECASE),
    re.compile(r"\bvault_known_dead_ends\b", re.IGNORECASE),
    re.compile(r"\bvault_mining_health\b", re.IGNORECASE),
    re.compile(r"MCP[\-\s]?FIRST", re.IGNORECASE),
    re.compile(r"MCP[\-\s]?recall", re.IGNORECASE),
]

# Hunt-definition: an explicit task / hunt section.
_HUNT_DEFINITION_PATTERNS = [
    re.compile(r"^#{1,4}\s*TASK\b", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^#{1,4}\s*HUNT[\-\s]?DEFINITION\b", re.IGNORECASE | re.MULTILINE),
    re.compile(r"\bhunt[\-\s]?definition\b", re.IGNORECASE),
    re.compile(r"^#{1,4}\s*HUNT\b", re.IGNORECASE | re.MULTILINE),
    re.compile(r"\btask\s+body\b", re.IGNORECASE),
]

# Skip-set: a known-dead-ends / skip-set reference.
_SKIP_SET_PATTERNS = [
    re.compile(r"\bskip[\-\s]?set\b", re.IGNORECASE),
    re.compile(r"\bknown[\-\s]?dead[\-\s]?ends?\b", re.IGNORECASE),
    re.compile(r"hunt_skip_set", re.IGNORECASE),
    re.compile(r"\bvault_known_dead_ends\b", re.IGNORECASE),
    re.compile(r"\balready[\-\s]?(filed|killed|cooled)", re.IGNORECASE),
]

# Brain-prime: a mindset / brain-prime priming section.
_BRAIN_PRIME_PATTERNS = [
    re.compile(r"\bbrain[\-\s]?prime\b", re.IGNORECASE),
    re.compile(r"\bvault_brain_prime_context\b", re.IGNORECASE),
    re.compile(r"\bmindset[\-\s]?(prim|hint|inject)", re.IGNORECASE),
    re.compile(r"\bfunction[\-\s]?mindset\b", re.IGNORECASE),
]

# Hacker-question requirements.
_HACKER_QUESTION_PATTERNS = [
    re.compile(r"\bhacker[\-\s]?questions?\b", re.IGNORECASE),
    re.compile(r"\bvault_hacker_questions\b", re.IGNORECASE),
    re.compile(r"hacker_questions_library", re.IGNORECASE),
    re.compile(r"\bhacker[\-\s]?q\b", re.IGNORECASE),
]

_SECTION_PATTERNS = {
    "mcp-recall": _MCP_RECALL_PATTERNS,
    "hunt-definition": _HUNT_DEFINITION_PATTERNS,
    "skip-set": _SKIP_SET_PATTERNS,
    "brain-prime": _BRAIN_PRIME_PATTERNS,
    "hacker-questions": _HACKER_QUESTION_PATTERNS,
}

# A context_pack_id with a non-empty value (not just the literal token) is a
# stronger recall signal used by --strict-recall.
_CONTEXT_PACK_ID_VALUE = re.compile(
    r"context[_\-\s]?pack[_\-\s]?id"
    r"\s*[:=]\s*"
    r"[\"']?([A-Za-z0-9][A-Za-z0-9._:\-]{3,})",
    re.IGNORECASE,
)

_REBUTTAL_VISIBLE = re.compile(
    r"^\s*wbc-rebuttal:\s*(?P<reason>.+?)\s*$", re.IGNORECASE | re.MULTILINE
)
_REBUTTAL_COMMENT = re.compile(
    r"<!--\s*wbc-rebuttal:\s*(?P<reason>.+?)\s*-->", re.IGNORECASE | re.DOTALL
)


def _find_rebuttal(text: str) -> str | None:
    """Return the rebuttal reason if a valid (non-empty, <=200char) marker is
    present, else None."""
    for pat in (_REBUTTAL_COMMENT, _REBUTTAL_VISIBLE):
        m = pat.search(text)
        if not m:
            continue
        reason = (m.group("reason") or "").strip()
        if reason and len(reason) <= REBUTTAL_MAX:
            return reason
    return None


def _section_present(text: str, section: str, strict_recall: bool = False) -> bool:
    patterns = _SECTION_PATTERNS[section]
    present = any(p.search(text) for p in patterns)
    if section == "mcp-recall" and present and strict_recall:
        # In strict-recall mode the brief must carry a context_pack_id with a
        # concrete value, not merely mention the recall commands.
        return bool(_CONTEXT_PACK_ID_VALUE.search(text))
    return present


def evaluate(text: str, strict_recall: bool = False) -> dict[str, Any]:
    """Evaluate a worker-brief body. Returns the result dict (no I/O)."""
    rebuttal = _find_rebuttal(text)

    present: dict[str, bool] = {}
    for section in SECTION_ORDER:
        present[section] = _section_present(text, section, strict_recall=strict_recall)

    missing = [s for s in SECTION_ORDER if not present[s]]

    if not missing:
        verdict = "pass-brief-complete"
        passed = True
    elif rebuttal is not None:
        verdict = "ok-rebuttal"
        passed = True
    else:
        verdict = VERDICT_FOR_SECTION[missing[0]]
        passed = False

    return {
        "schema": SCHEMA,
        "verdict": verdict,
        "passed": passed,
        "sections_present": present,
        "missing_sections": missing,
        "rebuttal_reason": rebuttal,
        "strict_recall": strict_recall,
    }


def _error(message: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "verdict": "error",
        "passed": False,
        "error": message,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate a worker brief artifact for the five "
        "load-bearing dispatch sections."
    )
    parser.add_argument("brief", help="Path to the worker-brief artifact (.md/.txt)")
    parser.add_argument(
        "--strict-recall",
        action="store_true",
        help="Require a context_pack_id with a concrete value, not just a "
        "mention of the MCP-recall commands.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the full result dict as JSON.",
    )
    args = parser.parse_args(argv)

    path = Path(args.brief)
    if not path.exists():
        result = _error(f"brief not found: {path}")
        if args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            print(f"error: {result['error']}", file=sys.stderr)
        return 2

    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:  # pragma: no cover - filesystem edge
        result = _error(f"could not read brief: {exc}")
        if args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            print(f"error: {result['error']}", file=sys.stderr)
        return 2

    if not text.strip():
        result = _error(f"brief is empty: {path}")
        if args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            print(f"error: {result['error']}", file=sys.stderr)
        return 2

    result = evaluate(text, strict_recall=args.strict_recall)
    result["brief_path"] = str(path)

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(f"verdict: {result['verdict']}")
        if result["missing_sections"]:
            print(f"missing: {', '.join(result['missing_sections'])}")
        if result["rebuttal_reason"]:
            print(f"rebuttal: {result['rebuttal_reason']}")

    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
