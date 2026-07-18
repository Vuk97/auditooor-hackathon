"""
auction_stage_skipped_via_hook_returns_false

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: auction-stage-skipped-via-hook-returns-false
Platform: solana
Source: phase7_rust_fixture_auction_stage_skipped_via_hook_returns_false.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

_IGNORED_RESULT_RE = re.compile(
    r"let\s+_[A-Za-z0-9_]*\s*=\s*[^;]*settle_[A-Za-z0-9_]*auction\s*\(",
    re.MULTILINE | re.IGNORECASE,
)
_FALSE_HOOK_RE = re.compile(
    r"fn\s+settle_[A-Za-z0-9_]*auction[\s\S]{0,400}?->\s*bool[\s\S]{0,400}?\bfalse\b",
    re.MULTILINE | re.IGNORECASE,
)
_PROCEED_RE = re.compile(
    r"proceed_to_[A-Za-z0-9_]+\s*\(",
    re.MULTILINE | re.IGNORECASE,
)
_SAFE_RESULT_CHECK_RE = re.compile(
    r"if\s*!\s*[A-Za-z0-9_]+\s*\{\s*return\s+Err|"
    r"if\s+[A-Za-z0-9_]+\s*==\s*false\s*\{\s*return",
    re.MULTILINE | re.IGNORECASE,
)


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source.decode("utf-8", errors="replace")

    ignored_result = _IGNORED_RESULT_RE.search(text)
    false_hook = _FALSE_HOOK_RE.search(text)
    proceed = _PROCEED_RE.search(text)
    if not (ignored_result and false_hook and proceed):
        return hits
    if _SAFE_RESULT_CHECK_RE.search(text):
        return hits

    first_line = text[: ignored_result.start()].count("\n") + 1
    first_snippet = text[ignored_result.start() : ignored_result.start() + 120].replace("\n", " ").strip()

    hits.append({
        "severity": "medium",
        "line": first_line,
        "col": 0,
        "snippet": first_snippet,
        "message": (
            f"{filepath}: pattern 'auction_stage_skipped_via_hook_returns_false' detected "
            "ignored failed auction-stage hook result lets execution "
            "advance anyway. "
            "Review for missing authorization / unsafe pattern."
        ),
    })
    return hits
