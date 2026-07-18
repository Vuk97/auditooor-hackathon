"""
incorrect_royalty_distribution_truncation_siphon

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: incorrect-royalty-distribution-truncation-siphon
Platform: solana
Source: phase7_rust_fixture_incorrect_royalty_distribution_truncation_siphon.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

from _util import source_nocomment

_PER_RECIPIENT_TRUNC_RE = re.compile(
    r"for\s*\([^)]*(?:addr|recipient)[^)]*,\s*bp[^)]*\)\s+in\s+&self\.recipients"
    r"[\s\S]{0,400}?self\.total_amount\s*\*\s*bp\s*\)\s*/\s*total_basis",
    re.IGNORECASE,
)
_CALLER_RESIDUAL_SIPHON_RE = re.compile(
    r"let\s+residual\s*=\s*self\.total_amount\s*-\s*total_distributed"
    r"[\s\S]{0,260}?balances\.entry\s*\(\s*caller\s*\)"
    r"\.or_insert\s*\(\s*0\s*\)\s*\+=\s*residual",
    re.IGNORECASE,
)
_DUST_GUARD_RE = re.compile(
    r"if\s+i\s*==\s*self\.recipients\.len\s*\(\s*\)\s*-\s*1|"
    r"let\s+dust\s*=|let\s+remainder\s*=|distribute_fair|scale_to",
    re.IGNORECASE,
)


def _hit(filepath: str, text: str, match: re.Match[str]):
    line = text[: match.start()].count("\n") + 1
    snippet = text[match.start() : match.start() + 120].replace("\n", " ").strip()
    return {
        "severity": "medium",
        "line": line,
        "col": 0,
        "snippet": snippet,
        "message": (
            f"{filepath}: royalty distribution truncates per-recipient shares "
            "and lets the caller receive the residual dust."
        ),
    }


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source_nocomment(source)

    if _DUST_GUARD_RE.search(text):
        return hits
    if not _PER_RECIPIENT_TRUNC_RE.search(text):
        return hits
    match = _CALLER_RESIDUAL_SIPHON_RE.search(text)
    if not match:
        return hits

    hits.append(_hit(filepath, text, match))
    return hits
