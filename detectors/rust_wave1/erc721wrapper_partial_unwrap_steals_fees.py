"""
erc721wrapper_partial_unwrap_steals_fees

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: erc721wrapper-partial-unwrap-steals-fees
Platform: solana
Source: phase7_rust_fixture_erc721wrapper_partial_unwrap_steals_fees.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

from _util import source_nocomment

_PARTIAL_UNWRAP_CLONE_RE = re.compile(
    r"fn\s+(?:unwrap_partial|partial_unwrap)\s*\([^)]*amount[^)]*\)[\s\S]*?\{"
    r"[\s\S]{0,900}?position\.clone\s*\(\)[\s\S]{0,500}?"
    r"(?:new_position\.)?liquidity\s*-=\s*amount",
    re.IGNORECASE,
)
_FEE_ACCOUNTING_RE = re.compile(r"fee_growth_inside|collect_fees|claim_fees|settle_fees", re.IGNORECASE)
_FEE_SETTLE_RE = re.compile(r"(?:collect_fees|claim_fees|settle_fees)\s*\(", re.IGNORECASE)
_NEXT_FN_RE = re.compile(r"\n\s*fn\s+")


def _hit(filepath: str, text: str, match: re.Match[str]):
    line = text[: match.start()].count("\n") + 1
    snippet = text[match.start() : match.start() + 120].replace("\n", " ").strip()
    return {
        "severity": "medium",
        "line": line,
        "col": 0,
        "snippet": snippet,
        "message": (
            f"{filepath}: partial unwrap clones a fee-bearing position and reduces "
            "liquidity without settling accrued fees first."
        ),
    }


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source_nocomment(source)

    if not _FEE_ACCOUNTING_RE.search(text):
        return hits
    match = _PARTIAL_UNWRAP_CLONE_RE.search(text)
    if not match:
        return hits
    next_fn = _NEXT_FN_RE.search(text, match.end())
    partial_body = text[match.start() : next_fn.start() if next_fn else len(text)]
    if _FEE_SETTLE_RE.search(partial_body):
        return hits

    hits.append(_hit(filepath, text, match))
    return hits
