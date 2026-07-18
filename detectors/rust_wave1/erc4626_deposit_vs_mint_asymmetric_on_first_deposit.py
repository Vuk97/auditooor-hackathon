"""
erc4626_deposit_vs_mint_asymmetric_on_first_deposit

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: erc4626-deposit-vs-mint-asymmetric-on-first-deposit
Platform: solana
Source: phase7_rust_fixture_erc4626_deposit_vs_mint_asymmetric_on_first_deposit.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

from _util import source_nocomment

_DEPOSIT_CONVERT_RE = re.compile(
    r"fn\s+deposit\s*\([^)]*\)\s*->[\s\S]*?\{[\s\S]*?convert_to_shares\s*\(",
    re.IGNORECASE,
)
_MINT_PREVIEW_RE = re.compile(
    r"fn\s+mint\s*\([^)]*\)\s*->[\s\S]*?\{[\s\S]*?preview_mint\s*\(",
    re.IGNORECASE,
)
_ASYM_PREVIEW_RE = re.compile(
    r"fn\s+preview_mint\s*\([^)]*\)\s*->[\s\S]*?\{[\s\S]*?"
    r"if\s+self\.total_assets\s*==\s*0\s*\|\|\s*self\.total_shares\s*==\s*0\s*\{"
    r"[\s\S]{0,180}?(?:max\s*\(\s*shares|round_?up|ceil|shares\s*\+|saturating_add)",
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
            f"{filepath}: ERC4626 deposit uses convert_to_shares while mint uses "
            "asymmetric first-deposit preview_mint logic."
        ),
    }


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source_nocomment(source)

    if not _DEPOSIT_CONVERT_RE.search(text):
        return hits
    if not _MINT_PREVIEW_RE.search(text):
        return hits
    asym_match = _ASYM_PREVIEW_RE.search(text)
    if not asym_match:
        return hits

    hits.append(_hit(filepath, text, asym_match))
    return hits
