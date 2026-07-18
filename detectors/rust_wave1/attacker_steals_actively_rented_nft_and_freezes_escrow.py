"""
attacker_steals_actively_rented_nft_and_freezes_escrow

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: attacker-steals-actively-rented-nft-and-freezes-escrow
Platform: solana
Source: phase7_rust_fixture_attacker_steals_actively_rented_nft_and_freezes_escrow.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

_INDICATOR_PATTERNS = ['fn\\s+(stop_rental|stopRental|cancel_rental|end_rental)', 'rentals?\\.(get|remove)', 'escrow\\.(remove|take)', 'nft_owner\\s*\\.\\s*insert\\s*\\(\\s*[^,]+\\s*,\\s*(self\\.)?caller', 'missing.*caller.*(renter|lender)|(renter|lender).*not.*check']

_COMPILED = [re.compile(p, re.MULTILINE | re.IGNORECASE) for p in _INDICATOR_PATTERNS]

# Minimum number of indicator patterns that must match to flag a hit.
_MIN_MATCH = 2


def _strip_line_comments(text: str) -> str:
    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source.decode("utf-8", errors="replace")
    code = _strip_line_comments(text)

    if re.search(r"self\.caller\s*!=\s*rental\.renter\s*&&\s*self\.caller\s*!=\s*rental\.lender", code):
        return hits

    match_count = sum(1 for c in _COMPILED if c.search(text))
    if match_count < _MIN_MATCH:
        return hits

    # Find a representative line for the first matching pattern
    first_line = 1
    first_snippet = ""
    for compiled, raw in zip(_COMPILED, _INDICATOR_PATTERNS):
        m = compiled.search(text)
        if m:
            first_line = text[: m.start()].count("\n") + 1
            first_snippet = text[m.start() : m.start() + 120].replace("\n", " ").strip()
            break

    hits.append({
        "severity": "medium",
        "line": first_line,
        "col": 0,
        "snippet": first_snippet,
        "message": (
            f"{filepath}: pattern 'attacker_steals_actively_rented_nft_and_freezes_escrow' detected "
            f"({match_count}/{len(_COMPILED)} indicators matched). "
            "Review for missing authorization / unsafe pattern."
        ),
    })
    return hits
