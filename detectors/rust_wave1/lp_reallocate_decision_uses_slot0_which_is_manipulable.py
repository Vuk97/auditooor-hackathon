"""
lp_reallocate_decision_uses_slot0_which_is_manipulable

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: lp-reallocate-decision-uses-slot0-which-is-manipulable
Platform: solana
Source: phase7_rust_fixture_lp_reallocate_decision_uses_slot0_which_is_manipulable.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

_INDICATOR_PATTERNS = ['pool\\.slot0\\.(tick|sqrt_price_x96|sqrtPriceX96)', 'self\\.pool\\.slot0\\.(tick|sqrt_price_x96|sqrtPriceX96)', 'slot0\\.(tick|sqrtPriceX96).*reallocat', 'reallocat.*slot0\\.(tick|sqrtPriceX96)', '\\.slot0\\b.*tick\\b.*rebalanc', 'rebalanc.*\\.slot0\\b.*tick\\b']

_COMPILED = [re.compile(p, re.MULTILINE | re.IGNORECASE) for p in _INDICATOR_PATTERNS]

# Minimum number of indicator patterns that must match to flag a hit.
_MIN_MATCH = 2


def _strip_line_comments(text: str) -> str:
    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source.decode("utf-8", errors="replace")
    code = _strip_line_comments(text)

    if "fn get_twap_tick" in code and re.search(r"let\s+twap_tick\s*=\s*self\.get_twap_tick\s*\(\s*\)", code):
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
            f"{filepath}: pattern 'lp_reallocate_decision_uses_slot0_which_is_manipulable' detected "
            f"({match_count}/{len(_COMPILED)} indicators matched). "
            "Review for missing authorization / unsafe pattern."
        ),
    })
    return hits
