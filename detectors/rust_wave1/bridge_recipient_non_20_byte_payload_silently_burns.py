"""
bridge_recipient_non_20_byte_payload_silently_burns

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: bridge-recipient-non-20-byte-payload-silently-burns
Platform: solana
Source: phase7_rust_fixture_bridge_recipient_non_20_byte_payload_silently_burns.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

_INDICATOR_PATTERNS = ['validate_to_length\\s*\\([^)]*\\)\\s*->\\s*Result\\s*<\\s*\\(\\)\\s*,', 'if\\s+\\w+\\.len\\(\\)\\s*>\\s*20', 'recipient\\.len\\(\\)\\s*>\\s*20', 'payload\\.len\\(\\)\\s*>\\s*20', 'copy_from_slice.*min.*len.*20', 'addr\\[..copy_len\\]']

_COMPILED = [re.compile(p, re.MULTILINE | re.IGNORECASE) for p in _INDICATOR_PATTERNS]

# Minimum number of indicator patterns that must match to flag a hit.
_MIN_MATCH = 2


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source.decode("utf-8", errors="replace")

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
            f"{filepath}: pattern 'bridge_recipient_non_20_byte_payload_silently_burns' detected "
            f"({match_count}/{len(_COMPILED)} indicators matched). "
            "Review for missing authorization / unsafe pattern."
        ),
    })
    return hits
