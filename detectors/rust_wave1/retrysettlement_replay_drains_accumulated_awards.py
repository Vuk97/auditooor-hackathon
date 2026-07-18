"""
retrysettlement_replay_drains_accumulated_awards

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: retrysettlement-replay-drains-accumulated-awards
Platform: solana
Source: phase7_rust_fixture_retrysettlement_replay_drains_accumulated_awards.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

_INDICATOR_PATTERNS = ['fn\\s+retry\\w*\\s*\\(', '\\.clone\\(\\).*executed\\s*=\\s*false', 'settlement.*executed\\s*=\\s*true.*retry', 'nonce_counter.*=.*nonce_counter\\s*\\+\\s*1']

_COMPILED = [re.compile(p, re.MULTILINE | re.IGNORECASE) for p in _INDICATOR_PATTERNS]

# Minimum number of indicator patterns that must match to flag a hit.
_MIN_MATCH = 2


def _strip_line_comments(text: str) -> str:
    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source.decode("utf-8", errors="replace")
    code = _strip_line_comments(text)

    match_count = sum(1 for c in _COMPILED if c.search(text))
    if match_count < _MIN_MATCH and re.search(
        r"fn\s+retry_settlement\b[\s\S]*?old\.clone\s*\(\s*\)"
        r"[\s\S]*?executed\s*=\s*false",
        code,
        re.IGNORECASE,
    ) and "remove(&old_nonce)" not in code:
        match_count = _MIN_MATCH
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
            f"{filepath}: pattern 'retrysettlement_replay_drains_accumulated_awards' detected "
            f"({match_count}/{len(_COMPILED)} indicators matched). "
            "Review for missing authorization / unsafe pattern."
        ),
    })
    return hits
