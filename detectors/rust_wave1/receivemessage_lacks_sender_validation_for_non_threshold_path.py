"""
receivemessage_lacks_sender_validation_for_non_threshold_path

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: receivemessage-lacks-sender-validation-for-non-threshold-path
Platform: solana
Source: phase7_rust_fixture_receivemessage_lacks_sender_validation_for_non_threshold_path.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

_INDICATOR_PATTERNS = ['receive_message.*threshold\\s*==\\s*1', 'if\\s+.*threshold\\s*==\\s*1\\s*\\{[^}]*authorized[^}]*\\}\\s*else']

_COMPILED = [re.compile(p, re.MULTILINE | re.IGNORECASE) for p in _INDICATOR_PATTERNS]

# Minimum number of indicator patterns that must match to flag a hit.
_MIN_MATCH = 1


def _strip_line_comments(text: str) -> str:
    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source.decode("utf-8", errors="replace")
    code = _strip_line_comments(text)

    match_count = sum(1 for c in _COMPILED if c.search(text))
    if match_count < _MIN_MATCH:
        body_match = re.search(r"fn\s+receive_message\b[\s\S]*?\{(?P<body>[\s\S]*?)\n\s*\}", code)
        if body_match:
            body = body_match.group("body")
            threshold_pos = body.find("threshold == 1")
            auth_pos = body.find("authorized_senders")
            if threshold_pos != -1 and auth_pos != -1 and threshold_pos < auth_pos:
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
            f"{filepath}: pattern 'receivemessage_lacks_sender_validation_for_non_threshold_path' detected "
            f"({match_count}/{len(_COMPILED)} indicators matched). "
            "Review for missing authorization / unsafe pattern."
        ),
    })
    return hits
