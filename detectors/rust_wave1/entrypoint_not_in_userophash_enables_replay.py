"""
entrypoint_not_in_userophash_enables_replay

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: entrypoint-not-in-userophash-enables-replay
Platform: solana
Source: phase7_rust_fixture_entrypoint_not_in_userophash_enables_replay.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

_INDICATOR_PATTERNS = ['hash_user_op.*chain_id.*(?!entry_point).*finalize', 'fn\\s+hash_(?:user_?op|operation)\\s*\\([^)]*\\)\\s*->\\s*B256\\s*\\{[^}]*chain_id[^}]*(?:finalize|return)(?!.*entry_point)', 'update\\s*\\(\\s*self\\.chain_id\\s*\\)[^;]*;\\s*(?:[^u]*update[^;]*;)*\\s*[^u]*finalize']

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
    if match_count < _MIN_MATCH:
        hash_fn = re.search(
            r"fn\s+hash_user_op\s*\([^)]*\)\s*->\s*B256\s*\{(?P<body>[\s\S]*?)\n\s*\}",
            code,
            re.IGNORECASE,
        )
        if hash_fn:
            body = hash_fn.group("body")
            if (
                "self.chain_id" in body
                and "finalize()" in body
                and not re.search(r"update\s*\(\s*self\.entry_point\.as_slice\s*\(\s*\)\s*\)", body)
            ):
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
            f"{filepath}: pattern 'entrypoint_not_in_userophash_enables_replay' detected "
            f"({match_count}/{len(_COMPILED)} indicators matched). "
            "Review for missing authorization / unsafe pattern."
        ),
    })
    return hits
