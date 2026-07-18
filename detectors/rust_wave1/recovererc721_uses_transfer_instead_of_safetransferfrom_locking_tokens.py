"""
recovererc721_uses_transfer_instead_of_safetransferfrom_locking_tokens

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: recovererc721-uses-transfer-instead-of-safetransferfrom-locking-tokens
Platform: solana
Source: phase7_rust_fixture_recovererc721_uses_transfer_instead_of_safetransferfrom_locking_tokens.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

_INDICATOR_PATTERNS = ['fn\\s+recover_erc721|fn\\s+recoverERC721|fn\\s+recover.*721', '\\.transfer\\s*\\([^,]+,\\s*[^,]+\\)(?!\\s*//.*safe)', 'recover.*erc721.*transfer(?!.*safe)']

_COMPILED = [re.compile(p, re.MULTILINE | re.IGNORECASE) for p in _INDICATOR_PATTERNS]

# Minimum number of indicator patterns that must match to flag a hit.
_MIN_MATCH = 2


def _strip_line_comments(text: str) -> str:
    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source.decode("utf-8", errors="replace")
    code = _strip_line_comments(text)

    if re.search(r"fn\s+recover_erc721\b[\s\S]*?safe_transfer_from\s*\(", code):
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
            f"{filepath}: pattern 'recovererc721_uses_transfer_instead_of_safetransferfrom_locking_tokens' detected "
            f"({match_count}/{len(_COMPILED)} indicators matched). "
            "Review for missing authorization / unsafe pattern."
        ),
    })
    return hits
