"""
onerc721received_never_fires_on_mint_transfer

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: onerc721received-never-fires-on-mint-transfer
Platform: solana
Source: phase7_rust_fixture_onerc721received_never_fires_on_mint_transfer.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

_SAFE_MINT_RE = re.compile(
    r"pub\s+fn\s+safe_mint\s*\(",
    re.MULTILINE | re.IGNORECASE,
)
_SAFE_TRANSFER_RE = re.compile(
    r"pub\s+fn\s+safe_transfer_from\s*\(",
    re.MULTILINE | re.IGNORECASE,
)
_CALLBACK_RE = re.compile(
    r"call_on_erc721_received\s*\(",
    re.MULTILINE | re.IGNORECASE,
)
_PLAIN_WRAP_RE = re.compile(
    r"safe_(?:mint|transfer_from)\s*\([\s\S]{0,400}?(?:self\.)?(?:mint|transfer(?:_from)?)\s*\(",
    re.MULTILINE | re.IGNORECASE,
)


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source.decode("utf-8", errors="replace")

    safe_mint = _SAFE_MINT_RE.search(text)
    safe_transfer = _SAFE_TRANSFER_RE.search(text)
    if not (safe_mint or safe_transfer):
        return hits
    if _CALLBACK_RE.search(text):
        return hits
    wrapped = _PLAIN_WRAP_RE.search(text)
    if not wrapped:
        return hits

    first_line = text[: wrapped.start()].count("\n") + 1
    first_snippet = text[wrapped.start() : wrapped.start() + 120].replace("\n", " ").strip()

    hits.append({
        "severity": "medium",
        "line": first_line,
        "col": 0,
        "snippet": first_snippet,
        "message": (
            f"{filepath}: pattern 'onerc721received_never_fires_on_mint_transfer' detected "
            "safe ERC721 wrapper delegates to mint/transfer without a "
            "visible receiver callback. "
            "Review for missing authorization / unsafe pattern."
        ),
    })
    return hits
