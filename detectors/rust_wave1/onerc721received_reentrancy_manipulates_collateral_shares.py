"""
onerc721received_reentrancy_manipulates_collateral_shares

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: onerc721received-reentrancy-manipulates-collateral-shares
Platform: solana
Source: phase7_rust_fixture_onerc721received_reentrancy_manipulates_collateral_shares.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

from _util import source_nocomment

_PARTIAL_SHARE_UPDATE_RE = re.compile(
    r"fn\s+(?:on_erc721_received|onERC721Received)\s*\([^)]*\)[\s\S]*?\{"
    r"[\s\S]{0,700}?config\.shares\s*=\s*shares\s*;"
    r"[\s\S]{0,700}?safe_transfer_from\s*\("
    r"[\s\S]{0,700}?config\.total_shares\s*=\s*config\.total_shares\s*\+\s*shares",
    re.IGNORECASE,
)
_REENTRANCY_GUARD_RE = re.compile(r"non_reentrant|reentrancy_guard|reentrancy_lock|mutex", re.IGNORECASE)


def _hit(filepath: str, text: str, match: re.Match[str]):
    line = text[: match.start()].count("\n") + 1
    snippet = text[match.start() : match.start() + 120].replace("\n", " ").strip()
    return {
        "severity": "medium",
        "line": line,
        "col": 0,
        "snippet": snippet,
        "message": (
            f"{filepath}: on_erc721_received performs a partial share update, "
            "then makes an external safe_transfer_from before finalizing total_shares."
        ),
    }


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source_nocomment(source)

    if _REENTRANCY_GUARD_RE.search(text):
        return hits
    match = _PARTIAL_SHARE_UPDATE_RE.search(text)
    if not match:
        return hits

    hits.append(_hit(filepath, text, match))
    return hits
