"""
liquidation_seaport_pair_expects_fake_clearinghouse_nft_settlementtoken

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: liquidation-seaport-pair-expects-fake-clearinghouse-nft-settlementtoken
Platform: solana
Source: phase7_rust_fixture_liquidation_seaport_pair_expects_fake_clearinghouse_nft_settlementtoken.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

from _util import source_nocomment

_LIQUIDATION_ORDER_RE = re.compile(
    r"fn\s+validate_liquidation_order\s*\([^)]*order\s*:\s*&Order[^)]*\)"
    r"[\s\S]{0,900}?order\.offer\s*\[\s*0\s*\]\s*!=\s*self\.collateral_nft"
    r"[\s\S]{0,900}?order\.consideration\s*\[\s*0\s*\]\s*!=\s*self\.settlement_token",
    re.IGNORECASE,
)
_EXTRA_CONSIDERATION_GUARD_RE = re.compile(
    r"consideration\.len\s*\(\s*\)\s*>\s*1|consideration\s*\[\s*1\s*\.\.\s*\]|"
    r"authorized_clearing_nfts\.contains_key|unauthorized NFT",
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
            f"{filepath}: liquidation order validates only the first settlement "
            "consideration item and does not reject extra fake clearing-house NFTs."
        ),
    }


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source_nocomment(source)

    match = _LIQUIDATION_ORDER_RE.search(text)
    if not match:
        return hits
    if _EXTRA_CONSIDERATION_GUARD_RE.search(text):
        return hits

    hits.append(_hit(filepath, text, match))
    return hits
