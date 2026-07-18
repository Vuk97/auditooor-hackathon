"""
incentivizederc20_recursive_liquidity_reward_steal

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: incentivizederc20-recursive-liquidity-reward-steal
Platform: solana
Source: phase7_rust_fixture_incentivizederc20_recursive_liquidity_reward_steal.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

from _util import source_nocomment

_DEPOSIT_COLLATERAL_RE = re.compile(
    r"fn\s+deposit_collateral\s*\([^)]*\btoken\s*:\s*TokenId[^)]*\bamount\s*:\s*u64",
    re.IGNORECASE,
)
_REWARD_RAW_BALANCE_RE = re.compile(
    r"fn\s+claim_rewards\s*\([^)]*\)[\s\S]*?\{[\s\S]{0,900}?"
    r"position\.balance\s*\*\s*pool\.reward_per_token_stored\s*(?:\n|\})",
    re.IGNORECASE,
)
_RECURSION_GUARD_RE = re.compile(
    r"source_position|underlying_source|yield_bearing_tokens|is_yield_bearing|"
    r"tracked_deposit|deposit_principal|recursive deposit blocked",
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
            f"{filepath}: collateral deposit/reward accounting lacks source "
            "tracking and computes rewards from raw recursive balances."
        ),
    }


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source_nocomment(source)

    match = _DEPOSIT_COLLATERAL_RE.search(text)
    if not match:
        return hits
    if not _REWARD_RAW_BALANCE_RE.search(text):
        return hits
    if _RECURSION_GUARD_RE.search(text):
        return hits

    hits.append(_hit(filepath, text, match))
    return hits
