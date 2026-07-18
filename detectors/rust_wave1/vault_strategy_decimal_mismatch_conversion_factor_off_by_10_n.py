"""
vault_strategy_decimal_mismatch_conversion_factor_off_by_10_n

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: vault-strategy-decimal-mismatch-conversion-factor-off-by-10-n
Platform: solana
Source: phase7_rust_fixture_vault_strategy_decimal_mismatch_conversion_factor_off_by_10_n.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

from _util import source_nocomment

_STRATEGY_DECIMALS_RE = re.compile(r"strategy_decimals\s*:\s*u8|VAULT_DECIMALS\s*:\s*u8\s*=\s*18", re.IGNORECASE)
_UNSCALED_DEPOSIT_RE = re.compile(
    r"fn\s+deposit\s*\([^)]*strategy\s*:\s*&StrategyConfig[^)]*\)[\s\S]*?\{"
    r"[\s\S]{0,700}?if\s+self\.total_assets\s*==\s*0\s*\{[\s\S]{0,120}?assets"
    r"[\s\S]{0,700}?assets\s*\*\s*self\.total_shares\s*/\s*self\.total_assets",
    re.IGNORECASE,
)
_UNSCALED_WITHDRAW_RE = re.compile(
    r"fn\s+withdraw\s*\([^)]*strategy\s*:\s*&StrategyConfig[^)]*\)[\s\S]*?\{"
    r"[\s\S]{0,700}?shares\s*\*\s*self\.total_assets\s*/\s*self\.total_shares",
    re.IGNORECASE,
)
_SCALING_RE = re.compile(
    r"scale_to_strategy|scale_to_vault|scaled_assets|scaled_shares|"
    r"strategy\.strategy_decimals|10u128\.pow|decimals_diff",
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
            f"{filepath}: vault/strategy path accepts StrategyConfig decimals but "
            "uses unscaled asset/share formulas across mismatched decimal domains."
        ),
    }


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source_nocomment(source)

    if not _STRATEGY_DECIMALS_RE.search(text):
        return hits
    if _SCALING_RE.search(text):
        return hits
    match = _UNSCALED_DEPOSIT_RE.search(text) or _UNSCALED_WITHDRAW_RE.search(text)
    if not match:
        return hits

    hits.append(_hit(filepath, text, match))
    return hits
