"""
f_63_64_gas_rule_bypass_bricks_l1_withdrawal

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: f-63-64-gas-rule-bypass-bricks-l1-withdrawal
Platform: solana
Source: phase7_rust_fixture_f_63_64_gas_rule_bypass_bricks_l1_withdrawal.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

from _util import source_nocomment

_DIRECT_GAS_FORWARD_RE = re.compile(
    r"fn\s+finalize_\w*withdrawal\s*\([^)]*\)[\s\S]*?\{[\s\S]{0,900}?"
    r"execute_callback\s*\([^;]*withdrawal\.gas_limit",
    re.IGNORECASE,
)
_RESERVE_OR_CAP_RE = re.compile(
    r"min_gas_reserve|remaining_gas|effective_gas|saturating_add|std::cmp::min|"
    r"\.min\s*\(|gas_needed|available_gas",
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
            f"{filepath}: withdrawal finalization forwards withdrawal.gas_limit "
            "directly to a callback without a gas reserve/cap for post-call work."
        ),
    }


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source_nocomment(source)

    match = _DIRECT_GAS_FORWARD_RE.search(text)
    if not match:
        return hits
    if _RESERVE_OR_CAP_RE.search(text):
        return hits

    hits.append(_hit(filepath, text, match))
    return hits
