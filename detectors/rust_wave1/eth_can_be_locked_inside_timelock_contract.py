"""
eth_can_be_locked_inside_timelock_contract

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: eth-can-be-locked-inside-timelock-contract
Platform: solana
Source: phase7_rust_fixture_eth_can_be_locked_inside_timelock_contract.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

_EXECUTE_RE = re.compile(
    r"fn\s+execute(?:_transaction)?\s*\([\s\S]*?(?:value|received_value)\s*:\s*(u64|u128|U256|Balance)",
    re.MULTILINE | re.IGNORECASE,
)
_REQUIRED_VALUE_RE = re.compile(
    r"let\s+required\s*=\s*tx\s*\.\s*value|received_value\s*<\s*required",
    re.MULTILINE | re.IGNORECASE,
)
_TRANSFER_RE = re.compile(
    r"transfer_(?:native|eth)\s*\([^)]*(?:required|value)",
    re.MULTILINE | re.IGNORECASE,
)
_SAFE_REFUND_RE = re.compile(
    r"refund\s*=|refund_stuck_funds|saturating_sub\s*\(\s*required\s*\)|"
    r"transfer_(?:native|eth)\s*\([^)]*refund",
    re.MULTILINE | re.IGNORECASE,
)


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source.decode("utf-8", errors="replace")

    if _SAFE_REFUND_RE.search(text):
        return hits

    execute = _EXECUTE_RE.search(text)
    required = _REQUIRED_VALUE_RE.search(text)
    transfer = _TRANSFER_RE.search(text)
    if not (execute and required and transfer):
        return hits

    first_line = text[: execute.start()].count("\n") + 1
    first_snippet = text[execute.start() : execute.start() + 120].replace("\n", " ").strip()

    hits.append({
        "severity": "medium",
        "line": first_line,
        "col": 0,
        "snippet": first_snippet,
        "message": (
            f"{filepath}: pattern 'eth_can_be_locked_inside_timelock_contract' detected "
            "timelock execute path forwards the scheduled value without "
            "a visible surplus refund path. "
            "Review for missing authorization / unsafe pattern."
        ),
    })
    return hits
