"""
withdrawfee_has_no_claimed_flag_drains_fee_pool_n_times

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: withdrawfee-has-no-claimed-flag-drains-fee-pool-n-times
Platform: solana
Source: phase7_rust_fixture_withdrawfee_has_no_claimed_flag_drains_fee_pool_n_times.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

from _util import source_nocomment

_WITHDRAW_FEE = re.compile(
    r"fn\s+withdraw_fee\s*\([^)]*&mut\s+self[^)]*\)[^{]*\{(?P<body>[\s\S]*?)\n\s*\}",
    re.MULTILINE | re.IGNORECASE,
)
_INDICATOR_PATTERNS = [_WITHDRAW_FEE.pattern]


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source_nocomment(source)

    match = _WITHDRAW_FEE.search(text)
    if not match:
        return hits
    body = match.group("body")
    if "fee_per_participant" not in body or "checked_mul" not in body:
        return hits
    if re.search(r"fee_withdrawn\s*(?:=|\}|\)|\])", body) or re.search(r"if\s+self\.fee_withdrawn\b", body):
        return hits

    first_line = text[: match.start()].count("\n") + 1
    first_snippet = text[match.start() : match.start() + 120].replace("\n", " ").strip()

    hits.append({
        "severity": "medium",
        "line": first_line,
        "col": 0,
        "snippet": first_snippet,
        "message": (
            f"{filepath}: pattern 'withdrawfee_has_no_claimed_flag_drains_fee_pool_n_times' detected "
            "withdraw_fee computes a participant fee without checking or setting a claimed flag."
        ),
    })
    return hits
