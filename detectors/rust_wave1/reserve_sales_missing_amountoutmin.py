"""
reserve_sales_missing_amountoutmin

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: reserve-sales-missing-amountoutmin
Platform: solana
Source: phase7_rust_fixture_reserve_sales_missing_amountoutmin.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

_FN_RE = re.compile(
    r"fn\s+(sell_ds_reserve|_selldsreserve|sell.*ds.*reserve)",
    re.MULTILINE | re.IGNORECASE,
)
_OUTPUT_RE = re.compile(
    r"calculate_output\s*\(",
    re.MULTILINE | re.IGNORECASE,
)
_RETURN_RE = re.compile(
    r"Ok\s*\(\s*amount_out\s*\)",
    re.MULTILINE | re.IGNORECASE,
)
_SAFE_SLIPPAGE_RE = re.compile(
    r"if\s+amount_out\s*<\s*(?:params\s*\.\s*)?amount_out_min|"
    r"if\s+amount_out\s*<\s*[^;]*amount_out_min",
    re.MULTILINE | re.IGNORECASE,
)


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source.decode("utf-8", errors="replace")

    fn_match = _FN_RE.search(text)
    output = _OUTPUT_RE.search(text)
    ret = _RETURN_RE.search(text)
    if not (fn_match and output and ret):
        return hits
    if _SAFE_SLIPPAGE_RE.search(text):
        return hits

    first_line = text[: fn_match.start()].count("\n") + 1
    first_snippet = text[fn_match.start() : fn_match.start() + 120].replace("\n", " ").strip()

    hits.append({
        "severity": "medium",
        "line": first_line,
        "col": 0,
        "snippet": first_snippet,
        "message": (
            f"{filepath}: pattern 'reserve_sales_missing_amountoutmin' detected "
            "reserve sale computes output and returns it without a "
            "visible minimum-output slippage check. "
            "Review for missing authorization / unsafe pattern."
        ),
    })
    return hits
