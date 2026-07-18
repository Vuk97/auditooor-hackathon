"""
selldsreserve_no_slippage_protection

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: selldsreserve-no-slippage-protection
Platform: solana
Source: phase7_rust_fixture_selldsreserve_no_slippage_protection.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

_FN_RE = re.compile(
    r"_sell_ds_reserve\s*\(",
    re.MULTILINE | re.IGNORECASE,
)
_PARAMS_RE = re.compile(
    r"struct\s+\w*[Pp]arams\s*\{[^}]*amount_in[^}]*deadline[^}]*\}",
    re.MULTILINE | re.IGNORECASE,
)
_OUTPUT_RE = re.compile(
    r"get_amount_out\s*\([^)]*amount_in",
    re.MULTILINE | re.IGNORECASE,
)
_SAFE_SLIPPAGE_RE = re.compile(
    r"if\s+amount_out\s*<\s*params\s*\.\s*amount_out_min(?:imum)?",
    re.MULTILINE | re.IGNORECASE,
)


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source.decode("utf-8", errors="replace")

    fn_match = _FN_RE.search(text)
    params = _PARAMS_RE.search(text)
    output = _OUTPUT_RE.search(text)
    if not (fn_match and params and output):
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
            f"{filepath}: pattern 'selldsreserve_no_slippage_protection' detected "
            "DS reserve sale computes output without a visible "
            "minimum-output slippage guard. "
            "Review for missing authorization / unsafe pattern."
        ),
    })
    return hits
