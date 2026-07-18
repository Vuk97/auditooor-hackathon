"""
liquidator_seizes_collateral_from_solvent_borrower_due_to_ema_lag

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: liquidator-seizes-collateral-from-solvent-borrower-due-to-ema-lag
Platform: solana
Source: phase7_rust_fixture_liquidator_seizes_collateral_from_solvent_borrower_due_to_ema_lag.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

_INDICATOR_PATTERNS = ['\\.ema\\b.*liquidat|liquidat.*\\.ema\\b', 'ema.*health_ratio|health_ratio.*ema', 'collateral_value.*ema|ema.*collateral_value', 'check_solvent.*spot.*can_liquidate.*ema|spot.*solvent.*ema.*liquidat']

_COMPILED = [re.compile(p, re.MULTILINE | re.IGNORECASE) for p in _INDICATOR_PATTERNS]

# Minimum number of indicator patterns that must match to flag a hit.
_MIN_MATCH = 2


def _strip_line_comments(text: str) -> str:
    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source.decode("utf-8", errors="replace")
    code = _strip_line_comments(text)

    match_count = sum(1 for c in _COMPILED if c.search(text))
    if match_count < _MIN_MATCH:
        solvent = re.search(r"fn\s+check_solvent\b[\s\S]*?\{(?P<body>[\s\S]*?)\n\s*\}", code)
        liquidate = re.search(r"fn\s+can_liquidate\b[\s\S]*?\{(?P<body>[\s\S]*?)\n\s*\}", code)
        if (
            solvent
            and liquidate
            and ".spot" in solvent.group("body")
            and ".ema" in liquidate.group("body")
        ):
            match_count = _MIN_MATCH
    if match_count < _MIN_MATCH:
        return hits

    # Find a representative line for the first matching pattern
    first_line = 1
    first_snippet = ""
    for compiled, raw in zip(_COMPILED, _INDICATOR_PATTERNS):
        m = compiled.search(text)
        if m:
            first_line = text[: m.start()].count("\n") + 1
            first_snippet = text[m.start() : m.start() + 120].replace("\n", " ").strip()
            break

    hits.append({
        "severity": "medium",
        "line": first_line,
        "col": 0,
        "snippet": first_snippet,
        "message": (
            f"{filepath}: pattern 'liquidator_seizes_collateral_from_solvent_borrower_due_to_ema_lag' detected "
            f"({match_count}/{len(_COMPILED)} indicators matched). "
            "Review for missing authorization / unsafe pattern."
        ),
    })
    return hits
