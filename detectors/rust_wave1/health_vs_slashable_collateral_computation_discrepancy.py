"""
health_vs_slashable_collateral_computation_discrepancy

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: health-vs-slashable-collateral-computation-discrepancy
Platform: solana
Source: phase7_rust_fixture_health_vs_slashable_collateral_computation_discrepancy.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

from _util import source_nocomment

_HEALTH_USES_WEIGHT = re.compile(
    r"fn\s+\w*health\w*\s*\([^)]*\)\s*->[^{]*\{[\s\S]*?\.weight\b",
    re.MULTILINE | re.IGNORECASE,
)
_SLASHABLE_FN = re.compile(
    r"fn\s+\w*slashable\w*\s*\([^)]*\)\s*->[^{]*\{(?P<body>[\s\S]*?)\n\s*\}",
    re.MULTILINE | re.IGNORECASE,
)

_INDICATOR_PATTERNS = [_HEALTH_USES_WEIGHT.pattern, _SLASHABLE_FN.pattern]


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source_nocomment(source)

    if not _HEALTH_USES_WEIGHT.search(text):
        return hits
    slashable = _SLASHABLE_FN.search(text)
    if not slashable:
        return hits
    slashable_body = slashable.group("body")
    if ".amount" not in slashable_body or ".weight" in slashable_body:
        return hits

    # Find a representative line for the first matching pattern
    first_line = text[: slashable.start()].count("\n") + 1
    first_snippet = text[slashable.start() : slashable.start() + 120].replace("\n", " ").strip()

    hits.append({
        "severity": "medium",
        "line": first_line,
        "col": 0,
        "snippet": first_snippet,
        "message": (
            f"{filepath}: pattern 'health_vs_slashable_collateral_computation_discrepancy' detected "
            "health calculation weights collateral but slashable collateral uses raw amounts."
        ),
    })
    return hits
