"""
public_servicenft_updateimpact_bypasses_governance_only_intent

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: public-servicenft-updateimpact-bypasses-governance-only-intent
Platform: solana
Source: phase7_rust_fixture_public_servicenft_updateimpact_bypasses_governance_only_intent.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

_INDICATOR_PATTERNS = ['pub\\s+fn\\s+(update_impact|updateImpact)', 'fn\\s+update_impact.*\\{[^}]*(?:(?!assert_governance|require_governance|only_governance|check_governance)[^}])*(?:cascade|reward|impact)', '(?s)///?\\s*(?:INTENDED|intended|only|ONLY).*(?:governance|GOVERNANCE).*\\n\\s*pub\\s+fn\\s+(?:update_impact|updateImpact)']

_COMPILED = [re.compile(p, re.MULTILINE | re.IGNORECASE) for p in _INDICATOR_PATTERNS]

# Minimum number of indicator patterns that must match to flag a hit.
_MIN_MATCH = 2


def _strip_line_comments(text: str) -> str:
    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source.decode("utf-8", errors="replace")
    code = _strip_line_comments(text)

    if re.search(r"fn\s+update_impact\b[\s\S]*?assert_governance_caller\s*\(\s*\)", code):
        return hits

    match_count = sum(1 for c in _COMPILED if c.search(text))
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
            f"{filepath}: pattern 'public_servicenft_updateimpact_bypasses_governance_only_intent' detected "
            f"({match_count}/{len(_COMPILED)} indicators matched). "
            "Review for missing authorization / unsafe pattern."
        ),
    })
    return hits
