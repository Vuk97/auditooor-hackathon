"""
generic_bridge_facet_allows_arbitrary_target_call_steals_via_user_allowance

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: generic-bridge-facet-allows-arbitrary-target-call-steals-via-user-allowance
Platform: solana
Source: phase7_rust_fixture_generic_bridge_facet_allows_arbitrary_target_call_steals_via_user_allowance.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

from _util import source_nocomment

_GENERIC_SWAP_RE = re.compile(
    r"fn\s+swap_and_start_bridge_tokens_generic\s*\([^)]*target\s*:[^)]*call_data\s*:",
    re.IGNORECASE,
)
_FORWARD_USER_CALL_RE = re.compile(
    r"self\.execute_swap\s*\(\s*target\s*,\s*call_data(?:\s*,[^)]*)?\)|"
    r"fn\s+execute_swap\s*\([^)]*target\s*:[^)]*call_data\s*:",
    re.IGNORECASE,
)
_TARGET_GUARD_RE = re.compile(
    r"allowed_targets|allow_?list|white_?list|approved_targets|"
    r"is_valid_target|is_approved_target|contains\s*\(\s*&\s*target",
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
            f"{filepath}: generic bridge forwards a user-supplied target/calldata "
            "pair without an allowlist or target validation."
        ),
    }


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source_nocomment(source)

    match = _GENERIC_SWAP_RE.search(text)
    if not match:
        return hits
    if not _FORWARD_USER_CALL_RE.search(text):
        return hits
    if _TARGET_GUARD_RE.search(text):
        return hits

    hits.append(_hit(filepath, text, match))
    return hits
