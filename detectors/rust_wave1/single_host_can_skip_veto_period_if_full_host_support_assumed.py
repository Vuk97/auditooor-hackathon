"""
single_host_can_skip_veto_period_if_full_host_support_assumed

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: single-host-can-skip-veto-period-if-full-host-support-assumed
Platform: solana
Source: phase7_rust_fixture_single_host_can_skip_veto_period_if_full_host_support_assumed.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

_SUPPORT_FN_RE = re.compile(
    r"has_full_host_support|all_hosts_support|skip_veto.*delay|full.*host.*support",
    re.MULTILINE | re.IGNORECASE,
)
_PARTIAL_ALL_RE = re.compile(
    r"votes\s*\.\s*(?:values|iter)\s*\(\s*\)\s*\.\s*all\s*\(",
    re.MULTILINE | re.IGNORECASE,
)
_SAFE_FULL_COUNT_RE = re.compile(
    r"votes\s*\.\s*len\s*\(\s*\)\s*(?:==|!=)\s*self\s*\.\s*hosts\s*\.\s*len\s*\(\s*\)",
    re.MULTILINE | re.IGNORECASE,
)
_SAFE_HOST_LOOKUP_RE = re.compile(
    r"self\s*\.\s*hosts\s*\.\s*iter\s*\(\s*\)\s*\.\s*all\s*\(|votes\s*\.\s*get\s*\(",
    re.MULTILINE | re.IGNORECASE,
)


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source.decode("utf-8", errors="replace")

    if _SAFE_FULL_COUNT_RE.search(text) and _SAFE_HOST_LOOKUP_RE.search(text):
        return hits

    support_fn = _SUPPORT_FN_RE.search(text)
    partial_all = _PARTIAL_ALL_RE.search(text)
    if not (support_fn and partial_all):
        return hits

    first_line = text[: partial_all.start()].count("\n") + 1
    first_snippet = text[partial_all.start() : partial_all.start() + 120].replace("\n", " ").strip()

    hits.append({
        "severity": "medium",
        "line": first_line,
        "col": 0,
        "snippet": first_snippet,
        "message": (
            f"{filepath}: pattern 'single_host_can_skip_veto_period_if_full_host_support_assumed' detected "
            "full-host support is inferred from recorded YES votes "
            "without proving every host voted. "
            "Review for missing authorization / unsafe pattern."
        ),
    })
    return hits
