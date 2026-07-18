"""
nativetokenlimitmodule_bypassed_via_executefromexecutor

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: nativetokenlimitmodule-bypassed-via-executefromexecutor
Platform: solana
Source: phase7_rust_fixture_nativetokenlimitmodule_bypassed_via_executefromexecutor.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

_EXECUTOR_RE = re.compile(
    r"fn\s+execute_from_executor\s*\(",
    re.MULTILINE | re.IGNORECASE,
)
_MODULE_RE = re.compile(
    r"NativeTokenLimitModule",
    re.MULTILINE | re.IGNORECASE,
)
_SAFE_TRACK_RE = re.compile(
    r"execute_from_executor[\s\S]{0,400}?(?:track_spend|record_spend)\s*\(",
    re.MULTILINE | re.IGNORECASE,
)


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source.decode("utf-8", errors="replace")

    executor = _EXECUTOR_RE.search(text)
    module = _MODULE_RE.search(text)
    if not (executor and module):
        return hits
    if _SAFE_TRACK_RE.search(text):
        return hits

    first_line = text[: executor.start()].count("\n") + 1
    first_snippet = text[executor.start() : executor.start() + 120].replace("\n", " ").strip()

    hits.append({
        "severity": "medium",
        "line": first_line,
        "col": 0,
        "snippet": first_snippet,
        "message": (
            f"{filepath}: pattern 'nativetokenlimitmodule_bypassed_via_executefromexecutor' detected "
            "executor entrypoint exists on the native-token limit module "
            "without a visible spend-tracking call. "
            "Review for missing authorization / unsafe pattern."
        ),
    })
    return hits
