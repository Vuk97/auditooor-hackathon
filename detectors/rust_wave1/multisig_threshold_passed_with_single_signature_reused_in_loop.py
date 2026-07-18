"""
multisig_threshold_passed_with_single_signature_reused_in_loop

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: multisig-threshold-passed-with-single-signature-reused-in-loop
Platform: solana
Source: phase7_rust_fixture_multisig_threshold_passed_with_single_signature_reused_in_loop.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

_LOOP_RE = re.compile(
    r"for\s+\w+\s+in\s+\w+",
    re.MULTILINE | re.IGNORECASE,
)
_AUTH_RE = re.compile(
    r"signers\s*\.\s*contains\s*\(",
    re.MULTILINE | re.IGNORECASE,
)
_INCREMENT_RE = re.compile(
    r"acquired_threshold\s*\+=\s*1|acquired_threshold\s*=\s*acquired_threshold\s*\+\s*1",
    re.MULTILINE | re.IGNORECASE,
)
_THRESHOLD_RE = re.compile(
    r"(?:self\s*\.\s*)?threshold\s*>=?\s*acquired_threshold|"
    r"acquired_threshold\s*>=?\s*(?:self\s*\.\s*)?threshold",
    re.MULTILINE | re.IGNORECASE,
)
_SAFE_DEDUP_RE = re.compile(
    r"!\s*seen_[A-Za-z0-9_]*\s*\.\s*insert\s*\([^)]*\)\s*\{\s*continue|"
    r"seen_[A-Za-z0-9_]*\s*\.\s*contains\s*\([^)]*\)\s*\{\s*continue",
    re.MULTILINE | re.IGNORECASE,
)


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source.decode("utf-8", errors="replace")

    if _SAFE_DEDUP_RE.search(text):
        return hits

    loop = _LOOP_RE.search(text)
    auth = _AUTH_RE.search(text)
    increment = _INCREMENT_RE.search(text)
    threshold = _THRESHOLD_RE.search(text)
    if not (loop and auth and increment and threshold):
        return hits

    first_line = text[: loop.start()].count("\n") + 1
    first_snippet = text[loop.start() : loop.start() + 120].replace("\n", " ").strip()

    hits.append({
        "severity": "medium",
        "line": first_line,
        "col": 0,
        "snippet": first_snippet,
        "message": (
            f"{filepath}: pattern 'multisig_threshold_passed_with_single_signature_reused_in_loop' detected "
            "threshold counter is advanced inside the signature loop "
            "without a visible duplicate-signer guard. "
            "Review for missing authorization / unsafe pattern."
        ),
    })
    return hits
