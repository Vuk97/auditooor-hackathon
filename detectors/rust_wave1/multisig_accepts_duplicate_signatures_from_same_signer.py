"""
multisig_accepts_duplicate_signatures_from_same_signer

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: multisig-accepts-duplicate-signatures-from-same-signer
Platform: solana
Source: phase7_rust_fixture_multisig_accepts_duplicate_signatures_from_same_signer.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

_LOOP_RE = re.compile(
    r"for\s*\(\s*[^,]+,\s*[^)]+\)\s*in\s+signatures",
    re.MULTILINE | re.IGNORECASE,
)
_AUTH_RE = re.compile(
    r"\.contains\s*\(\s*.*(?:address|addr|signer|pubkey|key)",
    re.MULTILINE | re.IGNORECASE,
)
_INCREMENT_RE = re.compile(
    r"valid_count\s*\+=\s*1|valid_count\s*=\s*valid_count\s*\+\s*1",
    re.MULTILINE | re.IGNORECASE,
)
_THRESHOLD_RE = re.compile(
    r"(?:self\s*\.\s*)?threshold\s*>=?\s*valid_count|"
    r"valid_count\s*>=?\s*(?:self\s*\.\s*)?threshold",
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
            f"{filepath}: pattern 'multisig_accepts_duplicate_signatures_from_same_signer' detected "
            "signature loop counts approvals toward threshold without "
            "a visible deduplication guard. "
            "Review for missing authorization / unsafe pattern."
        ),
    })
    return hits
