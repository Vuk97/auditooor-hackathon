"""
lientoken_buyoutlien_skips_vault_signature_validation

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: lientoken-buyoutlien-skips-vault-signature-validation
Platform: solana
Source: phase7_rust_fixture_lientoken_buyoutlien_skips_vault_signature_validation.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

_LIENTOKEN_BUYOUT_RE = re.compile(
    r"impl(?:<[^>]+>)?\s+LienToken(?:<[^>]+>)?\s*\{[\s\S]*?"
    r"pub\s+fn\s+buyout_lien\s*\([^)]*\)\s*->\s*Result\s*<\s*\(\)\s*,[\s\S]*?\{"
    r"(?P<body>[\s\S]*?)(?=\n\s*pub\s+fn|\n\s*}\s*$)",
    re.MULTILINE | re.IGNORECASE,
)
_VALIDATE_CALL_RE = re.compile(
    r"(?:self|self\s*\.\s*vault_impl)\s*\.\s*_validate_commitment\s*\(",
    re.MULTILINE | re.IGNORECASE,
)


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source.decode("utf-8", errors="replace")

    match = _LIENTOKEN_BUYOUT_RE.search(text)
    if not match:
        return hits

    body = match.group("body")
    if _VALIDATE_CALL_RE.search(body):
        return hits
    if "liens.get" not in body and "liens.remove" not in body:
        return hits

    first_line = text[: match.start()].count("\n") + 1
    first_snippet = text[match.start() : match.start() + 120].replace("\n", " ").strip()

    hits.append({
        "severity": "medium",
        "line": first_line,
        "col": 0,
        "snippet": first_snippet,
        "message": (
            f"{filepath}: pattern 'lientoken_buyoutlien_skips_vault_signature_validation' detected "
            "LienToken direct buyout path mutates lien state without a "
            "visible vault commitment validation. "
            "Review for missing authorization / unsafe pattern."
        ),
    })
    return hits
