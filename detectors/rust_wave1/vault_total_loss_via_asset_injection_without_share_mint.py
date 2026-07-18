"""
vault_total_loss_via_asset_injection_without_share_mint

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: vault-total-loss-via-asset-injection-without-share-mint
Platform: solana
Source: phase7_rust_fixture_vault_total_loss_via_asset_injection_without_share_mint.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

_REBASE_BODY_RE = re.compile(
    r"fn\s+\w*rebase\w*\s*\([^)]*\)\s*\{(?P<body>[\s\S]*?)\n\s*\}",
    re.MULTILINE | re.IGNORECASE,
)
_ASSET_BUMP_RE = re.compile(
    r"total_assets\s*\+\=\s*[^;]+",
    re.MULTILINE | re.IGNORECASE,
)
_SAFE_SHARE_BUMP_RE = re.compile(
    r"total_shares\s*\+\=\s*[^;]+",
    re.MULTILINE | re.IGNORECASE,
)


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source.decode("utf-8", errors="replace")

    rebase_match = _REBASE_BODY_RE.search(text)
    if not rebase_match:
        return hits

    body = rebase_match.group("body")
    if not _ASSET_BUMP_RE.search(body):
        return hits
    if _SAFE_SHARE_BUMP_RE.search(body):
        return hits

    first_line = text[: rebase_match.start()].count("\n") + 1
    first_snippet = text[rebase_match.start() : rebase_match.start() + 120].replace("\n", " ").strip()

    hits.append({
        "severity": "medium",
        "line": first_line,
        "col": 0,
        "snippet": first_snippet,
        "message": (
            f"{filepath}: pattern 'vault_total_loss_via_asset_injection_without_share_mint' detected "
            "vault accounting bumps assets inside a rebase-style path "
            "without a matching share mint. "
            "Review for missing authorization / unsafe pattern."
        ),
    })
    return hits
