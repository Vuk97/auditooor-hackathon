"""
erc20snapshot_snapshot_never_called_snapshots_never_actually_taken

Auto-generated from r94 phase7 overnight pipeline.
Pattern class: erc20snapshot-snapshot-never-called-snapshots-never-actually-taken
Platform: solana
Source: phase7_rust_fixture_erc20snapshot_snapshot_never_called_snapshots_never_actually_taken.json

Regex-based detector — uses regex_indicators from the DSL spec to flag
vulnerable patterns in Rust source files.
"""

from __future__ import annotations

import re

from _util import source_nocomment

_SNAPSHOT_STORAGE_RE = re.compile(r"\bERC20Snapshot\b|\bsnapshot_ids\b|\bsnapshots\b", re.IGNORECASE)
_SNAPSHOT_READ_RE = re.compile(
    r"fn\s+(?:balance_of_at|balanceOfAt|total_supply_at|totalSupplyAt)\s*\(",
    re.IGNORECASE,
)
_SNAPSHOT_WRITER_RE = re.compile(r"fn\s+_snapshot\s*\(", re.IGNORECASE)
_SNAPSHOT_CALL_RE = re.compile(
    r"(?:self\.|token\.|\w+\.)_snapshot\s*\(\s*\)|"
    r"fn\s+(?:snapshot|take_snapshot|create_snapshot)\s*\(",
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
            f"{filepath}: ERC20 snapshot read methods are present, but the snapshot "
            "writer is never exposed or called; snapshot reads can never observe "
            "a taken snapshot."
        ),
    }


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    text = source_nocomment(source)

    if not _SNAPSHOT_STORAGE_RE.search(text):
        return hits
    read_match = _SNAPSHOT_READ_RE.search(text)
    if not read_match:
        return hits
    if not _SNAPSHOT_WRITER_RE.search(text):
        return hits
    if _SNAPSHOT_CALL_RE.search(text):
        return hits

    hits.append(_hit(filepath, text, read_match))
    return hits
