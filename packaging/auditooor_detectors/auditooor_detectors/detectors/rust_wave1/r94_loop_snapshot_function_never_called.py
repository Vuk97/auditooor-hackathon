"""
r94_loop_snapshot_function_never_called.py

Flags contracts whose source imports / inherits an `ERC20Snapshot` /
`Snapshot` module AND exposes `balance_of_at` / `balanceOfAt` —
but never calls `_snapshot()` (or wraps it in an external fn). The
snapshot-at reads revert because no snapshots exist.

Source: Solodit #13402 (ConsenSys zDAO Token).
Class: snapshot-function-never-called (both).
"""

from __future__ import annotations
import re
from _util import source_nocomment

_SNAPSHOT_MODULE_RE = re.compile(
    r"ERC20Snapshot|Snapshot\.sol|ERC20SnapshotUpgradeable|"
    r"use\s+openzeppelin::token::erc20::extensions::snapshot"
)
_BALANCE_AT_USAGE_RE = re.compile(
    r"balance_of_at|balanceOfAt|totalSupplyAt|total_supply_at"
)
_SNAPSHOT_CALL_RE = re.compile(
    r"_snapshot\s*\(\s*\)|self\._snapshot\s*\(\s*\)|\.snapshot\s*\(\s*\)|"
    r"fn\s+(snapshot|take_snapshot|create_snapshot)\s*\("
)


def run(tree, source: bytes, filepath: str):
    hits = []
    src = source_nocomment(source)
    if not _SNAPSHOT_MODULE_RE.search(src):
        return hits
    if not _BALANCE_AT_USAGE_RE.search(src):
        return hits
    if _SNAPSHOT_CALL_RE.search(src):
        return hits
    hits.append({
        "severity": "high",
        "line": 1,
        "col": 0,
        "snippet": src[:200],
        "message": (
            "Contract inherits ERC20Snapshot and exposes "
            "`balanceOfAt` / `balance_of_at` but never calls "
            "`_snapshot()` anywhere — snapshot reads always revert "
            "(snapshot-function-never-called). See Solodit #13402 "
            "(zDAO Token)."
        ),
    })
    return hits
