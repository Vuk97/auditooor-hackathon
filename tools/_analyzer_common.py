"""
_analyzer_common.py — R79 T3: shared source-file walker for R76 analyzers.

All R76 analyzers (attack-path, acl-matrix, storage-layout,
integration-assumptions, missing-check-catalog, invariant-proposer) must
skip test / mock / dev / script / lib paths uniformly.

Previously each analyzer re-implemented this inline, and the skip logic
kept getting reverted during merges. This module is the SINGLE SOURCE OF
TRUTH — every analyzer imports `iter_source_files(workspace)` from here.

Usage:

    from _analyzer_common import iter_source_files

    for sol in iter_source_files(ws, max_files=300):
        # only real scope files — no test/mock/dev contaminating your report
        ...
"""

from __future__ import annotations
import pathlib
from typing import Iterator

# Path parts that should be excluded from ALL analyzer scans.
SKIP_PATH_PARTS: frozenset[str] = frozenset({
    "test", "tests",
    "mock", "mocks",
    "dev",
    "script", "scripts",
    "lib",
    "out",
    "cache",
    "node_modules",
    "economic_hypotheses",
    "ARCHIVED_FOR_SCAN",
})

# File-name suffixes that flag test/script files in Foundry convention.
SKIP_NAME_SUFFIXES: tuple[str, ...] = (
    ".t.sol",
    ".s.sol",
    ".spec.sol",
)


def is_scope_file(sol: pathlib.Path) -> bool:
    """Return True if this .sol file should be analyzed (not test/mock/lib)."""
    if any(part in SKIP_PATH_PARTS for part in sol.parts):
        return False
    if sol.name.endswith(SKIP_NAME_SUFFIXES):
        return False
    return True


def iter_source_files(workspace: pathlib.Path | str, max_files: int = 500) -> Iterator[pathlib.Path]:
    """Yield in-scope .sol files under workspace/src/, with a safety cap."""
    workspace = pathlib.Path(workspace)
    count = 0
    for sol in workspace.glob("src/**/*.sol"):
        if not is_scope_file(sol):
            continue
        if count >= max_files:
            break
        count += 1
        yield sol
