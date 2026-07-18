"""Canonical source-root resolver - shared by every coverage / depth gate.

THE BUG THIS FIXES: tools picked the source root by a fixed NAME preference
(e.g. prefer ``src/src`` and break). On a Cargo workspace cloned into ``ws/src``
whose real code lives in ``crates/*/src`` while the repo also has a thin
top-level ``src/``, the resolver landed on ``ws/src/src`` (a near-empty stub)
and the coverage gate audited ~0 functions. Same class of bug on any layout
where the conventional name is not where the code is.

THE FIX: pick the DEEPEST candidate directory that still contains ALL of the
workspace's in-scope source (by file count). That:
  - lands on ``ws/src`` for a Cargo workspace (crates/* live under it; the thin
    ``src/src`` stub does NOT contain all the source so it is rejected),
  - correctly STAYS on ``ws/src/src`` for a genuine Solidity nesting (both
    ``src`` and ``src/src`` contain all the source -> deepest wins = src/src),
  - falls back to the whole workspace when source is split across sibling dirs
    (e.g. external/ + src/) so nothing is missed.

No per-target config; correct for Rust / Solidity / Go / Move / Cairo / Vyper.
"""
from __future__ import annotations

from pathlib import Path

SOURCE_EXTS = {".rs", ".sol", ".vy", ".go", ".move", ".cairo", ".circom", ".nr", ".zok"}

_EXCLUDE_PARTS = {
    "target", "node_modules", "vendor", ".git", "lib", "out", "cache",
    "broadcast", "artifacts", "forge-std", ".cargo", "proptest-regressions",
    "fuzz", "benches", "bench", "test", "tests", "testdata", "mocks",
    "poc-tests", "poc_execution", "_archive", "examples",
    # workspace-internal artifact dirs (generated scaffolds / packs / logs) must
    # NEVER count as in-scope source - they contain generated .rs packs whose
    # presence would otherwise inflate count_sources(ws) and make the resolver
    # drift from [ws/src] to [ws] on re-runs.
    ".auditooor", ".audit_logs", "fuzz_runs", "mining_rounds", "submissions",
    "concolic", "critical_hunt", "swarm", "agent_outputs",
}

_CANDIDATE_SUBDIRS = ("src/src", "src", "external", "contracts", "sources", "crates")


def _is_test_file(name: str) -> bool:
    n = name.lower()
    return (n.endswith("test.rs") or n.endswith("_test.rs") or n == "tests.rs"
            or n.endswith(".t.sol") or n.endswith("_test.go") or n.endswith("test.go")
            or n.endswith("_test.move"))


def count_sources(root: Path, cap: int = 200_000) -> int:
    """Count in-scope source files under ``root`` (excludes tests/vendor/build)."""
    n = 0
    try:
        it = root.rglob("*")
    except OSError:
        return 0
    for p in it:
        if p.suffix.lower() not in SOURCE_EXTS:
            continue
        if any(part in _EXCLUDE_PARTS for part in p.parts):
            continue
        if _is_test_file(p.name):
            continue
        n += 1
        if n >= cap:
            break
    return n


def resolve_src_roots(ws) -> list[Path]:
    """Return the best in-scope source root(s) for a workspace.

    Returns a single-element list with the deepest candidate dir that contains
    all the workspace's source, or [ws] when the source is split across siblings.
    """
    ws = Path(ws)
    if not ws.is_dir():
        return [ws]
    total = count_sources(ws)
    if total == 0:
        return [ws]
    candidates: list[Path] = []
    for sub in _CANDIDATE_SUBDIRS:
        cand = ws / sub
        if cand.is_dir() and cand not in candidates:
            candidates.append(cand)
    # candidates that contain (essentially) ALL the workspace source
    full = [c for c in candidates if count_sources(c) >= total]
    if full:
        # deepest = most path parts = most specific root that still has everything
        return [sorted(full, key=lambda c: len(c.parts))[-1]]
    # source is split across siblings (external/ + src/, etc.): use the whole ws
    return [ws]
