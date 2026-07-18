"""Synthetic / codegen target exclusion for exploit-queue population.

A candidate exploit-queue lead whose TARGET FILE is Recon *chimera*
mutation-test scaffolding or protobuf/codegen is provably out-of-scope and must
never populate the queue - it can never be a production finding:

- ``chimera_harnesses/`` holds the Recon Chimera scaffolding. For every real
  target the fuzzer plants a deliberately-broken copy (a *Mutant*) plus mocks so
  its own suite can prove it KILLS them. A "theft"/"role-escalation" lead on a
  ``*Mutant*.sol`` is the fuzzer WORKING, never a deployed bug; these files are
  never compiled into production.
- ``*.pulsar.go`` / ``*.pb.go`` (and files carrying the ``Code generated ... DO
  NOT EDIT`` sentinel) are protobuf/codegen: reflection getters/setters and
  wire marshalling, not hand-written attacker-reachable business logic.

This module is the single source of truth for that classification. It mirrors
the existing dev-tooling/codegen exclusions:
- tools/guard-negative-space-analyzer.py :: _is_dev_tooling_config
- tools/declared-control-mutator-completeness-screen.py :: _is_generated_source

Applied at the exploit-queue POPULATION step by both queue writers:
- tools/exploit-queue.py (canonical exploit_queue.json builder)
- tools/exploit-queue-source-miner.py (exploit_queue.source_mined.json emitter)

ANTI-GREENING GUARDRAIL: this MUST only drop synthetic scaffolding + codegen.
Real in-scope production sources (e.g. src/vault/keeper/*.go,
src/nuva-evm-contracts/contracts/*.sol) do NOT match any predicate here and are
never dropped. See tools/tests/test_synthetic_target_exclusion.py.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

# Recon Chimera scaffolding directory - every path component is synthetic.
_CHIMERA_HARNESS_DIR_RE = re.compile(r"(?:^|/)chimera_harnesses/")
# Deliberately-broken mutant copies: *Mutant*.sol and *_mutant* scaffolding.
_MUTANT_BASENAME_RE = re.compile(r"(?:mutant)", re.IGNORECASE)
# Protobuf / grpc-gateway / codegen source file suffixes.
_CODEGEN_SUFFIXES = (".pulsar.go", ".pb.go", ".pb.gw.go", ".gen.go")
# "Code generated <tool> DO NOT EDIT" sentinel (protoc, abigen, stringer, ...).
_GENERATED_SENTINEL = re.compile(r"Code generated .{0,80}?DO NOT EDIT", re.I)
# Test / PoC / mock scaffolding: never compiled into production. Go `_test.go` is
# compiler-excluded; Foundry `.t.sol` + test/mock dirs + Mock*.sol are test-only.
_TEST_TARGET_SUFFIX_RE = re.compile(
    r"(?:_test\.(?:go|rs)|\.t\.sol|\.test\.(?:js|ts)|\.spec\.(?:js|ts))$", re.I
)
_TEST_DIR_RE = re.compile(
    r"(?:^|/)(?:tests?|mocks?|testdata|__tests__|__mocks__|simulation|simapp)/", re.I
)
_TEST_BASENAME_RE = re.compile(r"(?:^mock.*\.sol$|_poc(?:_test)?\.)", re.I)

# Row fields that may carry the lead's target file path.
_ROW_PATH_KEYS = (
    "contract",
    "file",
    "file_path",
    "source_file",
    "target_file",
    "path",
    "impact_path",
)

DROP_REASON_CHIMERA = "chimera_mutation_test_harness"
DROP_REASON_CODEGEN = "protobuf_or_codegen"
DROP_REASON_TEST = "test_or_poc_scaffold"


def _basename(path: str) -> str:
    return (path or "").replace("\\", "/").rsplit("/", 1)[-1]


def _norm_path(path: str) -> str:
    p = str(path or "").strip().strip("`'\"()[]{}<>,;").replace("\\", "/")
    if p.startswith("workspace:"):
        p = p.split(":", 1)[1]
    while p.startswith("./"):
        p = p[2:]
    # Drop a trailing ``:LINE`` / ``:LINE-END`` reference suffix.
    p = re.sub(r":\d+(?:-\d+)?$", "", p)
    return p.strip("/")


def is_chimera_mutation_harness_path(path: str) -> bool:
    """True when the path is Recon chimera mutation-test scaffolding.

    Matches the ``chimera_harnesses/`` directory anywhere in the path, or a
    ``*Mutant*.sol`` / ``*_mutant*`` basename (the deliberately-broken copies
    the fuzzer plants). Never matches a real production source path.
    """
    p = _norm_path(path)
    if not p:
        return False
    if _CHIMERA_HARNESS_DIR_RE.search("/" + p):
        return True
    base = _basename(p).lower()
    if base.endswith(".sol") and "mutant" in base:
        return True
    if "_mutant" in base:
        return True
    return False


def is_codegen_path(path: str, workspace: Path | None = None) -> bool:
    """True when the path is protobuf / generated (never hand-written) source.

    Suffix match is path-only (no file read required). When ``workspace`` is
    provided and the file resolves, the ``Code generated ... DO NOT EDIT``
    header sentinel is also honoured - mirroring _is_generated_source.
    """
    p = _norm_path(path)
    if not p:
        return False
    base = _basename(p).lower()
    if any(base.endswith(sfx) for sfx in _CODEGEN_SUFFIXES):
        return True
    if workspace is not None:
        candidate = Path(p) if Path(p).is_absolute() else (workspace / p)
        try:
            if candidate.is_file():
                head = candidate.read_text(encoding="utf-8", errors="replace")[:4096]
                if _GENERATED_SENTINEL.search(head):
                    return True
        except OSError:
            return False
    return False


def is_test_target_path(path: str) -> bool:
    """True when the path is test / PoC / mock scaffolding, never production.

    Go ``_test.go`` is compiler-excluded; Foundry ``.t.sol`` + ``test(s)/``,
    ``mock(s)/``, ``testdata/`` dirs + ``Mock*.sol`` + ``*_poc_test.*`` are
    test-only. A candidate lead whose TARGET is such a file can never be a
    deployed finding (the observed nuva case: leads on economic_invariant_test.go
    and the filed finding's own zz_chainhalt_abci_poc_test.go). Never matches a
    real production source path.
    """
    p = _norm_path(path)
    if not p:
        return False
    if _TEST_DIR_RE.search("/" + p):
        return True
    base = _basename(p).lower()
    if _TEST_TARGET_SUFFIX_RE.search(base):
        return True
    if _TEST_BASENAME_RE.search(base):
        return True
    return False


def _row_target_paths(row: dict[str, Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()

    def add(value: Any) -> None:
        if isinstance(value, str):
            v = value.strip()
            if v and v not in seen:
                seen.add(v)
                out.append(v)

    for key in _ROW_PATH_KEYS:
        add(row.get(key))
    refs = row.get("source_refs")
    if isinstance(refs, list):
        for ref in refs:
            if isinstance(ref, str) and "/" in ref:
                add(ref)
            elif isinstance(ref, dict):
                for key in ("path", "file", "source_ref", "file_line", "source_path"):
                    add(ref.get(key))
    return out


def classify_synthetic_or_codegen(
    row: dict[str, Any], workspace: Path | None = None
) -> tuple[bool, str, str]:
    """Classify a queue row's target file.

    Returns ``(drop, reason, path)``. ``drop`` is True iff the row targets Recon
    chimera mutation scaffolding or protobuf/codegen, in which case ``reason`` is
    one of DROP_REASON_* and ``path`` is the matched target path. A row targeting
    real production source returns ``(False, "", "")``.
    """
    if not isinstance(row, dict):
        return False, "", ""
    for raw in _row_target_paths(row):
        if is_chimera_mutation_harness_path(raw):
            return True, DROP_REASON_CHIMERA, _norm_path(raw)
    for raw in _row_target_paths(row):
        if is_test_target_path(raw):
            return True, DROP_REASON_TEST, _norm_path(raw)
    for raw in _row_target_paths(row):
        if is_codegen_path(raw, workspace):
            return True, DROP_REASON_CODEGEN, _norm_path(raw)
    return False, "", ""


def partition_synthetic_or_codegen_rows(
    rows: list[dict[str, Any]], workspace: Path | None = None
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    """Split rows into (survivors, dropped, reason_counts).

    A single generic population-time chokepoint: any row whose target file is
    chimera mutation scaffolding or codegen is DROPPED (removed, not just
    quarantined) so downstream prove-top-leads / no-leads-manifest logic never
    sees it. Rows without a resolvable path, or targeting production source,
    survive.
    """
    survivors: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    reason_counts: dict[str, int] = {}
    for row in rows:
        drop, reason, _path = classify_synthetic_or_codegen(row, workspace)
        if drop:
            dropped.append(row)
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
        else:
            survivors.append(row)
    return survivors, dropped, reason_counts
