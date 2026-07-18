"""StateCouplingEdge schema (v1) - frozen record + validator for the State-Coupling
Graph (SCG), the generalized Aptos-class coupling-completeness primitive.

An edge asserts that two persistent state CELLS are coupled (must move together under
some invariant), carries the COMPLETENESS OBLIGATION over that pair, the set of writer
functions that mutate each endpoint, a per-edge CONFIDENCE tier (R80 honesty), and the
IMPACT class the coupling-kind escalates to. See
reports/state_coupling_completeness_framework_design.md.

Producers:
  - tools/state-coupling-graph.py --emit  (semantic-ssa from dataflow_path.v1;
    degrades to syntactic from tools/coupled-state-completeness.py when no slice).
Consumers:
  - state-coupling-completeness-check.py (audit-complete signal),
  - exploit-queue.py (_gather_from_state_coupling), completeness-matrix-build.py.

Honesty contract (mirrors dataflow_schema.py): a `semantic-ssa` edge is IR-backed
(from a real def-use slice + call-graph closure) and citable; `syntactic` is a regex
PROMPT (advisory, probe-gated); `heuristic` is name-only and NEVER cited.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, Iterable, List, Tuple

SCHEMA_VERSION = "state_coupling_edge.v1"

# coupling kinds (the taxonomy) -> each grounds in a dataflow/infra signature.
COUPLING_KINDS = {
    "derived-from",      # cell B flows into cell A's state-write (A = f(B))
    "keyed-by",          # map A indexed by B; B maintained in a registry
    "co-indexed",        # A[k], B[k] written under the same key slice
    "conserved-with",    # Sigma cells written under one guarded slice
    "paired-lifecycle",  # add/remove, mint/burn writer sets
    "flush-group",       # multi-member invalidate set (Aptos)
    "mirror",            # local<->remote / senior<->junior replicated write
    "ordering",          # version<->commit monotonic sequence
    # 9th kind: a state value coupled to an EXTERNAL clock/round the contract never
    # writes (ttl / oracle-round / block.timestamp staleness). The writer-mutates-B-
    # not-A model cannot express it - the "other endpoint" has no on-chain writer; the
    # defect is a CONSUMER reading A without the freshness gate a sibling reader applies.
    "freshness-coupled-to-external-clock",
    # 10th kind: CROSS-DOMAIN conservation - an INTERNAL accounting cell (share/supply)
    # must move together with an EXTERNAL asset balance (bank.Send / ERC20 transfer of the
    # underlying), across the domain boundary. The intra-contract conserved-with model
    # cannot express it: one endpoint is not an in-scope storage cell, it is an external
    # token balance. The defect is a writer that changes the internal share/supply WITHOUT
    # the paired external value-move (mint shares without receiving assets = inflation /
    # insolvency) - the dominant cosmos/vault share-accounting bug class (Aptos-tier).
    "cross-domain-conservation",
    # 11th kind: INTERRUPTION - a coupled record set S SPLIT across >=2 functions. Phase-1
    # CREATES a pending/request/cooldown-named record (push/struct-store); the paired
    # SETTLEMENT (pop/delete + asset release) lives ONLY in a SEPARATE finalize/cancel body;
    # NO single fn writes all of S. If the phase-2 leg is unreachable the created record +
    # custodied asset are stranded (partial-update freeze). DISTINCT from flush-group (INTRA-
    # fn 2-cell partial commit): interruption is the CROSS-fn / cross-tx split. Terminal-
    # freeze proof needs negative-space reachability -> emitted advisory + verdict=needs-fuzz.
    "interruption",
    # 13th kind: FRESHNESS-COUPLED-TO-SHARED-CURSOR (a freshness SIBLING). DISTINCT from the
    # external-CLOCK freshness kind (a hard-coded clock the contract never writes, trigger=age):
    # cell A is a SNAPSHOT of an ON-CHAIN cursor the protocol ADVANCES, read cross-module via
    # `X.epoch()` / `X.checkpoint()` (root in _ORDERING_ROOTS), where that cursor has a PROVEN
    # NON-MONOTONIC writer (setCurrentEpoch / reset / delete - it can roll back / reorg, not just
    # increase) AND a SIBLING reader trusts the stored A without re-establishing it. On a
    # rollback the stored A desyncs from the live cursor (Polygon ValidatorShare
    # withdrawEpoch = stakeManager.epoch() vs the withdrawEpoch+delay<=epoch settle gate).
    # Trigger = rollover/reset/reorg, NOT age. Advisory + verdict=needs-fuzz.
    "freshness-coupled-to-shared-cursor",
    # 14th kind: STALE-HANDLE-AFTER-RECYCLE (R1 handle-freshness arm). The READ/HOLD side of a
    # reusable identity handle: a handle (array index / mapping key / token id / epoch slot /
    # type-tag/StructNameIndex / generational index) was correctly unique when ISSUED, its slot
    # was later FREED (pop / swap-pop / delete C[k] / burn / evict / Table::remove / move_from)
    # and RE-ISSUED to a NEW occupant, and a STALE HOLDER persisted across a tx/step/epoch then
    # resolves the recycled slot BLINDLY - with NO binding-freshness re-check (generation-counter
    # compare / referent-identity assert / existence+owner re-read / monotonic-not-recycled proof)
    # - into a severity-eligible sink (value-move / authority / type-cast). This is the namesake
    # Hexens 'Arbitrary Struct Hijack in Aptos Move VM' 0-day (recycled StructNameIndex resolves to
    # the wrong struct). DISJOINT from A4 write-collision-on-ISSUANCE (no recycle, no persisted
    # holder) and A12 numeric-cursor MONOTONICITY (that tracks a numeric value rolling back; this
    # tracks the referent IDENTITY of a freed+reissued SLOT changing). Advisory-first, env-gated
    # OFF (SCG_HANDLE_FRESHNESS); verdict=needs-fuzz (recycle reachability is the fuzz obligation).
    "stale-handle-after-recycle",
}

CONFIDENCES = {"semantic-ssa", "syntactic", "heuristic"}

# coupling-kind -> impact class (the "all impacts" bridge; each value must resolve to
# an attack_class_vocab class whose methodology_playbook -> a real impact_id).
KIND_IMPACT = {
    "derived-from": "coupled-state-partial-update",
    "keyed-by": "coupled-state-partial-update",
    "co-indexed": "coupled-state-partial-update",
    "conserved-with": "value-conservation-break",
    "paired-lifecycle": "coupled-state-partial-update",
    "flush-group": "asymmetric-cache-invalidation-partial-flush",
    "mirror": "cross-domain-state-desync",
    "ordering": "sequence-commit-desync",
    "freshness-coupled-to-external-clock": "stale-state-freshness-desync",
    "cross-domain-conservation": "value-conservation-break",
    "interruption": "coupled-state-partial-update",
    "freshness-coupled-to-shared-cursor": "stale-state-freshness-desync",
    "stale-handle-after-recycle": "stale-handle-referent-desync",
}

_TOP_KEYS = (
    "schema", "edge_id", "language", "kind", "cell_a", "cell_b",
    "writers_a", "writers_b", "obligation", "violators",
    "impact_class", "confidence", "evidence",
)
# a violator = a writer that mutates one endpoint but not (the obligation over) the other
_VIOLATOR_KEYS = ("fn", "file", "line", "mutates", "omits")


def new_edge(
    edge_id: str,
    language: str,
    kind: str,
    cell_a: str,
    cell_b: str,
    writers_a: List[str],
    writers_b: List[str],
    violators: List[Dict[str, Any]],
    confidence: str = "syntactic",
    evidence: Dict[str, Any] | None = None,
    obligation: str | None = None,
) -> Dict[str, Any]:
    """Build a v1 StateCouplingEdge. impact_class is derived from `kind`."""
    if obligation is None:
        obligation = (
            f"every writer of {cell_a!r} or {cell_b!r} must preserve their "
            f"{kind} coupling; a writer touching a strict subset desyncs them")
    return {
        "schema": SCHEMA_VERSION,
        "edge_id": edge_id,
        "language": language,
        "kind": kind,
        "cell_a": cell_a,
        "cell_b": cell_b,
        "writers_a": sorted(set(writers_a or [])),
        "writers_b": sorted(set(writers_b or [])),
        "obligation": obligation,
        "violators": violators or [],
        "impact_class": KIND_IMPACT.get(kind, "coupled-state-partial-update"),
        "confidence": confidence,
        "evidence": evidence or {},
    }


def validate(rec: Dict[str, Any]) -> Tuple[bool, List[str]]:
    errs: List[str] = []
    if not isinstance(rec, dict):
        return False, ["record is not a dict"]
    for k in _TOP_KEYS:
        if k not in rec:
            errs.append(f"missing top key: {k}")
    if rec.get("schema") != SCHEMA_VERSION:
        errs.append(f"schema mismatch: {rec.get('schema')!r}")
    if rec.get("kind") not in COUPLING_KINDS:
        errs.append(f"bad kind: {rec.get('kind')!r}")
    if rec.get("confidence") not in CONFIDENCES:
        errs.append(f"bad confidence: {rec.get('confidence')!r}")
    for lk in ("writers_a", "writers_b"):
        if not isinstance(rec.get(lk), list):
            errs.append(f"{lk} must be a list")
    vs = rec.get("violators")
    if isinstance(vs, list):
        for i, v in enumerate(vs):
            if not isinstance(v, dict):
                errs.append(f"violators[{i}] not a dict")
                continue
            for k in _VIOLATOR_KEYS:
                if k not in v:
                    errs.append(f"violators[{i}] missing key: {k}")
    else:
        errs.append("violators must be a list")
    return (len(errs) == 0), errs


def edges_path(ws) -> str:
    return os.path.join(str(ws), ".auditooor", "state_coupling_edges.jsonl")


def write_edges(ws, edges: Iterable[Dict[str, Any]]) -> int:
    p = edges_path(ws)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    edges = list(edges)
    with open(p, "w", encoding="utf-8") as fh:
        for e in edges:
            fh.write(json.dumps(e, sort_keys=True, default=str) + "\n")
    return len(edges)


def read_edges(ws, *, kinds: List[str] | None = None,
               min_confidence: str | None = None) -> List[Dict[str, Any]]:
    """Canonical reader. Drops malformed rows (a bad producer must not poison a
    consumer). `min_confidence` filters to >= a tier (semantic-ssa > syntactic >
    heuristic)."""
    p = edges_path(ws)
    if not os.path.isfile(p):
        return []
    order = {"heuristic": 0, "syntactic": 1, "semantic-ssa": 2}
    floor = order.get(min_confidence, -1) if min_confidence else -1
    kset = set(kinds) if kinds else None
    out: List[Dict[str, Any]] = []
    try:
        with open(p, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                ok, _e = validate(rec)
                if not ok:
                    continue
                if kset is not None and rec.get("kind") not in kset:
                    continue
                if order.get(rec.get("confidence"), -1) < floor:
                    continue
                out.append(rec)
    except OSError:
        return []
    return out
