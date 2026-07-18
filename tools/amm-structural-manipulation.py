#!/usr/bin/env python3
"""amm-structural-manipulation.py - LOGIC CAPABILITY (AMM structural-accounting).

docs/LOGIC_ARSENAL_ROADMAP.md, perpetual logic-arsenal loop. RANK-6 burndown
(AMM structural manipulation, HIGH x60). This is a COUPLED-UPDATE REACHABILITY
query over the OWNED go-dataflow / Slither data-dependency backend. It is NOT a
regex for "tick" / "swap".

DISTINCT FROM oracle-spot-price-manipulation-reasoner.py (already owned): that
reasoner asks whether a SPOT price authorizes a value move with no TWAP second
source (a two-set SUBSET test on the PRICE plane). THIS reasoner asks a different
question on the STRUCTURE plane: does a mutator of an AMM structural-accounting
field update the WHOLE coupled accounting group, or a proper SUBSET of it (or
cross a tick/bin boundary without re-establishing the group invariant)? A pool can
have a perfect oracle and still be drained if crossTick writes liquidityNet but
forgets the global active `liquidity`, or a swap updates reserve0 but not the
observation index / feeGrowth.

THE LOGIC TRIPLE (extracted from concentrated-liquidity / virtual-reserve
structural-accounting bugs - Uniswap-v3 tick-cross desync class, virtual-reserve
vs real-balance drift, TWAP observation-cardinality gaps, TraderJoe/LB bin
accounting desync):
  ASSUMPTION (protocol trusts):  the pool's internal STRUCTURAL-ACCOUNTING state
    (per-tick liquidityGross/Net + the global active liquidity; feeGrowthGlobal +
    per-tick feeGrowthOutside/Inside; observationIndex + cardinality + the
    observations ring; virtualReserve0/1 vs the REAL token balances; per-bin
    reserves + activeId) stays MUTUALLY CONSISTENT: the members of each coupled
    group MOVE TOGETHER on every mutation, and every tick/bin boundary crossing
    re-establishes the aggregate invariant (sum of per-slot components == the
    global aggregate; observation index monotonic; virtual == real +/- credited).
  INVARIANT (must hold), per coupled accounting GROUP G:
      MUTATORS(G)   = { external/public entrypoint f : some node in f's forward
                        callee closure WRITES (mutating sink) >=1 member of G }
      FULL(G)       = { f in MUTATORS(G) : f's closure writes the FULL observed
                        member set of G (all coupled members move together) }
      The protocol requires   MUTATORS(G)  is a SUBSET of  FULL(G) .
  TRUST-BOUNDARY (crossed): an attacker mints/burns/swaps AT A TICK/BIN BOUNDARY
    (or at the exact cardinality/reserve edge) so that a mutator updates a PROPER
    SUBSET of the coupled group - the pool's internal accounting (liquidityNet,
    feeGrowth, observation index, virtual reserve) desyncs from real balances, and
    the attacker withdraws against the phantom accounting.
  FINDING = the SET-DIFFERENCE  MUTATORS(G) \\ FULL(G)  per group, PLUS the
    boundary-cross survivors (a mutator that references a tick/bin boundary-crossing
    op but does not write the group's AGGREGATE / invariant-re-establish member).
    Emitted as an `amm-structural-manipulation` obligation.

WHY THIS IS LOGIC, NOT A SHAPE (guard-rail satisfied)
  A shape would be `body_contains('tick') and body_contains('swap')`. This query
  differs on the axes that make it an accounting-group set relation:
    (a) membership in MUTATORS(G) is TRANSITIVE forward-closure reachability to a
        mutating sink on a member of G - a write in an N-hop helper on a different
        body still classifies (impossible for a body-scoped regex);
    (b) the answer is a RELATION BETWEEN the WRITTEN member subset and the
        workspace-OBSERVED FULL member set of a COUPLED GROUP (the subset test
        MUTATORS is a subset of FULL); the finding is the SET-DIFFERENCE, i.e. a
        mutator whose write set is a PROPER subset of the coupled group - not a
        boolean over one token;
    (c) it is orthogonal to the coupled-state-completeness reasoner (which folds
        arbitrary must-move-together state pairs from a generic write-set diff) and
        to oracle-spot (a PRICE-plane subset test): here the groups are the
        FIXED AMM structural-accounting families with a KNOWN aggregate/component
        coupling and a KNOWN boundary-crossing re-establish obligation, so a
        component write without the aggregate (or a boundary cross without the
        aggregate) is the survivor - a per-node member classifier wrapped in the
        group set-difference, not the classifier alone.

OWNED BACKEND CONSUMED (nothing new is built here)
  <ws>/.auditooor/dataflow_paths.jsonl (schema dataflow_path.v1) produced by
  tools/go-dataflow.py (go/ssa + callgraph + backward DefUse) for the Go arm and
  the Slither data_dependency arm for Solidity. Auto-unions any scoped sidecar
  dataflow_paths.*.jsonl. Per entrypoint the CLOSURE node set consulted is:
  source.var/fn, sink.callee/cell/fn, every hop.ir/via/fn, every guard_nodes[].expr.
  A MUTATING sink (state-write/mint/burn/value-move/safeTransfer(From)/storage-value)
  whose callee/cell names a member of a coupled group marks that member as WRITTEN;
  any closure node naming a member marks it REFERENCED. FULL(G) is the
  workspace-wide union of referenced members of G (only members the pool actually
  implements are demanded). Reuses the exemplar helpers (_entrypoint_of/_fn_file/
  _fn_line/_in_scope_file/_short_fn/_contract_of/is_permissionless).

OUTPUT
  <ws>/.auditooor/amm_structural_manipulation_obligations.jsonl - one row per
  survivor, schema `auditooor.amm_structural_manipulation.v1`, exploit_queue-ingest
  compatible (contract/function/source_refs/root_cause_hypothesis/attack_class/
  broken_invariant_ids/quality_gate_status='needs_source'). A summary is printed /
  emitted (--json) with per-group |MUTATORS|, |partial-update|, |survivors|, the
  KEPT (full-coupled-update) set, and a class_present / substrate status:
    * substrate_vacuous : 0 dataflow records materialized (the call graph never
      built) - NOT a clean negative;
    * class_absent (cited-empty) : real substrate, but no coupled AMM
      structural-accounting group is present (class_present=False) - an honest
      N/A over a MATERIALIZED substrate (e.g. a non-AMM vault / a Go DLT);
    * survivors / all-full : the class IS present; either open obligations exist
      or every mutator updated the full coupled group.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent

# ---------------------------------------------------------------------------
# Reuse the exemplar set-difference hunter's record-parsing + scope helpers so
# every logic reasoner shares ONE source of truth for entrypoint identity and the
# OOS filter (a vendored cosmos-sdk keeper read is not an in-scope lead).
# ---------------------------------------------------------------------------
_CSDH_PATH = _HERE / "callgraph-set-difference-hunter.py"
_spec = importlib.util.spec_from_file_location("_csdh_reuse_amm", _CSDH_PATH)
_csdh = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_csdh)  # type: ignore[union-attr]

_entrypoint_of = _csdh._entrypoint_of
_fn_file = _csdh._fn_file
_fn_line = _csdh._fn_line
_in_scope_file = _csdh._in_scope_file
_short_fn = _csdh._short_fn
_contract_of = _csdh._contract_of
_is_permissionless_body = _csdh.is_permissionless

# ---------------------------------------------------------------------------
# MUTATING sink kinds: the sinks that WRITE structural-accounting state. A
# state_var_read / authority / none sink is NOT a mutation and cannot mark a
# member WRITTEN (only REFERENCED). storage-value = a Solidity storage assignment.
# ---------------------------------------------------------------------------
_MUTATING_SINK_KINDS = {
    "state-write", "storage-value", "mint", "burn",
    "value-move", "safeTransfer", "safeTransferFrom",
}

# ---------------------------------------------------------------------------
# COUPLED AMM STRUCTURAL-ACCOUNTING GROUPS. Each group is a set of MEMBER
# predicates. A group's members must MOVE TOGETHER on every mutation; the group's
# AGGREGATE member (the invariant-tie: the global/active aggregate that the
# per-slot components must sum to, or the monotonic index) MUST be re-written on
# any mutation that touches a component and on any boundary crossing.
#
# Member match is a per-node regex over the lowercased closure text / sink
# callee+cell. Component regexes are made SPECIFIC (liquiditynet before a bare
# \bliquidity\b) so the aggregate predicate does not swallow a component token.
# ---------------------------------------------------------------------------
# member spec: (member_key, compiled_regex, is_aggregate)
_GROUPS: dict[str, list[tuple[str, "re.Pattern[str]", bool]]] = {
    # Concentrated-liquidity per-tick liquidity accounting: crossing a tick must
    # apply liquidityNet to the GLOBAL active liquidity; liquidityGross gates
    # (de)initialization. Aggregate = active liquidity.
    "tick_liquidity": [
        ("liquidity_net", re.compile(r"liquiditynet|liquidity_net", re.I), False),
        ("liquidity_gross", re.compile(r"liquiditygross|liquidity_gross", re.I), False),
        ("active_liquidity",
         re.compile(r"activeliquidity|active_liquidity|"
                    r"(?:pool|global|state|self|\.)liquidity\b|^liquidity$",
                    re.I), True),
    ],
    # Fee-growth accounting: global fee growth accumulator + per-tick outside/inside
    # snapshots. Aggregate = feeGrowthGlobal (per-position fees derive from it).
    "fee_growth": [
        ("fee_inside", re.compile(r"feegrowthinside|fee_growth_inside", re.I), False),
        ("fee_outside", re.compile(r"feegrowthoutside|fee_growth_outside", re.I), False),
        ("fee_global", re.compile(r"feegrowthglobal|fee_growth_global", re.I), True),
    ],
    # TWAP observation ring: monotonic index + cardinality + the observations
    # array. Aggregate = observationIndex (must advance monotonically; cardinality
    # growth must not orphan the index).
    "observation": [
        ("obs_cardinality",
         re.compile(r"observationcardinality|observation_cardinality", re.I), False),
        ("obs_array", re.compile(r"\bobservations?\b", re.I), False),
        ("obs_index",
         re.compile(r"observationindex|observation_index", re.I), True),
    ],
    # Virtual-vs-real reserve accounting: virtual reserves / sqrtPrice track the
    # curve, the REAL token balance is the settlement. Aggregate = the real
    # balance (virtual must reconcile to real +/- credited).
    "virtual_reserve": [
        ("reserve0", re.compile(r"\breserve0\b|reserve_0", re.I), False),
        ("reserve1", re.compile(r"\breserve1\b|reserve_1", re.I), False),
        ("virtual_reserve",
         re.compile(r"virtualreserve|virtual_reserve|sqrtpricex96|sqrt_price", re.I), False),
        ("real_balance",
         re.compile(r"realbalance|real_balance|reservebalance", re.I), True),
    ],
    # Liquidity-Book / bin accounting: per-bin reserves + the active bin id + per-bin
    # liquidity. Aggregate = activeId (the active bin the swap walks; bin reserves
    # must reconcile to it).
    "bin": [
        ("bin_reserve", re.compile(r"binreserve|bin_reserve", re.I), False),
        ("bin_liquidity", re.compile(r"binliquidity|bin_liquidity", re.I), False),
        ("active_id",
         re.compile(r"\bactiveid\b|active_id|activebin|active_bin", re.I), True),
    ],
}

# Tick/bin BOUNDARY-CROSSING ops: a mutation whose closure references one of these
# is a boundary crossing and MUST re-establish the group's aggregate member.
_BOUNDARY_CROSS = re.compile(
    r"crosstick|cross_tick|\bcross\b|nexttick|next_tick|"
    r"nextinitializedtick|next_initialized|tickbitmap|fliptick|flip_tick|"
    r"getnextbin|next_bin|movebin|move_bin|nextnonemptybin",
    re.I,
)


def _member_hits(text: str) -> list[tuple[str, str, bool]]:
    """Return [(group, member_key, is_aggregate)] for every group member whose
    regex matches this single node text. A per-node member classifier; the LOGIC
    is the group set-difference wrapped around it."""
    if not text:
        return []
    low = text.lower()
    out: list[tuple[str, str, bool]] = []
    for group, members in _GROUPS.items():
        for mkey, rx, is_agg in members:
            if rx.search(low):
                out.append((group, mkey, is_agg))
    return out


# ---------------------------------------------------------------------------
# Per-entrypoint accumulation unit.
# ---------------------------------------------------------------------------
class Unit:
    __slots__ = ("fn", "file", "line", "lang", "n_records",
                 "written", "referenced", "boundary_groups",
                 "mutating_callees")

    def __init__(self, fn: str):
        self.fn = fn
        self.file = ""
        self.line = 0
        self.lang = ""
        self.n_records = 0
        # group -> set(member_key) WRITTEN by a mutating sink in the closure
        self.written: dict[str, set[str]] = {}
        # group -> set(member_key) REFERENCED anywhere in the closure
        self.referenced: dict[str, set[str]] = {}
        # groups whose closure references a boundary-crossing op
        self.boundary_groups: set[str] = set()
        self.mutating_callees: set[str] = set()

    def _add(self, store: str, group: str, mkey: str) -> None:
        d = getattr(self, store)
        d.setdefault(group, set()).add(mkey)


def _closure_node_texts(rec: dict) -> list[str]:
    """Closure NODE texts for the per-node member classifier: source var+fn,
    sink callee+cell+fn, every hop ir/via/fn, every guard expr."""
    out: list[str] = []
    src = rec.get("source") or {}
    out.append(str(src.get("var") or ""))
    out.append(str(src.get("fn") or ""))
    sink = rec.get("sink") or {}
    out.append(str(sink.get("callee") or ""))
    out.append(str(sink.get("cell") or ""))
    out.append(str(sink.get("fn") or ""))
    for h in rec.get("hops") or []:
        if not isinstance(h, dict):
            continue
        out.append(str(h.get("ir") or ""))
        out.append(str(h.get("via") or ""))
        out.append(str(h.get("fn") or ""))
    for g in rec.get("guard_nodes") or []:
        if isinstance(g, dict):
            out.append(str(g.get("expr") or ""))
    return [t for t in out if t]


def _sink_write_texts(rec: dict) -> list[str]:
    """The node texts that identify the WRITE TARGET of a mutating sink: the sink
    callee and cell (the field/collection cell being written)."""
    sink = rec.get("sink") or {}
    if str(sink.get("kind") or "") not in _MUTATING_SINK_KINDS:
        return []
    return [t for t in (str(sink.get("callee") or ""),
                        str(sink.get("cell") or "")) if t]


def build_units(dataflow_path: Path, ws_root: Path,
                include_oos: bool = False) -> tuple[dict, list[str], dict]:
    """Fold dataflow_paths.jsonl into per-ENTRYPOINT Units, tagging written /
    referenced group members and boundary-crossing groups. Returns
    (units_by_fn, warnings, stats)."""
    units: dict[str, Unit] = {}
    warnings: list[str] = []
    n_total = n_degraded = 0
    if not dataflow_path.is_file():
        warnings.append(f"dataflow_paths absent: {dataflow_path}")
        return units, warnings, {"n_total": 0, "n_degraded": 0}
    with dataflow_path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            n_total += 1
            if rec.get("degraded"):
                n_degraded += 1
                continue
            fn = _entrypoint_of(rec)
            if not fn:
                continue
            fpath = _fn_file(rec, fn)
            if not _in_scope_file(fpath, ws_root, include_oos):
                continue
            u = units.get(fn)
            if u is None:
                u = Unit(fn)
                u.file = fpath
                u.line = _fn_line(rec, fn)
                u.lang = str(rec.get("language") or "")
                units[fn] = u
            u.n_records += 1
            if not u.file and fpath:
                u.file = fpath

            node_texts = _closure_node_texts(rec)
            # REFERENCED members: any closure node naming a member.
            for t in node_texts:
                for group, mkey, _agg in _member_hits(t):
                    u._add("referenced", group, mkey)
                if _BOUNDARY_CROSS.search(t):
                    # attribute the boundary crossing to every group the closure
                    # otherwise references (a crossTick belongs to the
                    # tick_liquidity / fee_growth / observation families).
                    pass
            # boundary attribution: if ANY closure node is a boundary op, mark the
            # groups that are referenced in this same record's closure.
            has_boundary = any(_BOUNDARY_CROSS.search(t) for t in node_texts)
            if has_boundary:
                for t in node_texts:
                    for group, _mkey, _agg in _member_hits(t):
                        u.boundary_groups.add(group)

            # WRITTEN members: only the mutating sink's write-target texts.
            wtexts = _sink_write_texts(rec)
            if wtexts:
                sink = rec.get("sink") or {}
                callee = str(sink.get("callee") or "")
                if callee:
                    u.mutating_callees.add(callee)
                for t in wtexts:
                    for group, mkey, _agg in _member_hits(t):
                        u._add("written", group, mkey)
    stats = {"n_total": n_total, "n_degraded": n_degraded}
    if n_total and n_degraded == n_total:
        warnings.append(
            f"ALL {n_total} dataflow records are DEGRADED (substrate-starved: "
            f"compile-fail / go-dataflow timeout) - the coupled-update diff is "
            f"vacuously empty because the call graph never materialized. Re-run "
            f"go-dataflow.py scoped to the in-scope package (--alt-dataflow).")
    return units, warnings, stats


def compute_groups(units: dict) -> dict:
    """Per coupled GROUP: FULL(G) = workspace-wide union of REFERENCED members
    (the members the pool actually implements). A group is COUPLED (class present)
    iff |FULL(G)| >= 2 (a coupling invariant needs >=2 members). For each mutator
    of a coupled group, partial-update iff its WRITTEN subset is a proper non-empty
    subset of FULL(G); boundary-cross iff it crosses a boundary in G but does not
    write G's AGGREGATE member."""
    # workspace-wide observed (referenced) member set per group
    observed: dict[str, set[str]] = {}
    for u in units.values():
        for group, mset in u.referenced.items():
            observed.setdefault(group, set()).update(mset)
        for group, mset in u.written.items():
            observed.setdefault(group, set()).update(mset)
    coupled_groups = {g: ms for g, ms in observed.items() if len(ms) >= 2}

    # aggregate member keys per group (from the spec)
    agg_keys = {
        g: {mkey for (mkey, _rx, is_agg) in members if is_agg}
        for g, members in _GROUPS.items()
    }

    per_group: dict[str, dict] = {}
    survivor_rows: dict[str, dict] = {}  # fn -> row (dedup across groups)
    for group, full in coupled_groups.items():
        mutators: list[str] = []
        full_update: list[str] = []
        partial: list[str] = []
        boundary_surv: list[str] = []
        for fn, u in units.items():
            written = u.written.get(group, set())
            crosses = group in u.boundary_groups
            if not written and not crosses:
                continue
            if written:
                mutators.append(fn)
                if written >= full:  # writes the whole observed coupled group
                    full_update.append(fn)
                else:                # proper non-empty subset -> partial update
                    partial.append(fn)
                    _record_survivor(survivor_rows, fn, u, group, full,
                                     written, "partial-update",
                                     agg_keys.get(group, set()))
            # boundary crossing without re-establishing the aggregate member
            if crosses:
                wrote_agg = bool(written & agg_keys.get(group, set()))
                if not wrote_agg:
                    boundary_surv.append(fn)
                    _record_survivor(survivor_rows, fn, u, group, full,
                                     written, "boundary-cross",
                                     agg_keys.get(group, set()))
        per_group[group] = {
            "full_members": sorted(full),
            "aggregate_members": sorted(agg_keys.get(group, set()) & full),
            "n_mutators": len(set(mutators)),
            "n_full_update": len(set(full_update)),
            "n_partial_update": len(set(partial)),
            "n_boundary_cross": len(set(boundary_surv)),
            "kept_full_update": sorted({_short_fn(f) for f in full_update}),
        }
    return {
        "observed_members": {g: sorted(m) for g, m in observed.items()},
        "coupled_groups": sorted(coupled_groups),
        "per_group": per_group,
        "survivors": survivor_rows,
        "class_present": bool(coupled_groups),
    }


def _record_survivor(store: dict, fn: str, u: Unit, group: str,
                     full: set, written: set, reason: str,
                     agg_keys: set) -> None:
    row = store.get(fn)
    if row is None:
        row = {
            "fn": fn, "file": u.file, "line": u.line, "lang": u.lang,
            "groups": {}, "reasons": set(),
        }
        store[fn] = row
    row["reasons"].add(reason)
    g = row["groups"].setdefault(group, {
        "full_members": sorted(full),
        "written_members": sorted(written),
        "missing_members": sorted(full - written),
        "aggregate_members": sorted(agg_keys & full),
        "wrote_aggregate": bool(written & agg_keys),
        "reasons": [],
    })
    if reason not in g["reasons"]:
        g["reasons"].append(reason)


def make_obligation(row: dict, invariant_id: str,
                    permissionless: bool = True) -> dict:
    fn = row["fn"]
    short = _short_fn(fn)
    contract = _contract_of(fn)
    src_ref = row["file"] + (f":{row['line']}" if row["line"] else "")
    reasons = sorted(row["reasons"])
    groups = row["groups"]
    # pick the most-severe group description for the narrative
    parts = []
    broken = []
    for group, gi in groups.items():
        miss = gi["missing_members"]
        wrote = gi["written_members"]
        if "boundary-cross" in gi["reasons"] and not gi["wrote_aggregate"]:
            parts.append(
                f"group '{group}': closure crosses a tick/bin boundary but does "
                f"NOT re-write the aggregate member(s) {gi['aggregate_members']} "
                f"(wrote {wrote or 'none of the group'})")
        else:
            parts.append(
                f"group '{group}': writes SUBSET {wrote} of the coupled member "
                f"set {gi['full_members']}, MISSING {miss} (coupled members must "
                f"move together)")
        broken.append(f"INV-AMM-COUPLED-{group.upper()}")
    root = (
        f"Entrypoint '{fn}' mutates AMM structural-accounting state but updates "
        f"only a PROPER SUBSET of a coupled accounting group / crosses a tick|bin "
        f"boundary without re-establishing the group aggregate: "
        + "; ".join(parts)
        + ". Concentrated-liquidity structural-desync class: an attacker "
        "mints/burns/swaps at the boundary so the pool's internal accounting "
        "(liquidityNet, feeGrowth, observation index, virtual reserve) desyncs "
        "from real balances, then withdraws against the phantom accounting."
    )
    return {
        "schema": "auditooor.amm_structural_manipulation.v1",
        "obligation_type": "amm-structural-manipulation",
        "contract": contract,
        "function": short,
        "function_signature": fn,
        "language": row.get("lang", ""),
        "source_refs": [src_ref] if src_ref else [],
        "file": row["file"],
        "line": row["line"],
        "coupled_groups": {
            g: {
                "full_members": gi["full_members"],
                "written_members": gi["written_members"],
                "missing_members": gi["missing_members"],
                "aggregate_members": gi["aggregate_members"],
                "wrote_aggregate": gi["wrote_aggregate"],
                "reasons": gi["reasons"],
            } for g, gi in groups.items()
        },
        "survivor_reasons": reasons,
        "attack_class": "amm-structural-accounting-coupled-update-desync",
        "permissionless": bool(permissionless),
        "priority_rank": 0 if permissionless else 1,
        "likely_severity": "high",
        "broken_invariant_ids": [invariant_id] + broken,
        "root_cause_hypothesis": root,
        "quality_gate_status": "needs_source",
        "proof_status": "needs_source",
        "advisory_only": True,
        "needs_source": True,
        "learning_route": "mine-source",
        "falsification_requirements": [
            "COUPLED_WRITE: prove the MISSING coupled member(s) are NOT also "
            "written elsewhere in this fn's forward closure (a sibling helper that "
            "updates the aggregate liquidity / feeGrowthGlobal / observationIndex "
            "N hops away KILLS the lead). The write set must be a PROPER subset of "
            "the coupled group on EVERY path.",
            "BOUNDARY_REACHABLE: confirm the tick/bin boundary can be reached with "
            "attacker-chosen mint/burn/swap bounds inside one tx (the tick is "
            "crossable / the bin edge is hittable), not an admin-only path.",
            "DESYNC_TO_VALUE: show the accounting desync (phantom liquidity / "
            "stale feeGrowth / non-monotonic observation / virtual!=real) lets the "
            "attacker withdraw or mint MORE than deposited (net extraction).",
        ],
        "next_command": (
            "read the mutator + its callee closure; if the missing coupled member "
            "is never re-established on the boundary path, author the "
            "structural-accounting invariant (sum(component)==aggregate / "
            "index-monotonic / virtual==real) harness and drive an executed PoC."
        ),
    }


def _permissionless(u: Unit) -> bool:
    try:
        return _is_permissionless_body(u)
    except Exception:
        return True


def run(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--src-root", default=None,
                    help="in-scope source root used for the scope filter "
                         "(defaults to the workspace root)")
    ap.add_argument("--dataflow", default=None,
                    help="override dataflow_paths.jsonl path")
    ap.add_argument("--alt-dataflow", default=None,
                    help="additional dataflow jsonl to UNION (a scoped run)")
    ap.add_argument("--include-oos", action="store_true",
                    help="do NOT apply the scope OOS filter (debug)")
    ap.add_argument("--invariant-id",
                    default="INV-AMM-STRUCTURAL-COUPLED-UPDATE",
                    help="broken_invariant_id stamped on every obligation")
    ap.add_argument("--emit", default=None,
                    help="output jsonl path (default "
                         "<ws>/.auditooor/amm_structural_manipulation_obligations.jsonl)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit non-zero (rc=2) if the dataflow substrate is "
                         "vacuous (no records materialized)")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    scope_root = Path(args.src_root).expanduser().resolve() if args.src_root else ws
    df = Path(args.dataflow).expanduser() if args.dataflow else \
        ws / ".auditooor" / "dataflow_paths.jsonl"

    units, warnings, stats = build_units(df, scope_root,
                                         include_oos=args.include_oos)

    alt_paths: list[Path] = []
    if args.alt_dataflow:
        alt_paths.append(Path(args.alt_dataflow).expanduser())
    if not args.dataflow:
        for sib in sorted((ws / ".auditooor").glob("dataflow_paths.*.jsonl")):
            if sib.resolve() != df.resolve():
                alt_paths.append(sib)
    for alt in alt_paths:
        au, aw, ast = build_units(alt, scope_root, include_oos=args.include_oos)
        warnings.extend(aw)
        stats["n_total"] = stats.get("n_total", 0) + ast.get("n_total", 0)
        stats["n_degraded"] = stats.get("n_degraded", 0) + ast.get("n_degraded", 0)
        for fn, a in au.items():
            u = units.get(fn)
            if u is None:
                units[fn] = a
                continue
            for g, ms in a.written.items():
                u.written.setdefault(g, set()).update(ms)
            for g, ms in a.referenced.items():
                u.referenced.setdefault(g, set()).update(ms)
            u.boundary_groups |= a.boundary_groups
            u.mutating_callees |= a.mutating_callees
            u.n_records += a.n_records
            if not u.file:
                u.file = a.file

    res = compute_groups(units)

    # permissionless ranking per survivor
    perm: dict[str, bool] = {}
    for fn in res["survivors"]:
        perm[fn] = _permissionless(units[fn]) if fn in units else True

    obligations = []
    _seen = set()
    for fn, row in res["survivors"].items():
        # convert reasons set to sorted list for serialization
        row = dict(row)
        row["reasons"] = sorted(row["reasons"]) if isinstance(row["reasons"], set) \
            else row["reasons"]
        dk = (row["file"], row["line"], _short_fn(fn))
        if dk in _seen:
            continue
        _seen.add(dk)
        obligations.append(make_obligation(row, args.invariant_id,
                                            permissionless=perm.get(fn, True)))

    emit = Path(args.emit).expanduser() if args.emit else \
        ws / ".auditooor" / "amm_structural_manipulation_obligations.jsonl"
    emit.parent.mkdir(parents=True, exist_ok=True)
    with emit.open("w", encoding="utf-8") as fh:
        for ob in obligations:
            fh.write(json.dumps(ob) + "\n")

    n_records = stats.get("n_total", 0)
    substrate_vacuous = (n_records == 0) or (not units and n_records == 0)
    class_present = res["class_present"]
    if substrate_vacuous:
        status = "substrate_vacuous"
    elif not class_present:
        status = "class_absent"          # honest cited-empty over real substrate
    elif obligations:
        status = "survivors"
    else:
        status = "all_full_coupled"      # class present, every mutator full-couples

    summary = {
        "schema": "auditooor.amm_structural_manipulation_reasoner.v1",
        "workspace": str(ws),
        "src_root": str(scope_root),
        "dataflow": str(df),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "n_records": n_records,
        "n_degraded": stats.get("n_degraded", 0),
        "n_entrypoint_units": len(units),
        "class_present": class_present,
        "status": status,
        "substrate_vacuous": substrate_vacuous,
        "coupled_groups": res["coupled_groups"],
        "observed_members": res["observed_members"],
        "per_group": res["per_group"],
        "survivors": [
            {
                "fn": _short_fn(fn),
                "signature": fn,
                "file": row["file"], "line": row["line"],
                "reasons": sorted(row["reasons"]) if isinstance(row["reasons"], set)
                else row["reasons"],
                "groups": {
                    g: {"written": gi["written_members"],
                        "missing": gi["missing_members"],
                        "full": gi["full_members"]}
                    for g, gi in row["groups"].items()
                },
                "permissionless": perm.get(fn, True),
            }
            for fn, row in res["survivors"].items()
        ],
        "obligations_written": len(obligations),
        "obligations_path": str(emit),
        "warnings": warnings,
    }

    if args.json:
        print(json.dumps(summary, indent=2, default=list))
    else:
        print(f"[amm-structural] {ws.name}: status={status} "
              f"class_present={class_present} records={n_records} "
              f"units={len(units)} coupled_groups={res['coupled_groups']}")
        for g, gi in res["per_group"].items():
            print(f"  GROUP {g}: members={gi['full_members']} "
                  f"|MUTATORS|={gi['n_mutators']} full={gi['n_full_update']} "
                  f"partial={gi['n_partial_update']} boundary={gi['n_boundary_cross']}")
            if gi["kept_full_update"]:
                print(f"    KEPT (full coupled update): {gi['kept_full_update']}")
        for s in summary["survivors"][:40]:
            rank = "permissionless" if s.get("permissionless") else "role-gated"
            print(f"  SURVIVOR [{rank}] {s['fn']} {s['reasons']} "
                  f"groups={list(s['groups'])} {s['file']}:{s['line']}")
        for w in warnings:
            print(f"  WARN {w}", file=sys.stderr)
        print(f"  -> {len(obligations)} obligation(s) -> {emit}")

    if args.fail_closed and substrate_vacuous:
        return 2
    return summary


if __name__ == "__main__":
    out = run()
    if out == 2:
        sys.exit(2)
