#!/usr/bin/env python3
"""oracle-spot-price-manipulation-reasoner.py - LOGIC CAPABILITY (Oracle/TWAP class).

docs/LOGIC_ARSENAL_ROADMAP.md, perpetual logic-arsenal loop. This is a SET /
REACHABILITY / CLOSURE query over the OWNED go-dataflow / Slither data-dependency
backend. It is NOT a regex for `getReserves` / `slot0`.

THE LOGIC TRIPLE (extracted from the spot-price-manipulation 0-day class -
Mango Markets $114M, Cheese Bank $3.3M, Inverse Finance $15.6M, bZx, Warp,
Cream single-source valuation drains):
  ASSUMPTION (protocol trusts):  a price / valuation V that AUTHORIZES a
    value-moving decision (the released amount of a borrow / mint / liquidation /
    withdraw, or a quote feeding one) reflects a MANIPULATION-RESISTANT market
    price - one that an attacker cannot move to an arbitrary value inside a single
    transaction.
  INVARIANT (must hold):
      SPOT_TO_VALUE = { external/public entrypoint f : some node in f's forward
                        callee closure READS a SPOT price - a single-block AMM
                        reserve / pool-slot / balance-ratio read (getReserves /
                        slot0 / getAmountOut / balanceOf-ratio / instantaneous
                        NAV = totalAssets/totalShares) - AND that value REACHES a
                        VALUE-DECISION sink (mint / burn / value-move /
                        safeTransfer(From) fund move, or a borrow/liquidation/
                        redeem/swap quote) in the same closure }
      TWAP_XSOURCE  = { f in SPOT_TO_VALUE : some node in f's forward closure
                        interposes a MANIPULATION-RESISTANT second reading on the
                        priced value - a TWAP / cumulative-price / time-weighted /
                        Chainlink latestRoundData-with-staleness read, a two-source
                        deviation bound, a two-oracle min|max, or a
                        checkpoint/historical average }
      The protocol requires   SPOT_TO_VALUE  is a SUBSET of  TWAP_XSOURCE .
  TRUST-BOUNDARY (crossed): the spot price is read from an AMM pool / single
    reserve snapshot / instantaneous balance ratio the ATTACKER controls inside
    the same atomic tx (flash-loan-pump the pool, then borrow/mint/liquidate at
    the manufactured price), with no independent second source to reject it.
  FINDING = the SET-DIFFERENCE  SPOT_TO_VALUE \\ TWAP_XSOURCE : every entrypoint
    that lets a spot-derived price authorize a value move with no TWAP / second-
    source cross-check in its closure. Emitted as an
    `oracle-spot-price-manipulation` obligation.

WHY THIS IS LOGIC, NOT A SHAPE (guard-rail satisfied)
  A shape would be `body_contains('getReserves') and not body_contains('twap')`.
  This query differs on the three axes that make it a graph-set relation:
    (a) membership in SPOT_TO_VALUE is TRANSITIVE forward-closure reachability - a
        spot read in an N-hop pricing helper whose result flows to a fund move in
        a DIFFERENT function is still classified (impossible for a body-scoped
        regex; the source, the price helper and the value sink live in three
        different bodies);
    (b) the answer is a RELATION BETWEEN TWO SETS of functions (the subset test
        SPOT_TO_VALUE is a subset of TWAP_XSOURCE) whose finding is the SET-
        DIFFERENCE, not a boolean over one function's text - a TWAP/second-source
        node in ANY node of the closure (any file, any hop) removes the fn from
        the diff;
    (c) it is orthogonal to the conservation-haircut reasoner (LOGIC #5): a
        HAIRCUT (LTV / collateral-factor / discount) does NOT satisfy TWAP_XSOURCE
        here - Mango applied collateral weights and was still drained because the
        weighted price was SPOT. Only a manipulation-resistant SECOND READING
        (time-weighting / independent source / deviation bound) removes a fn.
        A per-node classifier is used (exactly as the owned solvency_guard_pred is
        a per-node predicate); the LOGIC is the transitive-closure set-difference
        wrapped around it, not the node classifier.

OWNED BACKEND CONSUMED (nothing new is built here)
  <ws>/.auditooor/dataflow_paths.jsonl (schema dataflow_path.v1) produced by
  tools/go-dataflow.py (go/ssa + callgraph + backward DefUse) for the Go arm and
  the Slither data_dependency arm for Solidity. Auto-unions any scoped sidecar
  dataflow_paths.*.jsonl. Per entrypoint the CLOSURE node set consulted is:
  source.var/fn, sink.callee/fn, every hop.ir/via/fn, and every
  guard_nodes[].expr. SPOT_TO_VALUE reads sink.kind + the closure node texts;
  TWAP_XSOURCE reads whether ANY closure node satisfies twap_second_source_pred.
  Reuses the exemplar callgraph-set-difference-hunter helpers (_entrypoint_of /
  _fn_file / _fn_line / _in_scope_file / _short_fn / _contract_of /
  is_permissionless) - single source of truth for record parsing + scope.

OUTPUT
  <ws>/.auditooor/oracle_spot_price_obligations.jsonl - one row per survivor,
  schema `auditooor.oracle_spot_price_manipulation.v1`, exploit_queue-ingest
  compatible (contract/function/source_refs/root_cause_hypothesis/attack_class/
  broken_invariant_ids/quality_gate_status='needs_source'). exploit-queue.py
  ingests it via _gather_from_oracle_spot_price_obligations -> the queue ->
  per-fn-mimo-batch-gen OPEN-OBLIGATIONS block. A summary is printed / emitted
  (--json) with |SPOT_TO_VALUE|, |TWAP_XSOURCE|, |SPOT\\TWAP|, the KEPT
  (spot-and-twap-guarded, proving the subtraction is non-vacuous) and survivors.
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
# the two logic reasoners share ONE source of truth for entrypoint identity and
# the OOS filter (a vendored cosmos-sdk keeper read is not an in-scope lead).
# ---------------------------------------------------------------------------
_CSDH_PATH = _HERE / "callgraph-set-difference-hunter.py"
_spec = importlib.util.spec_from_file_location("_csdh_reuse", _CSDH_PATH)
_csdh = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_csdh)  # type: ignore[union-attr]

_entrypoint_of = _csdh._entrypoint_of
_fn_file = _csdh._fn_file
_fn_line = _csdh._fn_line
_in_scope_file = _csdh._in_scope_file
_short_fn = _csdh._short_fn
_contract_of = _csdh._contract_of
is_permissionless = _csdh.is_permissionless

# ---------------------------------------------------------------------------
# VALUE-DECISION sink taxonomy: the money-moving / fund-release sinks whose
# amount a manipulated price authorizes. mint/burn (supply change priced by the
# oracle), value-move (bank/SendCoins move OUT), safeTransfer(From) (ERC20 move).
# state_var_read / authority / storage-value are NOT value decisions.
# ---------------------------------------------------------------------------
_VALUE_DECISION_SINK_KINDS = {
    "mint", "burn", "value-move", "safeTransfer", "safeTransferFrom",
}
# A value-decision can also be a QUOTE/valuation fn whose callee names an ACTUAL
# fund-release primitive even when the sink kind is a plain state-write (the
# priced quote is stored then paid). Restricted to genuine coin/fund MOVES so a
# config setter that merely NAMES a swap/collateral parameter (SetMaxSwapInValue,
# UpdateCollateralFactor) does NOT count - those are admin writes, not releases.
_VALUE_DECISION_CALLEE = re.compile(
    r"mintcoins|burncoins|sendcoins|"
    r"safetransfer|_transfer\b|transferfrom|"
    r"disburse|payout|seize|"
    r"\bborrow\b|\bliquidat|\bredeem\b|\brepay\b",
    re.IGNORECASE,
)
# Config-writer callees (admin setters) never count as a value decision even if
# their name embeds a money verb (SetMaxSwapInValue -> "swap"): the write changes
# a parameter, it does not move funds.
_CONFIG_WRITER_CALLEE = re.compile(
    r"\.(set|update|toggle|pause|unpause|enable|disable|configure)[a-z0-9_]*\s*$",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# SPOT price source predicate. A single-block, attacker-movable price reading:
#   - AMM reserve / pool-slot reads: getReserves, slot0, observeSingle-less,
#     getAmountOut/getAmountsIn (constant-product quote), token0/1Price,
#     sqrtPriceX96 (the instantaneous slot0 field), price0/1 (non-cumulative);
#   - balance-ratio / instantaneous NAV: balanceOf(...) used as a ratio,
#     totalAssets/totalShares, navPerShare, SetNetAssetValue / GetNetAssetValue
#     computed from a live bank balance, getPrice/spotPrice/currentPrice/priceOf
#     (a live single read, not a checkpointed average).
# Cumulative / time-weighted variants are EXCLUDED here (they are the FIX -
# handled by twap_second_source_pred), so `price0Cumulative` / `observe` do NOT
# count as a spot source.
# ---------------------------------------------------------------------------
_SPOT_IDENT = re.compile(
    r"get[_]?reserves|reserve[01]|"
    r"slot0|sqrtpricex96|"
    r"get[_]?amounts?(?:out|in)|"
    r"token[01]price|"
    r"spot[_]?price|current[_]?price|price[_]?of|priceof|"
    r"getprice|get[_]?spot|"
    r"net[_]?asset[_]?value|netassetvalue|nav[_]?per[_]?share|navpershare|"
    r"total[_]?assets\s*/\s*total[_]?shares|"
    r"balanceof\s*\(",
    re.IGNORECASE,
)
# `price0Cumulative` / `priceCumulative` are a TWAP building block, NOT a spot
# read - subtract them so a cumulative read does not falsely enter SPOT.
_SPOT_ANTI = re.compile(r"cumulative|time[_]?weighted|twap", re.IGNORECASE)


def spot_price_source_pred(text: str) -> bool:
    """True if a single closure node text reads an attacker-movable SPOT price
    (single-block reserve / slot / balance-ratio / instantaneous NAV). A
    per-node predicate; the LOGIC is the closure set-difference around it."""
    if not text:
        return False
    if _SPOT_ANTI.search(text):
        return False
    return bool(_SPOT_IDENT.search(text))


# ---------------------------------------------------------------------------
# TWAP / SECOND-SOURCE predicate - the manipulation-resistant reading that,
# present ANYWHERE in the closure, removes the fn from the diff:
#   - time-weighting: TWAP, price0/1Cumulative, timeWeighted, observe/consult
#     (UniV3 OracleLibrary.consult IS a TWAP call), cumulative;
#   - independent second source with freshness: latestRoundData / latestAnswer
#     paired with a staleness / updatedAt check, chainlink, aggregator;
#   - cross-source agreement: deviation / maxDeviation bound, two-oracle
#     min|max, price-vs-oracle compare, checkpoint/historical average.
# ---------------------------------------------------------------------------
_TWAP_IDENT = re.compile(
    r"twap|time[_]?weighted|"
    r"price[01]?cumulative|pricecumulative|cumulative[_]?price|"
    r"\bobserve\b|observations?|oraclelibrary|\bconsult\b|"
    r"latestrounddata|updatedat|stale|freshness|heartbeat|"
    r"chainlink|aggregator|pricefeed|"
    r"deviation|max[_]?deviation|"
    r"price[_]?checkpoint|moving[_]?average|"
    r"second[_]?source|two[_]?oracle|cross[_]?check|"
    # pre/post balance-snapshot conservation compare (balBefore/assetBalBefore/
    # ...BalAfter) - an independent second reading of the SAME quantity that
    # rejects a manipulated single read; the FOT-style `balanceOf(this) >
    # assetBalBefore` idiom. Deliberately NARROW (the `Bal(ance)Before/After`
    # token) so a tendermint LoadSnapshotChunk / a generic `checkpoint` handler
    # is NOT mistaken for a price second-source.
    r"bal(?:ance)?before|bal(?:ance)?after",
    re.IGNORECASE,
)


def twap_second_source_pred(text: str) -> bool:
    """True if a single closure node text is a manipulation-resistant second
    reading (TWAP / cumulative / independent-source-with-staleness / deviation
    bound). Present in ANY closure node it removes the fn from the diff."""
    if not text:
        return False
    return bool(_TWAP_IDENT.search(text))


# ---------------------------------------------------------------------------
# Per-entrypoint accumulation unit.
# ---------------------------------------------------------------------------
class Unit:
    __slots__ = ("fn", "file", "line", "lang", "n_records",
                 "spot_nodes", "value_sink_kinds", "value_sink_callees",
                 "twap_nodes", "guard_exprs")

    def __init__(self, fn: str):
        self.fn = fn
        self.file = ""
        self.line = 0
        self.lang = ""
        self.n_records = 0
        self.spot_nodes: set[str] = set()
        self.value_sink_kinds: set[str] = set()
        self.value_sink_callees: set[str] = set()
        self.twap_nodes: set[str] = set()
        self.guard_exprs: list[str] = []


def _closure_node_texts(rec: dict) -> list[str]:
    """The set of closure NODE texts consulted for the per-node predicates:
    source var+fn, sink callee+fn, every hop ir/via/fn, every guard expr."""
    out: list[str] = []
    src = rec.get("source") or {}
    out.append(str(src.get("var") or ""))
    out.append(str(src.get("fn") or ""))
    sink = rec.get("sink") or {}
    out.append(str(sink.get("callee") or ""))
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


def build_sets(dataflow_path: Path, ws_root: Path,
               include_oos: bool = False) -> tuple[dict, list[str]]:
    """Fold dataflow_paths.jsonl into per-ENTRYPOINT Units, tagging SPOT-source
    membership, value-decision-sink reachability and TWAP/second-source nodes
    across the closure. Returns (units_by_fn, warnings)."""
    units: dict[str, Unit] = {}
    warnings: list[str] = []
    n_total = n_degraded = 0
    if not dataflow_path.is_file():
        warnings.append(f"dataflow_paths absent: {dataflow_path}")
        return units, warnings
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
            for t in node_texts:
                if spot_price_source_pred(t):
                    u.spot_nodes.add(t[:160])
                if twap_second_source_pred(t):
                    u.twap_nodes.add(t[:160])

            sink = rec.get("sink") or {}
            skind = str(sink.get("kind") or "")
            callee = str(sink.get("callee") or "")
            if skind in _VALUE_DECISION_SINK_KINDS:
                u.value_sink_kinds.add(skind)
                if callee:
                    u.value_sink_callees.add(callee)
            elif (callee and _VALUE_DECISION_CALLEE.search(callee)
                  and not _CONFIG_WRITER_CALLEE.search(callee)):
                # a priced quote whose callee names a genuine fund-release action
                # even though the direct sink kind is a plain write (and is NOT an
                # admin config setter).
                u.value_sink_kinds.add(skind or "quote-release")
                u.value_sink_callees.add(callee)

            for g in rec.get("guard_nodes") or []:
                if isinstance(g, dict) and g.get("expr"):
                    u.guard_exprs.append(str(g["expr"]))
    if n_total and n_degraded == n_total:
        warnings.append(
            f"ALL {n_total} dataflow records are DEGRADED (substrate-starved: "
            f"compile-fail / go-dataflow timeout) - the set-difference is "
            f"vacuously empty because the call graph never materialized, NOT "
            f"because SPOT_TO_VALUE is a subset of TWAP_XSOURCE. Re-run "
            f"go-dataflow.py scoped to the in-scope package (see --alt-dataflow).")
    return units, warnings


def classify(units: dict, ws: Path | None = None) -> dict:
    """SPOT_TO_VALUE = spot-source node AND value-decision sink in closure.
    TWAP_XSOURCE  = those with a TWAP/second-source node in closure.
    SURVIVORS     = SPOT_TO_VALUE \\ TWAP_XSOURCE."""
    spot_to_value: set[str] = set()
    twap_xsource: set[str] = set()
    permissionless: dict[str, bool] = {}
    for fn, u in units.items():
        if u.spot_nodes and u.value_sink_kinds:
            spot_to_value.add(fn)
            if u.twap_nodes:
                twap_xsource.add(fn)
    survivors = sorted(spot_to_value - twap_xsource)
    kept = sorted(spot_to_value & twap_xsource)
    for fn in survivors:
        # is_permissionless reads the fn body window off (file,line) - our Unit
        # shares those slots. Fail-safe True (max scrutiny) if the body can't be
        # read; permissionless is a ranking hint, never correctness.
        try:
            permissionless[fn] = is_permissionless(units[fn])
        except Exception:
            permissionless[fn] = True
    return {
        "spot_to_value": sorted(spot_to_value),
        "twap_xsource": sorted(twap_xsource),
        "survivors": survivors,
        "kept": kept,
        "permissionless": permissionless,
    }


def make_obligation(u: Unit, invariant_id: str,
                    permissionless: bool = True) -> dict:
    short = _short_fn(u.fn)
    contract = _contract_of(u.fn)
    src_ref = u.file + (f":{u.line}" if u.line else "")
    kinds = sorted(u.value_sink_kinds)
    spot = sorted(u.spot_nodes)[:3]
    callees = sorted(u.value_sink_callees)[:4]
    root = (
        f"Entrypoint '{u.fn}' derives a price/valuation from a SPOT single-block "
        f"read ({'; '.join(spot) if spot else 'reserve/slot/balance-ratio'}) that "
        f"reaches a value-decision sink ({', '.join(kinds)}"
        + (f" via {', '.join(callees)}" if callees else "")
        + ") with NO TWAP / cumulative-price / independent-second-source / "
        "deviation-bound node anywhere in its forward closure "
        "(set-difference SPOT_TO_VALUE\\TWAP_XSOURCE). Mango/Cheese/Inverse class: "
        "an attacker flash-pumps the pool/reserve inside one tx and the "
        "manufactured price authorizes an over-sized borrow/mint/liquidation."
    )
    return {
        "schema": "auditooor.oracle_spot_price_manipulation.v1",
        "obligation_type": "oracle-spot-price-manipulation",
        "contract": contract,
        "function": short,
        "function_signature": u.fn,
        "language": u.lang,
        "source_refs": [src_ref] if src_ref else [],
        "file": u.file,
        "line": u.line,
        "spot_source_nodes": spot,
        "value_sink_kinds": kinds,
        "value_sink_callees": callees,
        "attack_class": "oracle-spot-price-manipulation-no-twap-second-source",
        "permissionless": bool(permissionless),
        "priority_rank": 0 if permissionless else 1,
        "likely_severity": "high",
        "broken_invariant_ids": [invariant_id],
        "root_cause_hypothesis": root,
        "quality_gate_status": "needs_source",
        "proof_status": "needs_source",
        "advisory_only": True,
        "learning_route": "mine-source",
        "falsification_requirements": [
            "TWAP_CLOSURE: prove NO TWAP / cumulative-price / independent-source-"
            "with-staleness / deviation-bound reading is reachable in the fwd "
            "closure of this fn (twap_second_source_pred is False on every closure "
            "node) - a manipulation-resistant read N hops away in a pricing helper "
            "KILLS the lead. A HAIRCUT / collateral-factor does NOT kill it.",
            "SPOT_ATTACKER_MOVABLE: confirm the priced source is an AMM reserve / "
            "pool slot / instantaneous balance-ratio the attacker can move inside "
            "the SAME atomic tx (flash-loanable pool), not an admin-set constant.",
            "VALUE_MAGNITUDE: show the manufactured price scales a fund-moving "
            "amount (borrow/mint/liquidation/withdraw), producing net extraction.",
        ],
        "next_command": (
            "read the pricing helper + its callee closure; if no TWAP/second-"
            "source cross-check is reachable and the pool is flash-movable, author "
            "the price-manipulation invariant harness and drive an executed PoC."
        ),
    }


def run(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--dataflow", default=None,
                    help="override dataflow_paths.jsonl path")
    ap.add_argument("--alt-dataflow", default=None,
                    help="additional dataflow jsonl to UNION (a scoped package run)")
    ap.add_argument("--include-oos", action="store_true",
                    help="do NOT apply the scope OOS filter (debug)")
    ap.add_argument("--invariant-id",
                    default="INV-SPOT-PRICE-TWAP-SECOND-SOURCE-SUBSET",
                    help="broken_invariant_id stamped on every obligation")
    ap.add_argument("--emit", default=None,
                    help="output jsonl path (default "
                         "<ws>/.auditooor/oracle_spot_price_obligations.jsonl)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit non-zero if the dataflow substrate is fully "
                         "degraded (the set-difference could not be computed)")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    df = Path(args.dataflow).expanduser() if args.dataflow else \
        ws / ".auditooor" / "dataflow_paths.jsonl"

    units, warnings = build_sets(df, ws, include_oos=args.include_oos)

    # Union scoped sidecars + explicit --alt-dataflow (robust on heavy monorepos
    # whose merged sidecar timed out - mirrors the exemplar's auto-discovery).
    alt_paths: list[Path] = []
    if args.alt_dataflow:
        alt_paths.append(Path(args.alt_dataflow).expanduser())
    if not args.dataflow:
        for sib in sorted((ws / ".auditooor").glob("dataflow_paths.*.jsonl")):
            if sib.resolve() != df.resolve():
                alt_paths.append(sib)
    for alt in alt_paths:
        alt_units, alt_warn = build_sets(alt, ws, include_oos=args.include_oos)
        warnings.extend(alt_warn)
        for fn, au in alt_units.items():
            u = units.get(fn)
            if u is None:
                units[fn] = au
                continue
            u.spot_nodes |= au.spot_nodes
            u.twap_nodes |= au.twap_nodes
            u.value_sink_kinds |= au.value_sink_kinds
            u.value_sink_callees |= au.value_sink_callees
            u.guard_exprs.extend(au.guard_exprs)
            u.n_records += au.n_records
            if not u.file:
                u.file = au.file

    res = classify(units, ws=ws)
    perm = res.get("permissionless") or {}

    obligations = []
    _seen = set()
    for fn in res["survivors"]:
        u = units[fn]
        dk = (u.file, u.line, _short_fn(fn))
        if dk in _seen:
            continue
        _seen.add(dk)
        obligations.append(make_obligation(u, args.invariant_id,
                                            permissionless=perm.get(fn, True)))

    emit = Path(args.emit).expanduser() if args.emit else \
        ws / ".auditooor" / "oracle_spot_price_obligations.jsonl"
    emit.parent.mkdir(parents=True, exist_ok=True)
    with emit.open("w", encoding="utf-8") as fh:
        for ob in obligations:
            fh.write(json.dumps(ob) + "\n")

    substrate_degraded = any("DEGRADED" in w for w in warnings) and not units

    summary = {
        "schema": "auditooor.oracle_spot_price_reasoner.v1",
        "workspace": str(ws),
        "dataflow": str(df),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "n_entrypoint_units": len(units),
        "size_SPOT_TO_VALUE": len(res["spot_to_value"]),
        "size_TWAP_XSOURCE": len(res["kept"]),
        "size_DIFF_survivors": len(res["survivors"]),
        "kept_spot_and_twap": [_short_fn(f) for f in res["kept"]],
        "survivors": [
            {"fn": _short_fn(f), "signature": f,
             "file": units[f].file, "line": units[f].line,
             "spot_source_nodes": sorted(units[f].spot_nodes)[:3],
             "value_sink_kinds": sorted(units[f].value_sink_kinds),
             "permissionless": perm.get(f, True)}
            for f in res["survivors"]
        ],
        "obligations_written": len(obligations),
        "obligations_path": str(emit),
        "warnings": warnings,
        "substrate_degraded": substrate_degraded,
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[oracle-spot-price] {ws.name}: "
              f"|SPOT_TO_VALUE|={summary['size_SPOT_TO_VALUE']} "
              f"|TWAP_XSOURCE|={summary['size_TWAP_XSOURCE']} "
              f"survivors(SPOT\\TWAP)={summary['size_DIFF_survivors']} "
              f"-> {len(obligations)} oracle-spot-price-manipulation obligation(s)")
        if res["kept"]:
            print("  KEPT (spot + reaches TWAP/second-source, removed from diff): "
                  + ", ".join(summary["kept_spot_and_twap"]))
        for s in summary["survivors"][:40]:
            rank = "permissionless" if s.get("permissionless") else "role-gated"
            print(f"  SURVIVOR [{rank}] {s['fn']}  {sorted(s['value_sink_kinds'])}"
                  f"  spot={s['spot_source_nodes']}  {s['file']}:{s['line']}")
        for w in warnings:
            print(f"  WARN {w}", file=sys.stderr)
        print(f"  -> {emit}")

    if args.fail_closed and substrate_degraded:
        return 3
    return summary


if __name__ == "__main__":
    out = run()
    if out == 3:
        sys.exit(3)
