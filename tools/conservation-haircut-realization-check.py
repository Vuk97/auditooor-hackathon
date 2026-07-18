#!/usr/bin/env python3
"""conservation-haircut-realization-check.py - LOGIC CAPABILITY #5.

docs/LOGIC_ARSENAL_ROADMAP.md, capability 5:
  "every value that flows into a borrow / withdraw / quote path WITHOUT a haircut
   or second-source cross-check emits a conservation obligation."

This is a SET / REACHABILITY / COMPOSITION query over the OWNED go-dataflow /
Slither data-dependency backend, JOINED to the conservation/haircut invariant
family in the owned invariant ledger. It is NOT a token present/absent detector.

THE LOGIC TRIPLE (extracted from the value-realization-without-haircut 0-day class
- Compound cETH price=1 seed, bZx/Harvest oracle-spot, Euler/Silo LTV-skips,
  Warp/Cream single-source valuation, Rari/Fuse rate-manipulation drains):
  ASSUMPTION (protocol trusts):  a value V that AUTHORIZES a fund-releasing action
    (the released amount of a borrow/withdraw, or a quote/valuation feeding one)
    has already been REALIZED conservatively - discounted by a haircut (LTV /
    collateral factor / liquidation discount / fee-of-notional) OR corroborated by
    a SECOND source (a deviation bound, a TWAP-vs-spot compare, a pre/post balance
    snapshot conservation check) - before it moves funds.
  INVARIANT (must hold):
      VALUE_RELEASE = { external/public entrypoint f : f's forward callee closure
                        REACHES a value-RELEASE sink (funds-out: value-move /
                        safeTransfer) OR f is a quote/valuation fn, and the flowing
                        source is an externally-derived VALUE (amount/price/quote/
                        collateral/shares/assets/...) }
      HAIRCUT_XCHECK = { f in VALUE_RELEASE : some node in f's forward closure
                         applies a HAIRCUT (LTV / collateral-factor / discount /
                         *factor / /PRECISION|/1e|/bps scale-down) OR a SECOND-
                         SOURCE cross-check (deviation / TWAP-vs-spot / two-oracle
                         min|max / pre-post balance-snapshot conservation) on the
                         released value }
      The protocol requires   VALUE_RELEASE  is a SUBSET of  HAIRCUT_XCHECK .
  TRUST-BOUNDARY (crossed): the external value source (an oracle price, a returned
    quote, a user-supplied release amount) is consumed RAW - full-notional, single-
    source - to authorize the fund move.
  FINDING = the SET-DIFFERENCE  VALUE_RELEASE \\ HAIRCUT_XCHECK : every entrypoint
    that releases value derived from an un-haircut, un-cross-checked source. Emitted
    as a `conservation-haircut-realization` obligation, its broken_invariant_ids
    JOINED to any matching accounting_conservation / haircut / deviation row in the
    owned invariant ledger (so the obligation cites an AUTHORED conservation
    invariant the un-haircut path may violate).

WHY THIS IS LOGIC, NOT A SHAPE (guard-rail satisfied)
  A shape would be `body_contains('transfer') and not body_contains('ltv')`. This
  query differs on the three axes that make it a graph-set relation:
    (a) membership in VALUE_RELEASE is TRANSITIVE forward-closure reachability to a
        funds-out sink through N-hop helpers - a release moved by a helper is still
        classified (impossible for a body-scoped regex);
    (b) the answer is a relation between TWO SETS of functions (the subset test
        VALUE_RELEASE is a subset of HAIRCUT_XCHECK) whose finding is the SET-
        DIFFERENCE, not a boolean over one function's text - a haircut applied in
        ANY node of the closure (any file, any hop) removes the fn from the diff;
    (c) it is JOINED to a SECOND owned dataset (the conservation invariant family
        in the ledger) - the obligation carries the specific authored invariant id
        it threatens, a cross-dataset relation no token match performs.

OWNED BACKENDS CONSUMED (nothing new is built here)
  1. <ws>/.auditooor/dataflow_paths.jsonl (schema dataflow_path.v1) produced by
     tools/go-dataflow.py (go/ssa + callgraph + backward DefUse) for the Go arm and
     the Slither data_dependency arm for Solidity. Auto-unions any scoped sidecar
     dataflow_paths.*.jsonl (e.g. dataflow_paths.nexus.jsonl on axelar). VALUE_RELEASE
     reads sink.kind + source.var; HAIRCUT_XCHECK reads the closure guard_nodes[].expr.
  2. <ws>/.auditooor/invariant_ledger.json (rows[].invariant_family / statement /
     source_citations) - the conservation/haircut invariant SET the diff joins to.

OUTPUT
  <ws>/.auditooor/conservation_haircut_obligations.jsonl - one row per survivor,
  schema `auditooor.conservation_haircut_realization.v1`, exploit_queue-ingest
  compatible (contract/function/source_refs/root_cause_hypothesis/attack_class/
  broken_invariant_ids/quality_gate_status='needs_source'). exploit-queue.py ingests
  it via _gather_from_conservation_haircut_obligations -> the queue ->
  per-fn-mimo-batch-gen OPEN-OBLIGATIONS block.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent

# ---------------------------------------------------------------------------
# VALUE-RELEASE sink taxonomy. A fund-RELEASE sink moves value OUT to an actor
# (the borrow/withdraw arm). go-dataflow classifySink / the Solidity sink taxonomy
# emit:
#   value-move    - Cosmos SendCoins* / bank move OUT of a module (the release)
#   safeTransfer  - Solidity ERC20 transfer OUT (arg is a recipient)
# EXCLUDED by default (not a value RELEASE authorized by an external value):
#   safeTransferFrom (deposit PULL - value moves IN), mint (increase), burn (a
#   downward mutation - that is LOGIC #3's callgraph-set-difference territory,
#   not a fund-release-on-a-quote), authority / state_var_read / storage-value.
# The QUOTE/valuation arm is name-gated separately (a quote fn need not itself
# reach a funds-out sink; it PRODUCES the value another fn releases on).
# Override with --release-kinds.
# ---------------------------------------------------------------------------
_DEFAULT_RELEASE_KINDS = {"value-move", "safeTransfer"}

# A quote / valuation / preview / conversion entrypoint: its return value is a
# price/amount that AUTHORIZES a downstream release. Name-gated (the dataflow
# backend has no "returns-a-quote" sink kind), joined with the value-source
# predicate so a bare getter over a config int never qualifies.
_QUOTE_NAME = re.compile(
    r"quote|preview|convert(to|from)?|valuation|getamount|amountout|amountin|"
    r"get[_]?price|priceof|latestanswer|exchangerate|redeemvalue|assetsof|"
    r"sharesof|to[_]?assets|to[_]?shares|calc[_]?|compute[_]?value",
    re.IGNORECASE,
)

# The flowing SOURCE var must be an externally-derived VALUE (the released
# quantity / price / quote), not ctx / addr / permission plumbing. This narrows
# VALUE_RELEASE to paths where a VALUE authorizes the move (the whole point of a
# haircut). A pure ctx/recipient-address flow is not a value-realization.
_VALUE_VAR = re.compile(
    r"amount|amt|value|val|price|quote|fee|collateral|share|asset|coin|"
    r"payout|reward|redeem|deposit|withdraw|principal|debt|liquid|stake|"
    r"nav|notional|qty|balance|bal|rate|worth",
    re.IGNORECASE,
)

# A release-authorizing entrypoint by NAME (borrow/withdraw/redeem/... ) - used
# with the value-source predicate so an entrypoint whose var is generic (ctx) but
# whose NAME is a clear release path still qualifies.
_RELEASE_NAME = re.compile(
    r"borrow|withdraw|redeem|payout|release|refund|unlock|claim|"
    r"transferfee|sweep|disburse|distribut|settle|liquidat|repay|swap",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# The HAIRCUT-or-SECOND-SOURCE-CROSS-CHECK node predicate. Classifies a single
# guard/closure NODE (an expr string) as "this value was realized conservatively".
# The LOGIC is the transitive-closure set-difference + invariant JOIN wrapped
# around it, not this per-node classifier (a guard_pred is ALWAYS a per-node
# predicate, exactly as the owned has_guard_in_closure default guard is).
# ---------------------------------------------------------------------------

# (1) HAIRCUT: a value scaled DOWN by a risk parameter / discount / notional-fee
#     before it authorizes a release. LTV / collateral-factor / liquidation
#     discount / *factor / / PRECISION | / 1e.. | / bps | * ratio.
_HAIRCUT = re.compile(
    r"ltv|loan[_]?to[_]?value|collateral[_]?factor|collateralfactor|"
    r"liquidation[_]?(discount|incentive|penalty|bonus)|haircut|discount|"
    r"[*/]\s*\w*factor|[*/]\s*\w*ratio|/\s*1e\d|/\s*10\s*\*\*|/\s*precision|"
    r"/\s*(10000|1000|100)\b|/\s*bps|\bbps\b|\bmantissa\b|closefactor",
    re.IGNORECASE,
)

# (2) SECOND-SOURCE cross-check: the value is corroborated against an INDEPENDENT
#     source before release - an oracle deviation bound, a TWAP-vs-spot compare, a
#     two-oracle min/max, or a staleness+bound check.
_XCHECK = re.compile(
    r"deviat|twap|spot|secondary|second[_]?source|price0|price1|min\s*\(|"
    r"max\s*\(|maxprice|minprice|min[_]?answer|max[_]?answer|"
    r"updatedat|staleness|stale|heartbeat|chainlink|fallback[_]?oracle",
    re.IGNORECASE,
)

# (3) POST-STATE balance-SNAPSHOT conservation cross-check: an expr comparing a
#     pre/post balance snapshot against the claimed value (the released amount is
#     cross-checked against the ACTUAL token-balance delta - a second source of
#     truth for the quantity). Needs a snapshot token AND a value quantity AND a
#     comparison operator, so an arbitrary `before` local never counts.
_SNAP = re.compile(
    r"\b("
    r"bal(?:ance)?before|bal(?:ance)?after|balbefore|balafter|"
    r"balancebefore|balanceafter|prev(?:bal)?|snapshot|"
    r"pre[_]?bal|post[_]?bal|_before|_after|before|after"
    r")\b",
    re.IGNORECASE,
)
_QTY = re.compile(
    r"bal(?:ance)?|share|collateral|reserve|supply|debt|amount|amt|asset|"
    r"deposit|liquidity|stake|coin|fund|value",
    re.IGNORECASE,
)
_CMP = re.compile(r"[<>]=?|==|!=")


def haircut_xcheck_pred(expr: str) -> bool:
    """True iff the closure-node expression realizes a value conservatively: a
    HAIRCUT scale-down, a SECOND-SOURCE deviation/twap cross-check, or a post-state
    balance-snapshot conservation compare. Pure node predicate; the set/closure/
    invariant-join logic lives in the caller. This is the OVERRIDE guard_pred(node)
    for has_guard_in_closure(fn, guard_pred=<haircut/xcheck>)."""
    e = (expr or "").strip()
    if not e:
        return False
    if _HAIRCUT.search(e):
        return True
    if _XCHECK.search(e):
        return True
    if _SNAP.search(e) and _QTY.search(e) and _CMP.search(e):
        return True
    return False


# ---------------------------------------------------------------------------
# Record -> entrypoint unit (identical convention to the owned
# callgraph-set-difference-hunter: the backward-slice ENTRYPOINT is the
# param-entrypoint source; fall back to the sink fn).
# ---------------------------------------------------------------------------
_ENTRY_SRC_KINDS = {"param-entrypoint", "entrypoint", "param"}


def _entrypoint_of(rec: dict) -> str:
    src = rec.get("source") or {}
    sink = rec.get("sink") or {}
    if str(src.get("kind") or "") in _ENTRY_SRC_KINDS and src.get("fn"):
        return str(src["fn"])
    if sink.get("fn"):
        return str(sink["fn"])
    return str(src.get("fn") or "")


def _fn_file(rec: dict, fn: str) -> str:
    sink = rec.get("sink") or {}
    src = rec.get("source") or {}
    if src.get("fn") == fn and src.get("file"):
        return str(src["file"])
    if sink.get("fn") == fn and sink.get("file"):
        return str(sink["file"])
    return str(src.get("file") or sink.get("file") or "")


def _fn_line(rec: dict, fn: str) -> int:
    sink = rec.get("sink") or {}
    src = rec.get("source") or {}
    if src.get("fn") == fn and src.get("line"):
        return int(src["line"])
    if sink.get("fn") == fn and sink.get("line"):
        return int(sink["line"])
    return int(src.get("line") or sink.get("line") or 0)


# ---------------------------------------------------------------------------
# scope OOS guard (single source of truth); degrade to a conservative default.
# ---------------------------------------------------------------------------
try:
    from tools.lib.scope_exclusion import is_oos  # type: ignore
except Exception:  # pragma: no cover
    _LIB = _HERE / "lib"
    if str(_LIB) not in sys.path:
        sys.path.insert(0, str(_LIB))
    try:
        from scope_exclusion import is_oos  # type: ignore
    except Exception:
        def is_oos(rel: str, **_) -> bool:  # type: ignore[misc]
            n = ("/" + str(rel).replace("\\", "/")).lower()
            return any(m in n for m in (
                "/test/", "/tests/", "_test.", ".t.sol", "/mock", "/vendor/",
                "/node_modules/", "/out/", "/build/", "/target/", "/.auditooor/",
            ))


_VENDOR_MARKERS = ("/pkg/mod/", "/go/pkg/", "/vendor/", "/node_modules/")
_CODEGEN_SUFFIXES = (".pb.go", ".pb.gw.go", ".gen.go", "_pb2.py")


def _in_scope_file(fpath: str, ws_root: Path, include_oos: bool) -> bool:
    """The unit's file must live UNDER the workspace root, not be vendored /
    codegen, and pass the shared OOS guard. A vendored cosmos-sdk bank keeper
    SendCoins is not an in-scope release obligation."""
    if not fpath:
        return False
    low = fpath.replace("\\", "/").lower()
    if any(m in low for m in _VENDOR_MARKERS):
        return False
    if any(low.endswith(s) for s in _CODEGEN_SUFFIXES):
        return False
    try:
        rel = Path(fpath).resolve().relative_to(ws_root)
    except Exception:
        return False
    if not include_oos and is_oos(str(rel)):
        return False
    return True


def _short_fn(fn: str) -> str:
    """Bare function name from a Solidity 'C.f(uint256)' or Go '(*pkg.T).Method'
    identity. The Go receiver form STARTS with '(' so handle ').' BEFORE '(' split."""
    s = (fn or "").strip()
    if ")." in s:
        s = s.rsplit(").", 1)[-1]
    s = s.split("(")[0].replace("*", "")
    return s.split(".")[-1].strip()


def _contract_of(fn: str) -> str:
    s = (fn or "").strip()
    if ")." in s:
        recv = s.rsplit(").", 1)[0].lstrip("(").lstrip("*")
        return recv.split(".")[-1]
    head = s.split("(")[0]
    parts = head.split(".")
    return parts[0] if len(parts) > 1 else ""


class Unit:
    __slots__ = ("fn", "file", "line", "lang", "release_kinds",
                 "release_callees", "value_vars", "guard_exprs",
                 "quote_named", "release_named", "n_records")

    def __init__(self, fn: str):
        self.fn = fn
        self.file = ""
        self.line = 0
        self.lang = ""
        self.release_kinds: set[str] = set()
        self.release_callees: set[str] = set()
        self.value_vars: set[str] = set()
        self.guard_exprs: list[str] = []
        self.quote_named = False
        self.release_named = False
        self.n_records = 0


def build_sets(dataflow_path: Path, release_kinds: set[str],
               ws_root: Path,
               include_oos: bool = False) -> tuple[dict, list[str]]:
    """Fold dataflow_paths.jsonl into per-ENTRYPOINT Units, tagging VALUE_RELEASE
    membership (reaches a funds-out release sink with a value-bearing source, OR is
    a quote/valuation fn over a value) and accumulating the CLOSURE guard-node
    exprs. Returns (units_by_fn, warnings)."""
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
                u.quote_named = bool(_QUOTE_NAME.search(_short_fn(fn)))
                u.release_named = bool(_RELEASE_NAME.search(_short_fn(fn)))
                units[fn] = u
            u.n_records += 1
            if not u.file and fpath:
                u.file = fpath
            src = rec.get("source") or {}
            var = str(src.get("var") or "")
            if _VALUE_VAR.search(var):
                u.value_vars.add(var)
            sink = rec.get("sink") or {}
            skind = str(sink.get("kind") or "")
            if skind in release_kinds:
                u.release_kinds.add(skind)
                if sink.get("callee"):
                    u.release_callees.add(str(sink["callee"]))
            for g in rec.get("guard_nodes") or []:
                e = g.get("expr")
                if e:
                    u.guard_exprs.append(str(e))
    if n_total and n_degraded == n_total:
        warnings.append(
            f"ALL {n_total} dataflow records are DEGRADED (substrate-starved: "
            f"compile-fail / go-dataflow timeout) - the set-difference is "
            f"vacuously empty because the call graph never materialized, NOT "
            f"because VALUE_RELEASE is a subset of HAIRCUT_XCHECK. Re-run "
            f"go-dataflow.py scoped to the in-scope package (see --alt-dataflow).")
    return units, warnings


def _is_value_release(u: Unit) -> bool:
    """VALUE_RELEASE membership: (a) reaches a funds-out release sink AND the
    flowing source carries a value (or the fn name is a clear release path), OR
    (b) is a quote/valuation fn over a value (its return authorizes a downstream
    release). A pure ctx/address flow with no value var and no release/quote name
    is NOT a value-realization path."""
    has_value = bool(u.value_vars)
    if u.release_kinds and (has_value or u.release_named):
        return True
    if u.quote_named and has_value:
        return True
    return False


def classify(units: dict) -> dict:
    """Compute VALUE_RELEASE, HAIRCUT_XCHECK, and the SET-DIFFERENCE
    VALUE_RELEASE \\ HAIRCUT_XCHECK."""
    release = {fn for fn, u in units.items() if _is_value_release(units[fn])}
    checked = set()
    for fn in release:
        u = units[fn]
        if any(haircut_xcheck_pred(e) for e in u.guard_exprs):
            checked.add(fn)
    survivors = sorted(release - checked)
    kept = sorted(release & checked)
    return {
        "release": sorted(release),
        "haircut_xcheck": sorted(checked),
        "survivors": survivors,
        "kept": kept,
    }


# ---------------------------------------------------------------------------
# Conservation/haircut INVARIANT-FAMILY JOIN (the second owned dataset). Loads
# <ws>/.auditooor/invariant_ledger.json rows whose invariant_family is a
# conservation/haircut/deviation family (or whose statement names one) and indexes
# them by the bare function name / scope asset they cite, so a survivor's obligation
# can carry the SPECIFIC authored invariant it threatens.
# ---------------------------------------------------------------------------
_CONS_FAMILIES = {
    "accounting_conservation", "state_freshness", "allowance_residue",
}
_CONS_STMT = re.compile(
    r"conservation|haircut|deviat|collateral[_ ]?factor|ltv|discount|"
    r"second[_ ]?source|twap|spot|realiz|valuation|solvenc|health[_ ]?factor",
    re.IGNORECASE,
)


def _invariant_id_of(row: dict) -> str:
    bm = row.get("bridge_meta") or {}
    return str(row.get("id") or bm.get("eq_lead_id") or "").strip()


def load_conservation_invariants(ws: Path) -> tuple[list[dict], dict]:
    """Return (conservation_rows, fn_index). fn_index maps a lowercased bare
    function name -> list of invariant ids that cite it (in statement /
    harness_target / production_path / source_citations)."""
    p = ws / ".auditooor" / "invariant_ledger.json"
    rows: list[dict] = []
    fn_index: dict[str, list[str]] = {}
    if not p.is_file():
        return rows, fn_index
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return rows, fn_index
    ledger = d.get("rows") if isinstance(d, dict) else d
    if not isinstance(ledger, list):
        return rows, fn_index
    for r in ledger:
        if not isinstance(r, dict):
            continue
        fam = str(r.get("invariant_family") or "").lower()
        stmt = str(r.get("statement") or "")
        if fam not in _CONS_FAMILIES and not _CONS_STMT.search(stmt):
            continue
        rows.append(r)
        inv_id = _invariant_id_of(r)
        if not inv_id:
            continue
        # index by any bare fn identifier mentioned in the citing text
        hay = " ".join(str(r.get(k) or "") for k in (
            "statement", "harness_target", "production_path")) + " " + \
            " ".join(str(x) for x in (r.get("source_citations") or []))
        for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", hay):
            fn_index.setdefault(tok.lower(), []).append(inv_id)
    return rows, fn_index


def _matched_invariants(u: Unit, fn_index: dict) -> list[str]:
    short = _short_fn(u.fn).lower()
    ids = list(dict.fromkeys(fn_index.get(short, [])))
    return ids[:6]


def make_obligation(u: Unit, default_inv_id: str, matched_inv: list[str]) -> dict:
    short = _short_fn(u.fn)
    contract = _contract_of(u.fn)
    src_ref = u.file + (f":{u.line}" if u.line else "")
    kinds = sorted(u.release_kinds)
    vvars = sorted(u.value_vars)[:4]
    arm = ("quote/valuation" if (u.quote_named and not u.release_kinds)
           else "borrow/withdraw release")
    root = (
        f"Entrypoint '{u.fn}' is a {arm} path: a value "
        + (f"({', '.join(vvars)}) " if vvars else "")
        + (f"reaches a fund-release sink ({', '.join(kinds)}) "
           if kinds else "authorizes a downstream release ")
        + "but NO node in its forward closure applies a HAIRCUT (LTV / collateral "
        "factor / discount / notional scale-down) OR a SECOND-SOURCE cross-check "
        "(oracle deviation / TWAP-vs-spot / two-oracle min|max / pre-post balance-"
        "snapshot conservation) on that value (set-difference VALUE_RELEASE\\"
        "HAIRCUT_XCHECK). Value-realization-without-haircut class: a single-source / "
        "full-notional value is consumed RAW to move funds, so a manipulated or "
        "over-stated value over-releases."
    )
    inv_ids = matched_inv or [default_inv_id]
    return {
        "schema": "auditooor.conservation_haircut_realization.v1",
        "obligation_type": "conservation-haircut-realization",
        "contract": contract,
        "function": short,
        "function_signature": u.fn,
        "language": u.lang,
        "source_refs": [src_ref] if src_ref else [],
        "file": u.file,
        "line": u.line,
        "release_arm": arm,
        "release_sink_kinds": kinds,
        "release_sink_callees": sorted(u.release_callees)[:4],
        "value_vars": vvars,
        "attack_class": "value-realization-without-haircut-or-second-source",
        "likely_severity": "high",
        "broken_invariant_ids": inv_ids,
        "joined_conservation_invariants": matched_inv,
        "root_cause_hypothesis": root,
        "quality_gate_status": "needs_source",
        "proof_status": "needs_source",
        "advisory_only": True,
        "learning_route": "mine-source",
        "falsification_requirements": [
            "HAIRCUT_CLOSURE: prove NO haircut / second-source cross-check is "
            "reachable in the fwd closure of this fn (has_guard_in_closure with the "
            "haircut/xcheck guard_pred returns False) - a discount or deviation "
            "check N hops away in a helper KILLS the lead.",
            "MANIPULABLE_VALUE: confirm the realized value is externally influenceable "
            "(spot oracle / AMM getRate / user-supplied amount), not an immutable "
            "constant or an internally-conserved ledger read.",
            "OVER_RELEASE: show the atomic over-valuation -> over-release step "
            "(borrow more than collateral supports / withdraw more than owed / "
            "quote inflated) with a concrete numeric delta.",
        ],
        "next_command": (
            "read the fn body + its callee closure; if a haircut/second-source "
            "cross-check is genuinely unreachable, author the conservation invariant "
            "harness (value_out <= haircut(value_in)) and drive an executed PoC."
        ),
    }


def run(argv=None) -> dict:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--dataflow", default=None,
                    help="override dataflow_paths.jsonl path")
    ap.add_argument("--alt-dataflow", default=None,
                    help="additional dataflow jsonl to UNION (e.g. a scoped "
                         "package run when the merged sidecar is degraded)")
    ap.add_argument("--release-kinds", default=None,
                    help="comma-list overriding the default fund-release sink kinds")
    ap.add_argument("--include-oos", action="store_true",
                    help="do NOT apply the scope OOS filter (debug)")
    ap.add_argument("--invariant-id",
                    default="INV-VALUE-RELEASE-HAIRCUT-REALIZATION",
                    help="default broken_invariant_id when no ledger row matches")
    ap.add_argument("--emit", default=None,
                    help="output jsonl path (default "
                         "<ws>/.auditooor/conservation_haircut_obligations.jsonl)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit non-zero if the dataflow substrate is fully "
                         "degraded (the set-difference could not be computed)")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    df = Path(args.dataflow).expanduser() if args.dataflow else \
        ws / ".auditooor" / "dataflow_paths.jsonl"
    release_kinds = set(_DEFAULT_RELEASE_KINDS)
    if args.release_kinds:
        release_kinds = {k.strip() for k in args.release_kinds.split(",")
                         if k.strip()}

    units, warnings = build_sets(df, release_kinds, ws,
                                 include_oos=args.include_oos)

    # Union any SCOPED sidecars <ws>/.auditooor/dataflow_paths.*.jsonl (e.g. a
    # per-package go-dataflow run, dataflow_paths.nexus.jsonl on axelar) plus any
    # explicit --alt-dataflow.
    alt_paths: list[Path] = []
    if args.alt_dataflow:
        alt_paths.append(Path(args.alt_dataflow).expanduser())
    if not args.dataflow:
        for sib in sorted((ws / ".auditooor").glob("dataflow_paths.*.jsonl")):
            if sib.resolve() != df.resolve():
                alt_paths.append(sib)
    for alt in alt_paths:
        alt_units, alt_warn = build_sets(alt, release_kinds, ws,
                                         include_oos=args.include_oos)
        warnings.extend(alt_warn)
        for fn, au in alt_units.items():
            u = units.get(fn)
            if u is None:
                units[fn] = au
                continue
            u.release_kinds |= au.release_kinds
            u.release_callees |= au.release_callees
            u.value_vars |= au.value_vars
            u.guard_exprs.extend(au.guard_exprs)
            u.quote_named = u.quote_named or au.quote_named
            u.release_named = u.release_named or au.release_named
            u.n_records += au.n_records
            if not u.file:
                u.file = au.file

    res = classify(units)

    # JOIN to the conservation/haircut invariant family in the owned ledger.
    cons_rows, fn_index = load_conservation_invariants(ws)

    obligations = []
    _seen_ob = set()
    n_joined = 0
    for fn in res["survivors"]:
        u = units[fn]
        dk = (u.file, u.line, _short_fn(fn))
        if dk in _seen_ob:
            continue
        _seen_ob.add(dk)
        matched = _matched_invariants(u, fn_index)
        if matched:
            n_joined += 1
        obligations.append(make_obligation(u, args.invariant_id, matched))

    emit = Path(args.emit).expanduser() if args.emit else \
        ws / ".auditooor" / "conservation_haircut_obligations.jsonl"
    emit.parent.mkdir(parents=True, exist_ok=True)
    with emit.open("w", encoding="utf-8") as fh:
        for ob in obligations:
            fh.write(json.dumps(ob) + "\n")

    substrate_degraded = any("DEGRADED" in w for w in warnings) and not units

    summary = {
        "schema": "auditooor.conservation_haircut_realization_summary.v1",
        "workspace": str(ws),
        "dataflow": str(df),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "release_kinds": sorted(release_kinds),
        "n_entrypoint_units": len(units),
        "size_VALUE_RELEASE": len(res["release"]),
        "size_HAIRCUT_XCHECK_among_release": len(res["kept"]),
        "size_DIFF_survivors": len(res["survivors"]),
        "n_conservation_invariants_loaded": len(cons_rows),
        "n_survivors_joined_to_invariant": n_joined,
        "kept_release_and_haircut": [_short_fn(f) for f in res["kept"]],
        "survivors": [
            {"fn": _short_fn(f), "signature": f,
             "file": units[f].file, "line": units[f].line,
             "release_sink_kinds": sorted(units[f].release_kinds),
             "value_vars": sorted(units[f].value_vars)[:4],
             "arm": ("quote/valuation"
                     if (units[f].quote_named and not units[f].release_kinds)
                     else "borrow/withdraw release")}
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
        print(f"[conservation-haircut] {ws.name}: "
              f"|VALUE_RELEASE|={summary['size_VALUE_RELEASE']} "
              f"|HAIRCUT_XCHECK(among release)|="
              f"{summary['size_HAIRCUT_XCHECK_among_release']} "
              f"survivors(RELEASE\\HAIRCUT)={summary['size_DIFF_survivors']} "
              f"-> {len(obligations)} conservation-haircut obligation(s); "
              f"{n_joined} joined to an authored conservation invariant "
              f"({len(cons_rows)} loaded)")
        if res["kept"]:
            print("  KEPT (release + reaches a haircut/second-source check, "
                  "removed from diff): "
                  + ", ".join(summary["kept_release_and_haircut"]))
        for s in summary["survivors"][:40]:
            print(f"  SURVIVOR {s['fn']}  [{s['arm']}]  "
                  f"{sorted(s['release_sink_kinds'])}  vars={s['value_vars']}  "
                  f"{s['file']}:{s['line']}")
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
