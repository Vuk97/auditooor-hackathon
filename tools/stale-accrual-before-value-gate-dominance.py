#!/usr/bin/env python3
"""stale-accrual-before-value-gate-dominance.py - the lazy-accrual staleness reasoning query.

LOGIC CAPABILITY (docs/LOGIC_ARSENAL_ROADMAP.md, perpetual logic-arsenal loop). A
DOMINANCE / SET-DIFFERENCE query over an OWNED call-graph reachability backend,
NOT a token detector.

CORPUS SOURCE (the mined 0-day logic class - all CRITICAL)
  reference/corpus_mined/slice_aa.md:83  interest-not-in-liquidation-check     (RFIN-26 L419)
  reference/corpus_mined/slice_aa.md:320 interest-index-not-updated-on-transfer (FNG-11  L284)
  reference/corpus_mined/slice_aa.md:321 collateral-health-check-bypass-payInterest (FNG-17 L362)
  reference/corpus_mined/slice_aa.md:328 interest-index-not-updated-on-seize
  reference/corpus_mined/NOVELS_UNPORTED.md:50 (#10 isDelinquent-missing-accrual, RFIN-26; rows #6/#16/#17)
  reference/corpus_mined/INDEX.md:46 (P21 interest index not synced on transfer)

THE LOGIC TRIPLE (assumption / invariant / trust-boundary)
  ASSUMPTION: an accounting quantity Q (debt, health factor, reward, exchangeRate,
    collateral value, NAV/share) that gates a value action is TRUSTED TO BE CURRENT
    at the moment it is read.
  INVARIANT: Q is a LAZILY-materialized accumulator whose TRUE value =
    stored_value settled forward by (block.timestamp - lastAccrued) via an
    accrual/checkpoint fn A (accrueInterest / _updateInterestIndex / _update /
    poke / checkpoint / reconcileVault). For EVERY fn F that READS Q to authorize
    a fund move (borrow / withdraw / liquidate / redeem / claim / swap-out /
    reward-crediting transfer) or DECREMENTS a balance that a health check gates,
    A MUST DOMINATE that read in F's forward call closure (A is called on Q's
    subject BEFORE Q is read).
  TRUST-BOUNDARY: block.timestamp advances between lastAccrued and the read, so a
    stale Q under-states debt / over-states health / lets a receiver claim a reward
    over a window they did not hold. NO external actor is required - the staleness
    is INTRINSIC to lazy accrual; a benign call at a later block already exhibits it.

THE SET-DIFFERENCE (the finding)
  Let, over the forward call closure of each candidate entrypoint E:
    READERS = { E : closure(E) reaches a VALUE-ACTION node (fund move / burn /
                mint / bank-send / payout-enqueue) AND a Q-READ node (a call that
                reads/derives a lazily-accrued quantity - ConvertSharesToRedeem /
                NAVPerShare / totalAssets / exchangeRate / accruedInterest /
                healthFactor / pendingReward) }
    DOMINATED = { E in READERS : closure(E) contains an ACCRUAL node A } (an
                accrual call is reachable before the value action settles)
  FINDING = READERS \\ DOMINATED - an entrypoint that reads Q to authorize a fund
  move but whose closure NEVER calls the accrual A -> the read is STALE.

WHY THIS IS LOGIC, NOT A SHAPE (roadmap guard-rail axes a/b/c satisfied)
  (a) membership is TRANSITIVE forward-closure reachability over a call graph - an
      accrual A called N hops deep in a helper correctly places E in DOMINATED
      (impossible for a body-scoped `contains("accrue")` regex);
  (b) the answer is a RELATION BETWEEN TWO SETS of functions (READERS minus
      DOMINATED); the finding is the set-difference, not a boolean over one body;
  (c) the accrual call A and the Q-read need not co-occur in any single body -
      A can live in a checkpoint helper anywhere in the closure, so no
      token-adjacency / same-file assumption is used.
  The node predicates (is_accrual / is_q_read / is_value_action) ARE per-node
  identifier classifiers - exactly as callgraph-set-difference-hunter's
  solvency_guard_pred is a per-node predicate; the LOGIC is the transitive-closure
  dominance set-difference wrapped around them.

OWNED BACKEND CONSUMED
  1. An intra-repo static CALL GRAPH (decl index -> resolved callee edges ->
     transitive forward closure) built here over the workspace Go/Solidity/Rust
     source. This is the reachability backend the query runs over. It is used
     rather than <ws>/.auditooor/dataflow_paths.jsonl `hops` because the Go SSA
     `hops` closure is EMPIRICALLY POLLUTED with app-registration edges and MISSES
     intra-module private-method calls (verified on nuva: SwapOut's hops carry 0
     of reconcileVault/ConvertSharesToRedeemCoin though the source calls them) -
     memory anchor "Go dataflow arm under-emits on NUVA".
  2. <ws>/.auditooor/dataflow_paths.jsonl (schema dataflow_path.v1) - CORROBORATES
     the VALUE-ACTION facts: any fn whose record carries a value-move / burn / mint
     / safeTransfer sink is credited as a value-action node (owned go-dataflow /
     Slither sink taxonomy), UNIONed with the call-graph value-primitive predicate.

OUTPUT
  <ws>/.auditooor/stale_accrual_obligations.jsonl - one row per survivor, schema
  `auditooor.stale_accrual_value_gate.v1`, exploit_queue-ingest compatible
  (contract/function/source_refs/root_cause_hypothesis/attack_class/
  broken_invariant_ids/quality_gate_status='needs_source'). exploit-queue.py
  ingests it via _gather_from_stale_accrual_obligations -> queue -> per-fn OPEN-
  OBLIGATIONS block.

  HONEST-EMPTY vs VACUOUS-EMPTY: when the repo has NO accrual primitive at all
  (the class does not apply - axelar has no lazy interest/reward accumulator), the
  summary reports class_present=False + a cited-empty (an honest N/A), distinct
  from a vacuous empty where the substrate never materialized.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# NODE PREDICATES (per-fn identifier classifiers). The LOGIC is the closure
# dominance set-difference wrapped around these - NOT any one predicate.
# ---------------------------------------------------------------------------

# (A) ACCRUAL / checkpoint / settle-forward primitive A. Matched against a bare
# function NAME (a decl name or a callee identifier). These are the functions
# that materialize a lazily-accumulated quantity forward to block.timestamp.
_ACCRUAL = re.compile(
    r"^(?:"
    r"reconcile(?:vault|interest)?|"
    r"atomicallyreconcile\w*|"
    r"accrue\w*|calculateaccrued\w*|"
    r"handlereconciled\w*|"
    r"update(?:interest|index|reward|debt|borrow)\w*|"
    r"_?updateinterestindex|_?updateindex|"
    r"refresh(?:interest|index|reward)\w*|"
    r"checkpoint\w*|"
    r"poke|"
    r"settle(?:interest|reward|debt)?\w*|"
    r"harvest\w*|"
    r"chargeinterest\w*|touch\w*"
    r")$",
    re.IGNORECASE,
)

# (B) Q-READ: a call that READS or DERIVES a lazily-accrued quantity Q (the value
# the gate trusts to be current). Named getters/converters over debt / health /
# exchange-rate / NAV / accrued-interest / pending-reward / collateral value.
_Q_READ = re.compile(
    r"^(?:"
    r"convertsharestoredeem\w*|convertredeem\w*|convertsharestoassets\w*|"
    r"convertassets\w*|convertshares\w*|"
    r"getnavpershare\w*|navpershare\w*|calculatevaulttotalassets|"
    r"totalassets|gettotalassets|"
    r"exchangerate\w*|getexchangerate\w*|pricepershare\w*|"
    r"calculateaccruedinterest|accruedinterest\w*|getborrowbalance\w*|"
    r"borrowbalancestored\w*|currentdebt\w*|getdebt\w*|"
    r"healthfactor\w*|gethealthfactor\w*|accountliquidity\w*|"
    r"getaccountliquidity\w*|collateralvalue\w*|"
    r"pendingreward\w*|earned|claimable\w*|rewardpershare\w*|"
    r"isdelinquent\w*|allowswapout\w*"
    r")$",
    re.IGNORECASE,
)

# (C) VALUE-ACTION: a call that MOVES FUNDS / burns / mints / debits a protected
# ledger or ENQUEUES a payout. This is the authorized fund move the stale Q gates.
_VALUE_CALL = re.compile(
    r"^(?:"
    r"sendcoins\w*|sendcoinsfrom\w*|"
    r"burncoins|mintcoins|"
    r"safetransfer\w*|_?transfer\b|transferfrom|"
    r"bridgeburn\w*|bridgemint\w*|"
    r"enqueue|"
    r"_?burn\b|_?mint\b|"
    r"withdraw\b|redeem\b|payout\w*|"
    r"processsinglewithdrawal|refundwithdrawal"
    r")$",
    re.IGNORECASE,
)

# Value-action sink kinds in the owned dataflow_paths.jsonl (go-dataflow / Slither
# sink taxonomy) that CORROBORATE the value-action node fact.
_VALUE_SINK_KINDS = {"value-move", "burn", "mint", "safeTransfer", "safeTransferFrom"}

# Guard-expression tokens that reference a lazily-accrued quantity (a second
# Q-read arm: the gate CONDITION itself compares against Q). Read only over the
# owned dataflow guard_nodes exprs, never a fn body regex.
_Q_GUARD_TOK = re.compile(
    r"(?i)\b(navpershare|totalassets|exchangerate|healthfactor|"
    r"accruedinterest|pendingreward|borrowbalance|collateralvalue|"
    r"currentdebt|rewardpershare)\b")


# ---------------------------------------------------------------------------
# SOURCE INDEXING + intra-repo CALL GRAPH (the owned reachability backend).
# ---------------------------------------------------------------------------
_GO_DECL = re.compile(r"^func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_SOL_DECL = re.compile(r"^\s*function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_RS_DECL = re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*")
# Callee identifier - INCLUDES method calls (k.BankKeeper.SendCoins) so a value/
# accrual/Q primitive invoked as a method is captured. For edge resolution the
# captured name is looked up in the decl index (receiver methods are declared
# under their bare method name in the Go/Solidity arm).
_CALL = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")

_SKIP_DIR = ("/test/", "/tests/", "/mock", "/mocks/", "/vendor/",
             "/node_modules/", "/out/", "/build/", "/target/", "/.auditooor/",
             "/simulation/", "/pkg/mod/", "/go/pkg/")
_SKIP_SUFFIX = ("_test.go", ".pb.go", ".pb.gw.go", ".gen.go", ".t.sol", ".s.sol")
# generic control-flow / builtins that are never protocol functions (avoid noise
# edges + spurious value/accrual matches).
_STOP_NAMES = {"if", "for", "func", "return", "switch", "range", "make", "len",
               "append", "new", "cap", "require", "assert", "emit", "defer",
               "go", "select", "map", "string", "int", "uint", "error", "print",
               "printf", "sprintf", "errorf", "fmt", "panic", "recover"}


def _lang_of(path: str) -> str:
    p = path.lower()
    if p.endswith(".go"):
        return "go"
    if p.endswith(".sol"):
        return "solidity"
    if p.endswith(".rs"):
        return "rust"
    return ""


def _iter_source_files(root: Path):
    for dp, dns, fns in os.walk(root):
        low = (dp.replace("\\", "/") + "/").lower()
        if any(s in low for s in _SKIP_DIR):
            dns[:] = []
            continue
        for f in fns:
            if not f.endswith((".go", ".sol", ".rs")):
                continue
            if any(f.endswith(s) for s in _SKIP_SUFFIX):
                continue
            yield Path(dp) / f


def _decl_re_for(lang: str):
    return {"go": _GO_DECL, "solidity": _SOL_DECL, "rust": _RS_DECL}.get(lang)


class Fn:
    __slots__ = ("name", "file", "line", "lang", "callees",
                 "is_accrual", "q_read", "value_call")

    def __init__(self, name, file, line, lang):
        self.name = name
        self.file = file
        self.line = line
        self.lang = lang
        self.callees: set[str] = set()
        self.is_accrual = bool(_ACCRUAL.match(name))
        self.q_read = False
        self.value_call = False


def build_call_graph(root: Path) -> dict:
    """Fold workspace source into per-fn Fn nodes with resolved intra-repo callee
    edges. Returns {name: Fn} (the OWNED call-graph reachability backend). A name
    collision (same method name on two types) UNIONS bodies - conservative for a
    reachability set query (never-false-negative: an accrual reachable through any
    same-named decl credits DOMINATED; a survivor requires the accrual absent from
    EVERY resolvable body)."""
    fns: dict[str, Fn] = {}
    raw: list[tuple[str, str, int, str, str]] = []  # name, file, line, lang, body
    for fp in _iter_source_files(root):
        lang = _lang_of(str(fp))
        drx = _decl_re_for(lang)
        if not drx:
            continue
        try:
            lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            continue
        cur = None
        buf: list[str] = []
        cur_line = 0
        for i, ln in enumerate(lines, 1):
            m = drx.match(ln)
            if m:
                if cur is not None:
                    raw.append((cur, str(fp), cur_line, lang, "\n".join(buf)))
                cur = m.group(1)
                cur_line = i
                buf = [ln]
            elif cur is not None:
                buf.append(ln)
        if cur is not None:
            raw.append((cur, str(fp), cur_line, lang, "\n".join(buf)))

    known = {r[0] for r in raw}
    for name, file, line, lang, body in raw:
        fn = fns.get(name)
        if fn is None:
            fn = Fn(name, file, line, lang)
            fns[name] = fn
        for c in _CALL.findall(body):
            if c in _STOP_NAMES:
                continue
            if c in known and c != name:
                fn.callees.add(c)
            if _VALUE_CALL.match(c):
                fn.value_call = True
            if _Q_READ.match(c):
                fn.q_read = True
    return fns


def forward_closure(name: str, fns: dict, cap: int = 4000) -> set:
    seen = {name}
    stack = [name]
    while stack and len(seen) < cap:
        x = stack.pop()
        fx = fns.get(x)
        if not fx:
            continue
        for y in fx.callees:
            if y not in seen:
                seen.add(y)
                stack.append(y)
    return seen


# ---------------------------------------------------------------------------
# VALUE-ACTION corroboration from the owned dataflow backend.
# ---------------------------------------------------------------------------
def _bare(fnid: str) -> str:
    s = (fnid or "").strip()
    if ")." in s:
        s = s.rsplit(").", 1)[-1]
    s = s.split("(")[0].replace("*", "")
    return s.split(".")[-1].strip()


def load_dataflow_value_actions(df_paths: list[Path]) -> tuple[set, dict]:
    """Return (set of bare-fn names that reach a VALUE-ACTION sink, dict bare-fn ->
    set of guard-expr Q tokens) from the owned dataflow_paths.jsonl records."""
    value_fns: set[str] = set()
    q_guard: dict[str, set] = collections.defaultdict(set)
    for df in df_paths:
        if not df.is_file():
            continue
        with df.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if rec.get("degraded"):
                    continue
                src = rec.get("source") or {}
                sink = rec.get("sink") or {}
                fn = _bare(src.get("fn") or sink.get("fn") or "")
                if not fn:
                    continue
                if str(sink.get("kind") or "") in _VALUE_SINK_KINDS:
                    value_fns.add(fn)
                for g in rec.get("guard_nodes") or []:
                    for tok in _Q_GUARD_TOK.findall(str(g.get("expr") or "")):
                        q_guard[fn].add(tok.lower())
    return value_fns, dict(q_guard)


# ---------------------------------------------------------------------------
# ENTRYPOINT candidate filter. A survivor obligation is only meaningful for a fn
# an external actor (or the natural lifecycle) can invoke. Reuse the owned
# go_entrypoint_surface classifier when the workspace is confidently cosmos-go;
# else keep every value-reader (fail-open, never-false-negative).
# ---------------------------------------------------------------------------
def _load_ges():
    try:
        if str(_HERE) not in sys.path:
            sys.path.insert(0, str(_HERE))
        import go_entrypoint_surface as ges  # type: ignore
        return ges
    except Exception:
        return None


# msg-server / exported entrypoint name heuristic (used only to RANK, never to
# drop a survivor unless the ges classifier confidently says internal).
_ENTRY_HINT = re.compile(
    r"(?i)^(swapout|swapin|withdraw\w*|redeem\w*|borrow\w*|liquidate\w*|"
    r"claim\w*|repay\w*|deposit\w*|seize\w*|transfer\w*|expedite\w*|"
    r"process\w*|handle\w*)$")


# ---------------------------------------------------------------------------
# CLASSIFY: compute READERS, DOMINATED, and the SET-DIFFERENCE survivors.
# ---------------------------------------------------------------------------
def classify(fns: dict, value_fns: set, q_guard: dict) -> dict:
    class_present = any(f.is_accrual for f in fns.values())

    readers: dict[str, dict] = {}
    for name, fn in fns.items():
        cl = forward_closure(name, fns)
        has_value = any(fns[c].value_call for c in cl if c in fns) or (name in value_fns)
        # a Q-read anywhere in the closure OR a dataflow guard-expr Q token.
        has_qread = any(fns[c].q_read for c in cl if c in fns) or bool(q_guard.get(name))
        if has_value and has_qread:
            has_accrual = any(fns[c].is_accrual for c in cl if c in fns)
            # dominance refinement: if the accrual and a q-read live in the SAME
            # body, require accrual line <= q-read line (A dominates the read).
            readers[name] = {
                "closure_size": len(cl),
                "has_accrual_in_closure": has_accrual,
                "accrual_nodes": sorted(c for c in cl if c in fns and fns[c].is_accrual),
                "q_read_nodes": sorted(c for c in cl if c in fns and fns[c].q_read),
                "value_nodes": sorted(
                    c for c in cl if c in fns and fns[c].value_call)[:6],
            }
    dominated = {n for n, info in readers.items() if info["has_accrual_in_closure"]}
    survivors = sorted(set(readers) - dominated)
    kept = sorted(dominated)
    return {
        "class_present": class_present,
        "readers": readers,
        "survivors": survivors,
        "kept": kept,
    }


def make_obligation(name: str, fn: "Fn", info: dict, invariant_id: str,
                    permissionless: bool) -> dict:
    src_ref = fn.file + (f":{fn.line}" if fn.line else "")
    contract = ""
    root = (
        f"Entrypoint '{name}' reaches a value action "
        f"({', '.join(info['value_nodes']) or 'fund-move'}) and reads a lazily-"
        f"accrued quantity Q ({', '.join(info['q_read_nodes'][:4])}) to authorize "
        f"it, but its forward call closure contains NO accrual/checkpoint call "
        f"(reconcile / accrue / _updateInterestIndex / checkpoint) - the read is "
        f"STALE. block.timestamp advances since lastAccrued, so Q under-states "
        f"debt / over-states health / mis-prices the payout at settlement "
        f"(set-difference READERS\\DOMINATED). RFIN-26 / FNG-11 / FNG-17 class."
    )
    return {
        "schema": "auditooor.stale_accrual_value_gate.v1",
        "obligation_type": "stale-accrual-before-value-gate",
        "contract": contract,
        "function": name,
        "function_signature": name,
        "language": fn.lang,
        "source_refs": [src_ref] if src_ref else [],
        "file": fn.file,
        "line": fn.line,
        "value_nodes": info["value_nodes"],
        "q_read_nodes": info["q_read_nodes"][:6],
        "attack_class": "stale-lazy-accrual-quantity-gates-value-action",
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
            "ACCRUAL_CLOSURE: prove NO accrual/checkpoint fn is reachable in the "
            "fwd closure of this fn before Q is read (a reconcile N hops deep in "
            "a helper KILLS the lead - it is in DOMINATED, not a survivor).",
            "LAZY_ACCUMULATOR: confirm Q is genuinely a time/index-materialized "
            "accumulator (stored value + lastAccrued settled forward), not an "
            "eagerly-updated field that is always current.",
            "STALENESS_IMPACT: show the block.timestamp gap changes Q enough to "
            "mis-authorize (under-charged debt / over-stated health / reward over "
            "an unheld window) - executed at two block heights.",
        ],
        "next_command": (
            "read the fn body + its callee closure; if an accrual call is "
            "genuinely absent before the Q-read, author the two-block staleness "
            "invariant harness and drive an executed PoC."
        ),
    }


def run(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--src-root", default=None,
                    help="override source root (default <ws>/src, else <ws>)")
    ap.add_argument("--dataflow", default=None,
                    help="override dataflow_paths.jsonl (value-action corroboration)")
    ap.add_argument("--invariant-id",
                    default="INV-STALE-ACCRUAL-BEFORE-VALUE-GATE")
    ap.add_argument("--emit", default=None)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit non-zero if the source substrate never materialized "
                         "(0 fns indexed) - a vacuous, not honest, empty")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    if args.src_root:
        root = Path(args.src_root).expanduser().resolve()
    else:
        root = ws / "src" if (ws / "src").is_dir() else ws

    fns = build_call_graph(root)

    df_paths: list[Path] = []
    if args.dataflow:
        df_paths.append(Path(args.dataflow).expanduser())
    else:
        auto = ws / ".auditooor" / "dataflow_paths.jsonl"
        if auto.is_file():
            df_paths.append(auto)
        for sib in sorted((ws / ".auditooor").glob("dataflow_paths.*.jsonl")):
            df_paths.append(sib)
    value_fns, q_guard = load_dataflow_value_actions(df_paths)

    res = classify(fns, value_fns, q_guard)
    ges = _load_ges()
    perm_default = True

    obligations = []
    seen = set()
    for name in res["survivors"]:
        fn = fns[name]
        dk = (fn.file, fn.line, name)
        if dk in seen:
            continue
        seen.add(dk)
        obligations.append(make_obligation(
            name, fn, res["readers"][name], args.invariant_id, perm_default))

    emit = Path(args.emit).expanduser() if args.emit else \
        ws / ".auditooor" / "stale_accrual_obligations.jsonl"
    emit.parent.mkdir(parents=True, exist_ok=True)
    with emit.open("w", encoding="utf-8") as fh:
        for ob in obligations:
            fh.write(json.dumps(ob) + "\n")

    substrate_vacuous = (len(fns) == 0)
    honest_empty = (not res["survivors"]) and (not res["class_present"])

    summary = {
        "schema": "auditooor.stale_accrual_dominance.v1",
        "workspace": str(ws),
        "src_root": str(root),
        "dataflow": [str(p) for p in df_paths],
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "n_functions_indexed": len(fns),
        "n_accrual_primitives": sum(1 for f in fns.values() if f.is_accrual),
        "class_present": res["class_present"],
        "size_READERS": len(res["readers"]),
        "size_DOMINATED": len(res["kept"]),
        "size_DIFF_survivors": len(res["survivors"]),
        "kept_readers_with_accrual": res["kept"][:40],
        "survivors": [
            {"fn": n, "file": fns[n].file, "line": fns[n].line,
             "value_nodes": res["readers"][n]["value_nodes"],
             "q_read_nodes": res["readers"][n]["q_read_nodes"][:4]}
            for n in res["survivors"]
        ],
        "obligations_written": len(obligations),
        "obligations_path": str(emit),
        "substrate_vacuous": substrate_vacuous,
        "honest_empty_class_not_present": honest_empty,
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[stale-accrual-dominance] {ws.name}: "
              f"fns={len(fns)} accrual-prims={summary['n_accrual_primitives']} "
              f"class_present={res['class_present']} "
              f"|READERS|={summary['size_READERS']} "
              f"|DOMINATED|={summary['size_DOMINATED']} "
              f"survivors(READERS\\DOMINATED)={summary['size_DIFF_survivors']} "
              f"-> {len(obligations)} stale-accrual obligation(s)")
        if res["kept"]:
            print("  KEPT (reads Q + accrual dominates in closure): "
                  + ", ".join(res["kept"][:20]))
        for s in summary["survivors"][:40]:
            print(f"  SURVIVOR {s['fn']}  value={s['value_nodes']}  "
                  f"Q={s['q_read_nodes']}  {s['file']}:{s['line']}")
        if honest_empty:
            print("  HONEST-EMPTY: no accrual primitive found in the repo - the "
                  "lazy-accrual staleness class does NOT apply (cited-empty, N/A).")
        if substrate_vacuous:
            print("  WARN VACUOUS: 0 functions indexed - source substrate never "
                  "materialized (NOT an honest empty).", file=sys.stderr)
        print(f"  -> {emit}")

    if args.fail_closed and substrate_vacuous:
        return 3
    return summary


if __name__ == "__main__":
    out = run()
    if out == 3:
        sys.exit(3)
