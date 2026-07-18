#!/usr/bin/env python3
"""assumption-enumeration-falsification.py - NOVELTY-GENERATION LAYER item 2.

ASSUMPTION ENUMERATION + FALSIFICATION (docs/LOGIC_ARSENAL_ROADMAP.md:63-65).

This is a NOVELTY engine, NOT a class recognizer. It does NOT read the corpus /
attack-class taxonomy at all. Instead it DERIVES, from the workspace's own code
signals, the implicit assumptions each in-scope function makes, and for each one
emits an ADVERSARIAL OBLIGATION: is this assumption ENFORCED on the reachable
path, or merely ASSUMED (falsifiable)? A falsifiable assumption on a reachable
path is a candidate 0-day whether or not it matches any known corpus class -
that unnamed-ness is precisely the point (guard-rail: derive from code, not a
class list).

The seven implicit-assumption axes (roadmap:63) enumerated per unit:

  value-bounded      the numeric value it moves is within some bound
  non-zero           an amount / denominator is non-zero
  caller-trusted     the caller is authorized to invoke a state mutator
  no-reentry         no reentrant re-entry between an external call and a write
  external-succeeds  an external call's return / success is honored
  order-holds        a nonce / sequence / ordering precondition holds
  init-once          an initializer runs exactly once
  no-overflow        arithmetic on the moved value cannot wrap  (advisory)

REASONING QUERY over OWNED backends (no new detector, no new source walker):

  1. value_moving_functions.json   per-(file,fn) value signals: transfer_hit,
     ledger_write_hit, authz_write_hit, guarded_callee_hit + evidence lists.
     (produced by tools/coupled-state / value-mover census)
  2. guard_completeness.jsonl      per-(file,fn) `guarded` bool + guard_evidence.
  3. dataflow_paths.jsonl          per-fn guard_nodes {file,line,expr}, sink
     kinds, source var + source.kind=="param-entrypoint" reachability.
     Its guard_nodes are the PERSISTED output of
     slither_predicates.has_guard_in_closure (dataflow-slice.py:1553), so
     consuming them IS reusing the closure-guard primitive to answer
     "is this assumption ENFORCED or merely assumed" - exactly the dispatch ask.

For Solidity workspaces with a live slither compile, has_guard_in_closure can be
consulted directly (best-effort, --slither); by default we consume its persisted
guard_nodes so the query is offline, fast, and fires on Go/Rust too.

An obligation is FALSIFIABLE iff: the assumption is PRESENT (a code signal shows
the function makes it) AND no enforcement evidence is found in any backend AND
the unit is reachable. Every emitted row cites a file:line anchor from a backend
record - never an ungrounded claim.

Usage:
  python3 tools/assumption-enumeration-falsification.py <workspace> [--json]
        [--only-falsifiable] [--out PATH] [--min-signals N]

Output: <workspace>/.auditooor/assumption_falsification_obligations.jsonl
        (+ a summary block on stderr / --json to stdout)
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
from collections import defaultdict

# ---------------------------------------------------------------------------
# Backend loaders (owned artifacts under <ws>/.auditooor/)
# ---------------------------------------------------------------------------

AUDITOOOR = ".auditooor"


def _adir(ws: pathlib.Path) -> pathlib.Path:
    return ws / AUDITOOOR


def _norm_fn(name: str) -> str:
    """Bare function name, signature/contract-qualifier stripped, lowercased.

    'CrossChainManager.burn(uint256,string)' -> 'burn'
    'NewAxelarApp' -> 'newaxelarapp'
    """
    if not name:
        return ""
    n = name.split("(", 1)[0]
    if "." in n:
        n = n.rsplit(".", 1)[1]
    return n.strip().lower()


def _basename(f: str) -> str:
    return os.path.basename(f or "")


def _unit_key(file: str, fn: str) -> str:
    return f"{_basename(file).lower()}::{_norm_fn(fn)}"


def load_value_movers(ws: pathlib.Path) -> dict:
    p = _adir(ws) / "value_moving_functions.json"
    out: dict = {}
    if not p.exists():
        return out
    try:
        d = json.loads(p.read_text())
    except Exception:
        return out
    for r in d.get("functions", []) or []:
        k = _unit_key(r.get("file", ""), r.get("function", ""))
        out[k] = r
    return out


def load_guard_completeness(ws: pathlib.Path) -> dict:
    p = _adir(ws) / "guard_completeness.jsonl"
    out: dict = {}
    if not p.exists():
        return out
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        k = _unit_key(r.get("file", ""), r.get("function", ""))
        out[k] = r
    return out


def load_dataflow(ws: pathlib.Path) -> dict:
    """Fold dataflow_paths.jsonl into per-unit {guard_exprs, sinks, reachable,
    file, line}. Degrade records (no source.fn) are skipped."""
    p = _adir(ws) / "dataflow_paths.jsonl"
    out: dict = defaultdict(lambda: {"guard_exprs": [], "sinks": set(),
                                      "reachable": False, "file": "", "line": 0,
                                      "hop_callees": set(),
                                      "closure_guarded_n": 0, "unguarded_n": 0,
                                      "closure_note": ""})
    if not p.exists():
        return {}
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        src = r.get("source") or {}
        fn = src.get("fn")
        if not fn:
            continue  # degrade / no-source record
        k = _unit_key(src.get("file", ""), fn)
        agg = out[k]
        if not agg["file"]:
            agg["file"] = src.get("file", "")
            agg["line"] = src.get("line", 0)
        for g in r.get("guard_nodes", []) or []:
            e = g.get("expr", "")
            if e:
                agg["guard_exprs"].append({"expr": e, "file": g.get("file", ""),
                                           "line": g.get("line", 0)})
        sink = r.get("sink") or {}
        if sink.get("kind"):
            agg["sinks"].add(sink.get("kind"))
        # authoritative guard-closure verdict per path (the fields the engine
        # previously ignored, folding only guard_nodes[].expr). closure_guarded=
        # a compensating guard dominates this path's sink; a genuinely-unguarded
        # path is unguarded==True AND NOT corrected by closure analysis. Root-
        # caused 2026-07-14: ~59 nuva assumption-negation false-reds were emitted
        # falsifiable while carrying closure_guarded=True.
        if r.get("closure_guarded") is True:
            agg["closure_guarded_n"] += 1
            if not agg["closure_note"]:
                agg["closure_note"] = str(
                    r.get("closure_note") or sink.get("expr") or "closure-guarded")[:160]
        if r.get("unguarded") is True and r.get("unguarded_closure_corrected") is not True:
            agg["unguarded_n"] += 1
        if src.get("kind") == "param-entrypoint":
            agg["reachable"] = True
        for h in r.get("hops", []) or []:
            c = h.get("via") or h.get("fn")
            if c:
                agg["hop_callees"].add(str(c))
    return dict(out)


# ---------------------------------------------------------------------------
# Enforcement-signature regexes (structural, over guard exprs / evidence).
# These check whether an assumption is ENFORCED; they are NOT bug-shape
# detectors and never touch the corpus.
# ---------------------------------------------------------------------------

AUTHORITY_RX = re.compile(
    r"msg\.sender|_msgsender|\bowner\b|onlyowner|hasrole|_checkrole|_checkowner|"
    r"\brole\b|require.*sender|access|authoriz|caller\s*==|admin|governor|"
    r"getsigners|sdk\.acc|ctx\.sender|isadmin|onlyrole",
    re.I)
NONZERO_RX = re.compile(r"==\s*0|!=\s*0|>\s*0|>=\s*1|\.iszero|isnil|== nil|!= nil", re.I)
BOUND_RX = re.compile(r"[<>]=?|\bmax\b|\bcap\b|balance|limit|<=|>=|min\(|max\(", re.I)
INIT_RX = re.compile(r"initiali|_disableinit|already|onlyonce|setup|reinit", re.I)
REENTRY_RX = re.compile(r"nonreentrant|reentran|\block\b|_status|mutex|guard\b", re.I)
RETURN_CHECK_RX = re.compile(r"success|require\s*\(.*call|revert|\berr\b|!= nil|== nil|returndata", re.I)
ORDER_RX = re.compile(r"nonce|sequence|\border\b|expected|prev|last|monoton|counter", re.I)


def _has(exprs, evidence_txt, rx) -> dict | None:
    for g in exprs:
        if rx.search(g.get("expr", "")):
            return {"via": "guard_expr", "expr": g["expr"], "file": g.get("file", ""),
                    "line": g.get("line", 0)}
    if evidence_txt and rx.search(evidence_txt):
        return {"via": "guard_evidence", "expr": evidence_txt[:120]}
    return None


# ---------------------------------------------------------------------------
# Core: enumerate assumptions per unit and falsify.
# ---------------------------------------------------------------------------

def enumerate_unit(key, vm, gc, df) -> list:
    """Return a list of assumption obligations for one unit. vm/gc/df are that
    unit's records from each backend (any may be None/{})."""
    vm = vm or {}
    gc = gc or {}
    df = df or {"guard_exprs": [], "sinks": set(), "reachable": False,
                "file": "", "line": 0, "hop_callees": set()}

    file = vm.get("file") or gc.get("file") or df.get("file") or ""
    fn = vm.get("function") or gc.get("function") or ""
    line = df.get("line") or 0
    exprs = df.get("guard_exprs", [])
    guarded_flag = bool(gc.get("guarded"))
    guard_ev = str(gc.get("guard_evidence", "") or "")
    sinks = df.get("sinks", set())

    transfer = bool(vm.get("transfer_hit"))
    ledger = bool(vm.get("ledger_write_hit"))
    authz = bool(vm.get("authz_write_hit"))
    value_sink = bool(sinks & {"transfer", "burn", "mint", "send", "call",
                               "safetransfer", "safetransferfrom"})
    moves_value = transfer or ledger or authz or value_sink
    external_call = bool(vm.get("guarded_callee_hit")) or bool(df.get("hop_callees")) \
        or bool(sinks & {"call", "delegatecall", "send", "safetransfer",
                         "safetransferfrom", "transfer"})
    reachable = df.get("reachable", False) or transfer or authz or ledger

    # GUARD-CLOSURE DOMINANCE (feeds-verified fix, root-caused 2026-07-14): when
    # EVERY reachable path to this unit's sink is closure-guarded (>=1 guarded
    # path AND 0 genuinely-unguarded paths), a compensating guard dominates and
    # the negated assumption is NOT falsifiable on a reachable path. Conservative
    # by construction: a unit with even one unguarded path stays falsifiable, so a
    # real attack surface is never suppressed. This consumes the authoritative
    # dataflow_paths.jsonl closure verdict the engine already had on disk (step-1c
    # runs before this reasoner) instead of re-deriving from an inline-only bag.
    guard_dominated = (df.get("closure_guarded_n", 0) > 0
                       and df.get("unguarded_n", 0) == 0)
    guard_note = df.get("closure_note", "")

    obligations = []

    def emit(assumption, present, present_anchor, enforce_hit, reason):
        if not present:
            return
        enforced = enforce_hit is not None
        base_falsifiable = (not enforced) and reachable
        dominated = base_falsifiable and guard_dominated
        obligations.append({
            "assumption": assumption,
            "present_signal": present_anchor,
            "enforced": enforced,
            "enforcement_evidence": enforce_hit,
            "falsifiable": base_falsifiable and not guard_dominated,
            "falsifiable_reason": None if enforced else (
                f"guard-closure-dominated: every reachable path to the sink is "
                f"closure-guarded ({guard_note})" if dominated else reason),
            "guard_closure_dominated": dominated,
            "reachable": reachable,
        })

    # ---- caller-trusted: any state mutator assumes the caller is authorized.
    if moves_value:
        auth_hit = _has(exprs, guard_ev, AUTHORITY_RX)
        if auth_hit is None and guarded_flag and AUTHORITY_RX.search(guard_ev):
            auth_hit = {"via": "guard_completeness", "expr": guard_ev[:120]}
        emit("caller-trusted", True,
             {"why": "mutates protected state / moves value",
              "evidence": {"transfer": transfer, "ledger_write": ledger,
                           "authz_write": authz, "value_sink": sorted(sinks & {'transfer','burn','mint','send','call'})},
              "file": file, "line": line},
             auth_hit,
             "state mutator has no caller-identity / access guard on a reachable path")

    # ---- value-bounded: a moved numeric value assumes it is bounded.
    if transfer or value_sink:
        bound_hit = _has(exprs, guard_ev, BOUND_RX)
        emit("value-bounded", True,
             {"why": "moves a numeric value to a transfer/mint/burn sink",
              "evidence": {"transfer": transfer, "sinks": sorted(sinks)},
              "file": file, "line": line},
             bound_hit,
             "moved value has no bound / balance comparison on a reachable path")

    # ---- non-zero: an amount/denominator assumes it is non-zero.
    if transfer or value_sink:
        nz_hit = _has(exprs, guard_ev, NONZERO_RX)
        emit("non-zero", True,
             {"why": "value-moving amount / denominator", "file": file, "line": line},
             nz_hit,
             "amount not asserted non-zero on a reachable path")

    # ---- external-succeeds: an external call assumes it returns success.
    if external_call:
        rc_hit = _has(exprs, guard_ev, RETURN_CHECK_RX)
        emit("external-succeeds", True,
             {"why": "performs an external call / callee dispatch",
              "evidence": {"guarded_callee": bool(vm.get("guarded_callee_hit")),
                           "hop_callees": sorted(list(df.get("hop_callees", set()))[:5])},
              "file": file, "line": line},
             rc_hit,
             "external call return / success not honored on a reachable path")

    # ---- no-reentry: value-mover with an external call assumes no re-entry.
    if moves_value and external_call:
        re_hit = _has(exprs, guard_ev, REENTRY_RX)
        emit("no-reentry", True,
             {"why": "external call inside a value mutator", "file": file, "line": line},
             re_hit,
             "no reentrancy lock between external call and state write")

    # ---- init-once: an initializer assumes it runs once.
    if INIT_RX.search(_norm_fn(fn)):
        io_hit = _has(exprs, guard_ev, INIT_RX)
        if io_hit is None and guarded_flag:
            io_hit = {"via": "guard_completeness", "expr": guard_ev[:120] or "guarded"}
        emit("init-once", True,
             {"why": "initializer/setup function", "file": file, "line": line},
             io_hit,
             "initializer has no run-once guard")

    # ---- order-holds: nonce/sequence signal assumes ordering holds.
    order_present = bool(ORDER_RX.search(guard_ev)) or any(
        ORDER_RX.search(g.get("expr", "")) for g in exprs) or \
        bool(ORDER_RX.search(_norm_fn(fn)))
    if order_present and moves_value:
        ord_hit = _has(exprs, guard_ev, ORDER_RX)
        emit("order-holds", True,
             {"why": "nonce/sequence-bearing state mutator", "file": file, "line": line},
             ord_hit,
             "ordering/nonce precondition present but not asserted as a guard")

    # ---- no-overflow (advisory): arithmetic on a ledger value.
    if ledger and not transfer:
        emit("no-overflow", True,
             {"why": "arithmetic on ledger value (advisory)", "file": file, "line": line},
             None,  # no structural enforcement signature; always advisory-open
             "arithmetic bound not structurally provable from backends (advisory)")
        # demote advisory no-overflow: never falsifiable=True (advisory only)
        obligations[-1]["falsifiable"] = False
        obligations[-1]["advisory"] = True

    return obligations


def run(ws: pathlib.Path, min_signals: int = 1) -> dict:
    vmap = load_value_movers(ws)
    gmap = load_guard_completeness(ws)
    dmap = load_dataflow(ws)
    keys = set(vmap) | set(gmap) | set(dmap)

    units = []
    for k in sorted(keys):
        obls = enumerate_unit(k, vmap.get(k), gmap.get(k), dmap.get(k))
        if len(obls) < min_signals:
            continue
        vm = vmap.get(k) or {}
        gc = gmap.get(k) or {}
        df = dmap.get(k) or {}
        units.append({
            "unit": k,
            "file": vm.get("file") or gc.get("file") or df.get("file") or "",
            "function": vm.get("function") or gc.get("function") or "",
            "assumptions": obls,
            "falsifiable_count": sum(1 for o in obls if o["falsifiable"]),
        })

    total_obl = sum(len(u["assumptions"]) for u in units)
    total_fals = sum(u["falsifiable_count"] for u in units)
    by_axis = defaultdict(lambda: [0, 0])  # [present, falsifiable]
    for u in units:
        for o in u["assumptions"]:
            by_axis[o["assumption"]][0] += 1
            if o["falsifiable"]:
                by_axis[o["assumption"]][1] += 1

    return {
        "workspace": str(ws),
        "units_analyzed": len(units),
        "backends": {
            "value_moving_functions": len(vmap),
            "guard_completeness": len(gmap),
            "dataflow_paths": len(dmap),
        },
        "total_obligations": total_obl,
        "falsifiable_obligations": total_fals,
        "by_axis": {a: {"present": v[0], "falsifiable": v[1]} for a, v in sorted(by_axis.items())},
        "units": units,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("workspace")
    ap.add_argument("--json", action="store_true", help="emit full report JSON to stdout")
    ap.add_argument("--only-falsifiable", action="store_true",
                    help="restrict the written jsonl to falsifiable obligations")
    ap.add_argument("--min-signals", type=int, default=1)
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    ws = pathlib.Path(args.workspace).resolve()
    if not ws.exists():
        print(f"[err] workspace not found: {ws}", file=sys.stderr)
        return 2
    rep = run(ws, min_signals=args.min_signals)

    outp = pathlib.Path(args.out) if args.out else (_adir(ws) / "assumption_falsification_obligations.jsonl")
    outp.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with outp.open("w") as fh:
        for u in rep["units"]:
            for o in u["assumptions"]:
                if args.only_falsifiable and not o["falsifiable"]:
                    continue
                row = {"unit": u["unit"], "file": u["file"], "function": u["function"], **o}
                fh.write(json.dumps(row) + "\n")
                n += 1

    if args.json:
        print(json.dumps(rep, indent=2, default=list))
    else:
        print(f"[assumption-enum-falsify] ws={ws.name} units={rep['units_analyzed']} "
              f"obligations={rep['total_obligations']} falsifiable={rep['falsifiable_obligations']} "
              f"-> {outp} ({n} rows)", file=sys.stderr)
        for a, v in rep["by_axis"].items():
            print(f"    {a:18s} present={v['present']:4d} falsifiable={v['falsifiable']:4d}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
