#!/usr/bin/env python3
"""go-mustsucceed-panic-reachability.py - the Go consensus-halt reasoning query.

LOGIC CAPABILITY (docs/LOGIC_ARSENAL_ROADMAP.md, Go must-succeed panic class).
This is a TAINT-REACHABILITY / CALL-GRAPH-COMPOSITION query over the OWNED
go-dataflow SSA backend, NOT a grep for `x.(T)`.

THE INVARIANT (Cosmos/Go-L1 deterministic validator halt)
  A Cosmos app's ABCI / module-lifecycle path - BeginBlock(er) / EndBlock(er) /
  PreBlock(er) / FinalizeBlock / PrepareProposal / ProcessProposal / ExtendVote /
  VerifyVoteExtension / InitChain / Commit - is a MUST-SUCCEED path: baseapp runs
  it OUTSIDE the per-tx `recoverTx` deferred-recover, so a panic there is NOT
  caught-and-rolled-back (as it is for a Msg handler) - it propagates, every
  honest validator re-executes the same block deterministically, and the chain
  HALTS. The trust boundary therefore requires:

    For every panic-CAPABLE node N (an unchecked type-assert `x.(T)`, a slice/
    array/string INDEX that can go out of range, or a nil-pointer DEREF) whose
    triggering operand is ATTACKER-CONTROLLED (data-dependent on a msg field /
    packet data / vote-extension byte a param carries): N is NOT reachable in the
    forward call-closure of a MUST-SUCCEED entrypoint (or that operand is
    validated before it).

  Every attacker-tainted panic node reachable from a must-succeed root is a
  consensus-halt lead, emitted as a `mustsucceed-panic-reachability` obligation.

WHY THIS IS LOGIC, NOT A SHAPE (guard-rail satisfied)
  The existing detector for this family
  (ingress_unbounded_loop_or_panic_hypotheses.jsonl, pattern_id
  `go.panic.untrusted_ingress_unbounded_loop_or_panic`) is a SNIPPET regex: it
  matches a `for ... range m.X` / `x.(T)` TEXT in a msg's ValidateBasic body. It
  cannot tell a recover-wrapped Msg handler (panic = failed tx, harmless) from a
  must-succeed ABCI hook (panic = chain halt), and it never proves the panic
  operand is param-tainted. This query differs on the three axes that make it a
  reachability relation:
    (a) PANIC membership is an IR-level SSA fact (a *ssa.TypeAssert with
        CommaOk==false / a *ssa.Index[Addr] / a *ssa.UnOp MUL nil-deref) whose
        triggering operand the go-dataflow BACKWARD SLICER traced to a
        *ssa.Parameter - not a text match on `.(`;
    (b) the answer is a RELATION between two sets of functions computed by a
        forward call-graph closure: {fns reachable from a must-succeed ABCI/
        lifecycle root} INTERSECT {fns containing an attacker-tainted panic node}
        - a panic three helper-hops below EndBlocker is correctly included, a
        panic in a recover-wrapped Msg handler is correctly excluded;
    (c) the must-succeed vs recover-wrapped distinction is a SEMANTIC property of
        the ABCI framework (the go_entrypoint_surface entry-family taxonomy),
        located anywhere in the closure, never a same-body token.

OWNED BACKENDS CONSUMED (no new engine built here)
  1. <ws>/.auditooor/dataflow_paths*.jsonl (schema dataflow_path.v1), produced by
     tools/go-dataflow.py run with `-panic-sinks`. The panic arm emits
     kind=="panic" records (sink.panic_op in {type-assert,index,slice-bounds,
     nil-deref}) whose source.kind=="param" - the attacker-reaches-panic fact.
     Every record (panic AND value/state) also seeds the forward call-graph edge
     set (source.fn REACHES sink.fn; hop.fn chain gives the intermediate reach).
  2. tools/go_entrypoint_surface.is_go_entry_point + the ABCI/lifecycle name
     families (_ABCI_CONSENSUS_NAMES | _MODULE_LIFECYCLE_NAMES) - the single
     source of truth for "is this a MUST-SUCCEED consensus entrypoint". Msg
     handlers / ante / genesis / query are recover-wrapped or read-only and are
     NOT roots.

OUTPUT
  <ws>/.auditooor/mustsucceed_panic_obligations.jsonl - one row per survivor,
  schema `auditooor.mustsucceed_panic_reachability.v1`, exploit_queue-ingest
  compatible (exploit-queue.py _gather_from_mustsucceed_panic_obligations ->
  queue -> per-fn-mimo-batch-gen OPEN-OBLIGATIONS block).
  A summary (--json) reports |MUSTSUCCEED roots|, |attacker-tainted panic nodes|,
  |reachable survivors|, and the KEPT (panic nodes NOT reachable from any
  must-succeed root, proving the reachability filter is non-vacuous).
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent

# ---------------------------------------------------------------------------
# MUST-SUCCEED entrypoint families - the ONLY roots whose panic HALTS the chain
# (run OUTSIDE baseapp's per-tx deferred recover). Sourced from the owned
# go_entrypoint_surface taxonomy (single source of truth); a local fallback
# mirrors it so the reasoner degrades gracefully if the import path shifts.
# ---------------------------------------------------------------------------
try:
    from go_entrypoint_surface import (  # type: ignore
        _ABCI_CONSENSUS_NAMES as _ABCI,
        _MODULE_LIFECYCLE_NAMES as _LIFECYCLE,
    )
    _MUSTSUCCEED_NAMES = set(_ABCI) | set(_LIFECYCLE)
    _MUSTSUCCEED_SRC = "go_entrypoint_surface"
except Exception:  # pragma: no cover - defensive fallback
    _MUSTSUCCEED_NAMES = {
        "InitChain", "PrepareProposal", "ProcessProposal", "ExtendVote",
        "VerifyVoteExtension", "FinalizeBlock", "Commit",
        "BeginBlock", "EndBlock", "Midblock", "MidBlock",
        "PreBlocker", "PreBlock", "BeginBlocker", "EndBlocker", "Midblocker",
    }
    _MUSTSUCCEED_SRC = "local-fallback"

# CheckTx/DeliverTx/Query are recover-wrapped or read-only in baseapp - a panic
# there does NOT halt consensus. They live in _ABCI_CONSENSUS_NAMES (that gate
# measures ATTACK SURFACE, a broader question); for the CONSENSUS-HALT invariant
# they must be excluded from the must-succeed ROOT set.
_RECOVER_WRAPPED = {"CheckTx", "DeliverTx", "Query", "Info"}
_MUSTSUCCEED_NAMES = {n for n in _MUSTSUCCEED_NAMES if n not in _RECOVER_WRAPPED}

_PANIC_KIND = "panic"

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


def _short_fn(fn: str) -> str:
    """Bare method name from a Go '(*pkg.T).Method' / 'pkg.func' identity."""
    s = (fn or "").strip()
    if ")." in s:
        s = s.rsplit(").", 1)[-1]
    s = s.split("(")[0].replace("*", "")
    return s.split(".")[-1].strip()


def _contract_of(fn: str) -> str:
    """Receiver TYPE for the obligation `contract` field, best-effort."""
    s = (fn or "").strip()
    if ")." in s:
        recv = s.rsplit(").", 1)[0].lstrip("(").lstrip("*")
        return recv.split(".")[-1]
    head = s.split("(")[0]
    parts = head.split(".")
    return parts[0] if len(parts) > 1 else ""


def _in_scope_file(fpath: str, ws_root: Path, include_oos: bool) -> bool:
    """An in-scope panic node's file lives UNDER the workspace root, is not a
    vendored module-cache path, is not codegen, and passes the shared OOS guard.
    A panic inside a cosmos-sdk dependency is not an in-scope obligation (the
    protocol did not author it) - only the fork/app code is."""
    if not fpath:
        return False
    low = fpath.replace("\\", "/").lower()
    if any(m in low for m in _VENDOR_MARKERS):
        return False
    if any(low.endswith(s) for s in _CODEGEN_SUFFIXES):
        return False
    # A relative sink.file (some go-dataflow configs emit module-relative paths)
    # must be anchored to the ws root before the containment check - otherwise
    # `.resolve()` would resolve it against the process CWD and `relative_to`
    # would wrongly reject an in-scope node (a silent false-negative that starves
    # the whole reachability set). Absolute paths are used as-is.
    p = Path(fpath)
    if not p.is_absolute():
        p = ws_root / p
    try:
        rel = p.resolve().relative_to(ws_root)
    except Exception:
        return False
    if not include_oos and is_oos(str(rel)):
        return False
    return True


class PanicNode:
    __slots__ = ("fn", "file", "line", "op", "src_var", "src_fn", "lang",
                 "guarded", "n_records")

    def __init__(self, key):
        self.fn = key[0]
        self.file = key[1]
        self.line = key[2]
        self.op = ""
        self.src_var = ""
        self.src_fn = ""
        self.lang = "go"
        self.guarded = True   # AND across records: a node is guarded only if EVERY
        self.n_records = 0    # tainted record for it carries a dominating guard.


def load_records(paths):
    """Yield (rec, source_path) for every non-degraded go record across the given
    dataflow jsonl files."""
    for p in paths:
        if not p or not Path(p).is_file():
            continue
        with Path(p).open(encoding="utf-8") as fh:
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
                if str(rec.get("language") or "") not in ("go", ""):
                    continue
                yield rec


def build(paths, ws_root: Path, include_oos: bool):
    """Fold the dataflow records into (edges, panic_nodes, roots, warnings).

    edges     : forward call-graph adjacency {caller_fn -> {callee_fn}}, seeded
                from source.fn -> sink.fn of EVERY record plus the hop.fn chain.
    panic_nodes: {(fn,file,line) -> PanicNode} for kind==panic, source.kind==param
                in-scope records (attacker-tainted panic-capable nodes).
    roots     : {fn identity : bare_name} for every fn seen whose bare method name
                is in the MUST-SUCCEED family.
    """
    edges: dict[str, set] = collections.defaultdict(set)
    panic_nodes: dict[tuple, PanicNode] = {}
    roots: dict[str, str] = {}
    seen_fns: set[str] = set()
    n_records = 0
    n_degraded_only = True

    def _note_fn(fn: str):
        if not fn:
            return
        seen_fns.add(fn)
        bn = _short_fn(fn)
        if bn in _MUSTSUCCEED_NAMES:
            roots[fn] = bn

    for rec in load_records(paths):
        n_degraded_only = False
        n_records += 1
        src = rec.get("source") or {}
        sink = rec.get("sink") or {}
        src_fn = str(src.get("fn") or "")
        sink_fn = str(sink.get("fn") or "")
        _note_fn(src_fn)
        _note_fn(sink_fn)
        # forward reach edge: the tainted param enters at src_fn and flows to the
        # sink deeper in the call tree -> src_fn can REACH sink_fn.
        if src_fn and sink_fn and src_fn != sink_fn:
            edges[src_fn].add(sink_fn)
        # hop chain gives intermediate call reach (each hop.fn is on the path).
        chain = [src_fn] + [str(h.get("fn") or "") for h in (rec.get("hops") or [])] + [sink_fn]
        chain = [c for c in chain if c]
        for a, b in zip(chain, chain[1:]):
            if a != b:
                edges[a].add(b)
                _note_fn(a)
                _note_fn(b)
        # attacker-tainted panic node
        if str(sink.get("kind") or "") == _PANIC_KIND and str(src.get("kind") or "") == "param":
            pfile = str(sink.get("file") or "")
            if not _in_scope_file(pfile, ws_root, include_oos):
                continue
            key = (sink_fn, pfile, int(sink.get("line") or 0))
            node = panic_nodes.get(key)
            if node is None:
                node = PanicNode(key)
                panic_nodes[key] = node
            node.n_records += 1
            if not node.op:
                node.op = str(sink.get("panic_op") or "")
            if not node.src_var:
                node.src_var = str(src.get("var") or "")
            if not node.src_fn:
                node.src_fn = src_fn
            # a node is GUARDED (removed) only if EVERY tainted record for it
            # carries a dominating guard (unguarded==False); one unguarded record
            # keeps the node live. rec.unguarded defaults True (no guard) in the
            # dataflow schema, so an absent/True value leaves the node a survivor.
            node.guarded = node.guarded and (rec.get("unguarded") is False)
    warnings = []
    if n_degraded_only:
        warnings.append(
            "no non-degraded Go dataflow records found - the panic substrate is "
            "starved (go-dataflow must be re-run with `-panic-sinks` scoped to the "
            "in-scope ABCI/keeper packages). The reachability set is vacuously "
            "empty, NOT proven-clean.")
    return edges, panic_nodes, roots, warnings, n_records


def forward_closure(roots: set, edges: dict) -> set:
    """BFS forward reachability from the root fn identities over the call edges."""
    seen = set(roots)
    stack = list(roots)
    while stack:
        cur = stack.pop()
        for nxt in edges.get(cur, ()):  # noqa: SIM118
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def classify(edges, panic_nodes, roots):
    """Compute REACHABLE (panic nodes in the forward closure of a must-succeed
    root) vs KEPT (panic nodes NOT reachable - the non-vacuity witness)."""
    reach = forward_closure(set(roots.keys()), edges)
    survivors = []
    kept = []
    for key, node in panic_nodes.items():
        # A node is a survivor iff its containing fn is reachable from a
        # must-succeed root (a root panicking IN ITS OWN body is reachable: the
        # root is in its own closure). A guarded operand (dominating validation
        # on every tainted record) removes it.
        if node.fn in reach and not node.guarded:
            survivors.append(node)
        else:
            kept.append(node)
    return survivors, kept, reach


def _nearest_root(node: PanicNode, edges, roots) -> str:
    """Best-effort: a must-succeed root that reaches node.fn (for the citation).
    Returns '' if none directly resolvable (still reachable transitively)."""
    for r in roots:
        if r == node.fn:
            return r
        # 1-2 hop check keeps the citation cheap; the survivor set already proved
        # transitive reach in classify().
        if node.fn in edges.get(r, ()):  # noqa: SIM118
            return r
    for r in roots:
        if forward_closure({r}, edges) and node.fn in forward_closure({r}, edges):
            return r
    return ""


def make_obligation(node: PanicNode, edges, roots, invariant_id: str) -> dict:
    short = _short_fn(node.fn)
    contract = _contract_of(node.fn)
    root_fn = _nearest_root(node, edges, roots)
    root_name = _short_fn(root_fn) if root_fn else "(transitive must-succeed root)"
    src_ref = node.file + (f":{node.line}" if node.line else "")
    op_desc = {
        "type-assert": "an unchecked type assertion (x.(T) without comma-ok)",
        "index": "an out-of-range slice/array index",
        "slice-bounds": "an out-of-range slice expression bound",
        "nil-deref": "a nil-pointer dereference",
    }.get(node.op, f"a panic-capable {node.op} node")
    root = (
        f"MUST-SUCCEED consensus path '{root_name}' reaches {op_desc} in "
        f"'{node.fn}' whose triggering operand is data-dependent on an "
        f"attacker-controlled parameter"
        + (f" ('{node.src_var}')" if node.src_var else "")
        + ". Because baseapp runs ABCI/module-lifecycle paths OUTSIDE the per-tx "
        "deferred recover, an attacker who drives this operand to the panicking "
        "value causes a deterministic panic every validator re-hits on block "
        "re-execution -> chain halt (liveness failure)."
    )
    return {
        "schema": "auditooor.mustsucceed_panic_reachability.v1",
        "obligation_type": "mustsucceed-panic-reachability",
        "contract": contract,
        "function": short,
        "function_signature": node.fn,
        "language": node.lang,
        "source_refs": [src_ref] if src_ref else [],
        "file": node.file,
        "line": node.line,
        "panic_op": node.op,
        "attacker_param": node.src_var,
        "attacker_param_fn": node.src_fn,
        "mustsucceed_root": root_fn,
        "mustsucceed_root_name": root_name,
        "attack_class": "mustsucceed-path-attacker-panic-consensus-halt",
        "likely_severity": "high",
        "broken_invariant_ids": [invariant_id],
        "root_cause_hypothesis": root,
        "quality_gate_status": "needs_source",
        "proof_status": "needs_source",
        "advisory_only": True,
        "learning_route": "mine-source",
        "falsification_requirements": [
            "RECOVER_WRAP: prove the panicking node is NOT actually run inside a "
            "deferred recover (a module BeginBlock/EndBlock wrapped in "
            "app.BeginBlocker's own recover, or an inner utils.RunCached recover, "
            "KILLS the halt claim).",
            "ATTACKER_REACH: confirm the tainted operand is externally reachable "
            "to the panicking value - a msg field / packet data / vote-extension "
            "byte with no prior ValidateBasic / bounds / type guard between ingress "
            "and the node.",
            "DETERMINISM: show every honest validator re-executes the same block "
            "and panics identically (a non-deterministic-only panic is a fork, a "
            "different class).",
        ],
        "next_command": (
            "read the fn body + the must-succeed caller closure; if the panic "
            "operand is genuinely attacker-reachable and unguarded and the path is "
            "not recover-wrapped, drive an executed restart-survival PoC (R82)."
        ),
    }


def run(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--dataflow", default=None,
                    help="override primary dataflow_paths.jsonl path")
    ap.add_argument("--include-oos", action="store_true",
                    help="do NOT apply the scope OOS filter (debug)")
    ap.add_argument("--invariant-id",
                    default="INV-MUSTSUCCEED-PATH-NO-ATTACKER-PANIC")
    ap.add_argument("--emit", default=None,
                    help="output jsonl path (default "
                         "<ws>/.auditooor/mustsucceed_panic_obligations.jsonl)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit non-zero if the panic dataflow substrate is fully "
                         "starved (no non-degraded records -> reachability could "
                         "not be computed)")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    adir = ws / ".auditooor"
    paths: list[Path] = []
    if args.dataflow:
        paths.append(Path(args.dataflow).expanduser())
    else:
        main_df = adir / "dataflow_paths.jsonl"
        if main_df.is_file():
            paths.append(main_df)
        # auto-union every scoped sidecar (dataflow_paths.<scope>.jsonl), which is
        # where a per-package `-panic-sinks` run lands on a heavy Cosmos monorepo.
        for sib in sorted(adir.glob("dataflow_paths.*.jsonl")):
            if sib not in paths:
                paths.append(sib)

    edges, panic_nodes, roots, warnings, n_records = build(
        paths, ws, include_oos=args.include_oos)
    survivors, kept, reach = classify(edges, panic_nodes, roots)

    obligations = []
    _seen = set()
    for node in sorted(survivors, key=lambda n: (n.file, n.line, n.fn)):
        dk = (node.file, node.line, _short_fn(node.fn))
        if dk in _seen:
            continue
        _seen.add(dk)
        obligations.append(make_obligation(node, edges, roots, args.invariant_id))

    emit = Path(args.emit).expanduser() if args.emit else \
        adir / "mustsucceed_panic_obligations.jsonl"
    emit.parent.mkdir(parents=True, exist_ok=True)
    with emit.open("w", encoding="utf-8") as fh:
        for ob in obligations:
            fh.write(json.dumps(ob) + "\n")
        # Capability-vacuity-telltale: the reachability join RAN over a real Go
        # entrypoint surface (>=1 record) and produced 0 reachable panic survivors.
        # PERSIST an explicit cited-empty examined-record so the reasoner-firing gate
        # scores this FIRED_CLEAN (ran, examined, recorded 0) not silently VACUOUS.
        if not obligations and n_records > 0:
            fh.write(json.dumps({
                "schema": "auditooor.mustsucceed_panic_reachability.examined_record.v1",
                "note": ("cited-empty: must-succeed panic-reachability join ran over "
                         "the Go entrypoint surface, 0 reachable panic survivors"),
                "survivors": [],
                "report": {
                    "reasoner": "go-mustsucceed-panic-reachability",
                    "totals": {"examined": n_records,
                               "mustsucceed_roots": len(roots),
                               "panic_nodes": len(panic_nodes)},
                },
            }) + "\n")

    substrate_starved = bool(warnings) and not panic_nodes

    summary = {
        "schema": "auditooor.mustsucceed_panic_reachability_summary.v1",
        "workspace": str(ws),
        "dataflow_paths": [str(p) for p in paths],
        "mustsucceed_family_source": _MUSTSUCCEED_SRC,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "n_go_records": n_records,
        "n_mustsucceed_roots": len(roots),
        "mustsucceed_roots": sorted({_short_fn(r) for r in roots}),
        "n_attacker_tainted_panic_nodes": len(panic_nodes),
        "n_reachable_survivors": len(survivors),
        "n_kept_unreachable_or_guarded": len(kept),
        "panic_op_breakdown": dict(collections.Counter(
            n.op for n in survivors)),
        "survivors": [
            {"fn": _short_fn(n.fn), "signature": n.fn, "op": n.op,
             "file": n.file, "line": n.line, "attacker_param": n.src_var}
            for n in survivors[:60]
        ],
        "obligations_written": len(obligations),
        "obligations_path": str(emit),
        "warnings": warnings,
        "substrate_starved": substrate_starved,
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[mustsucceed-panic] {ws.name}: "
              f"|MUSTSUCCEED roots|={summary['n_mustsucceed_roots']} "
              f"|attacker-tainted panic nodes|={summary['n_attacker_tainted_panic_nodes']} "
              f"reachable-survivors={summary['n_reachable_survivors']} "
              f"kept(unreachable/guarded)={summary['n_kept_unreachable_or_guarded']} "
              f"-> {len(obligations)} mustsucceed-panic obligation(s)")
        for s in summary["survivors"][:40]:
            print(f"  SURVIVOR {s['fn']} [{s['op']}] param={s['attacker_param']}  "
                  f"{s['file']}:{s['line']}")
        for w in warnings:
            print(f"  WARN {w}", file=sys.stderr)
        print(f"  -> {emit}")

    if args.fail_closed and substrate_starved:
        return 3
    return summary


if __name__ == "__main__":
    out = run()
    if out == 3:
        sys.exit(3)
