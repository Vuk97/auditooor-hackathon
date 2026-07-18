#!/usr/bin/env python3
# <!-- r36-rebuttal: lane composition-novelty registered via dispatch report; enforcement lane owns runbook wiring -->
"""composition-novelty-search.py  (CNS)

NOVELTY-GENERATION LAYER primitive (docs/LOGIC_ARSENAL_ROADMAP.md), sibling of
protocol-invariant-synth-violation-search.py (PISVS).

WHAT MAKES THIS DIFFERENT FROM atomic-sequence-economic-sequencer (ATES) AND
callgraph-set-difference-hunter (CGSD)
========================================================================
ATES hard-codes ONE composition class (flash-loan borrow->pump->withdraw over a
value-conservation cell). CGSD hard-codes the Euler DOWN\\CHECK unguarded-mutation
class. Both are single-class recognizers.

CNS is CLASS-AGNOSTIC. It takes the target's OWN derived invariants (PISVS +
coupled-state graph + value-conservation synth - REUSED, never rebuilt) and, for
each derived invariant I and each reachable ordered op-pair (op_a, op_b) that
write/read a COMMON state node touched by I, poses the never-covered mega-hack
question:

    I(op_a) = ok   AND   I(op_b) = ok   AND   I(op_a ; op_b) = VIOLATED

Neither op individually is a known-class hit (each preserves I in isolation, which
is exactly why a per-function audit passes each) - the bug lives ONLY in the
SEQUENTIAL composition. That difference (single-op-safe vs composition-violated) is
the finding, and it is a class no per-function recognizer owns.

THE LOGIC TRIPLE (assumption / invariant / trust-boundary)
  ASSUMPTION: each operation independently preserves every derived invariant I
    (verified in isolation; per-function audits therefore pass each op).
  INVARIANT (meta): for every derived I and every reachable ordered pair
    (op_a, op_b) sharing a state node of I, I holds after op_a;op_b iff it holds
    after each alone.  The bug is  I(op_a)=ok AND I(op_b)=ok AND I(op_a;op_b)=bad.
  TRUST-BOUNDARY: atomicity/ordering across the two ops is ASSUMED but not
    enforced - no shared lock spans the pair, no post-composition assertion node
    dominates it.  op_a moves a member of I to a boundary; op_b's precondition
    assumed the pre-op_a value.

THE REASONING QUERY (composition over the OWNED coupled-state graph, not a shape)
  1. InvariantsOf(target) = REUSE the derived-invariant producers:
       - PISVS  .auditooor/pisvs/derived_invariants.jsonl (D1 ratio-authority,
         D2 escrow=liability, D3 supply-monotonicity).
       - coupled-state graph  .auditooor/state_coupling_edges.jsonl (must-move-
         together groups: cell_a<->cell_b).
     Each invariant carries its STATE-SYMBOL set (the nodes it constrains) and a
     per-symbol coupled-member set.
  2. Candidate op-pairs = from the OWNED coupled-state graph (state-node ->
     writer-fn edges from writers_a/writers_b/violators) UNIONED with the shared-
     ledger-field index from value_moving_functions.json.  For each state node S
     touched by I, enumerate ordered pairs (op_a, op_b) of mutators/readers of S
     (and of S's coupled siblings).  This is the SAME shared-state-node index ATES
     builds - reused, not rebuilt.
  3. SURVIVOR = a pair where a lightweight symbolic/effect check shows I is
     preserved by op_a ALONE and by op_b ALONE (single-op-safe: neither op is a
     coupled-state single-op violator of I, i.e. neither omits a member of I in
     isolation), BUT the SEQUENTIAL effect (op_a then op_b) can violate I - op_a
     writes a member of I that op_b reads/depends on as a precondition (ratio
     denominator, guard threshold, coupled sibling), AND no shared lock and no
     post-composition assertion node dominates the pair.

GUARD-RAIL (why this is a per-invariant single-op-safe-vs-composition-violated
difference over reachable op-pairs, NOT a grep for two function names)
  (a) the unit is an ordered PAIR keyed to a DERIVED invariant's shared state
      node; removing I, or the shared node, or making op_b not touch I's state,
      dissolves the finding (mutation-verifiable - the tests do exactly this).
  (b) single-op-safe is a per-op RELATION to I (not-a-single-op-violator), and
      composition-violating is a SECOND relation (op_a writes what op_b depends
      on) - a set/relation over two functions, not a boolean over one body.
  (c) the dominator check is a REACHABILITY NEGATIVE (shared lock / post-
      composition assertion / guarded-reader over the coupling) - a dominator
      anywhere over the pair KILLS the survivor.

HONESTY (the effect check is ADVISORY by construction)
  A static effect model CANNOT prove a numeric boundary crossing on a real
  interleaving.  So every survivor carries effect_confidence:
      "static-differential"  - a structural sequential-dependency signal is
                               present (op_a writes a member op_b reads as a
                               precondition, e.g. a ratio denominator / coupled
                               sibling that op_b assumes stable).
      "needs_source"         - the sequential effect cannot be confirmed
                               statically; the pair is a search obligation only.
  CNS NEVER emits a CONFIRMED composition bug.  A CONFIRMED verdict REQUIRES a
  downstream EXECUTED PoC (rubric item 7).  Every obligation carries
  proof_status="open" / search_status="needs-search".

OUTPUT (advisory; never self-credits coverage)
  <ws>/.auditooor/composition_novelty/
    composition_survivors.jsonl        - one survivor per line
    composition_novelty_obligations.jsonl - search obligations (queue-ingest)
    composition_novelty_manifest.json  - census + counts + substrate status
  Also publishes <ws>/.auditooor/composition_novelty_obligations.jsonl at the
  .auditooor root (the name the logic-obligation-resolution gate + exploit-queue
  novelty consumer key on).

  substrate status is HONEST:
    "cited-empty"      - invariants + op-writers present, 0 survivors (cites why).
    "substrate_vacuous"- no derived invariants AND no coupled edges present (the
                         producers did not run) - a FAIL-LOUD, never a silent pass.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

SCHEMA = "auditooor.composition_novelty.v1"

_TOOLS_DIR = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Substrate dependency (EXPLICIT). CNS owns NO substrate of its own - it REUSES
# the ledgers written by the invariant producers. These are the ONLY inputs the
# composition query reads; their ABSENCE means the producers never ran, which is
# a FAIL-LOUD substrate_vacuous, never a fabricated survivor.
# ---------------------------------------------------------------------------
def _substrate_arms(ws: Path) -> dict:
    aud = ws / ".auditooor"
    return {
        # PISVS derived invariants (with the root fallback PISVS also publishes)
        ".auditooor/pisvs/derived_invariants.jsonl (PISVS)": [
            aud / "pisvs" / "derived_invariants.jsonl",
            aud / "novelty_obligations.jsonl",
        ],
        # coupled-state graph edges (must-move-together cells + op-writers)
        ".auditooor/state_coupling_edges.jsonl (coupled-state graph)": [
            aud / "state_coupling_edges.jsonl",
        ],
    }


def _missing_producers(ws: Path) -> list[str]:
    """Return [] if AT LEAST ONE substrate arm materialized (producers ran); else
    the list of absent producer ledgers (substrate_vacuous - fail-loud)."""
    arms = _substrate_arms(ws)
    present = {label: any(p.is_file() for p in paths)
               for label, paths in arms.items()}
    if any(present.values()):
        return []
    return [label for label, ok in present.items() if not ok]


# Producer scripts run by --autorun-producers, in dependency order. Each entry is
# (script-name-in-tools/, argv-tail) run with the current interpreter. Failures
# are tolerated per-producer; substrate presence is re-checked afterwards and the
# honest substrate_vacuous verdict still fires if nothing materialized.
def _producer_commands(ws: Path) -> list[tuple[str, list[str]]]:
    wss = str(ws)
    return [
        ("protocol-invariant-synth-violation-search.py", [wss]),
        ("coupled-state-completeness-graph.py", ["--workspace", wss]),
        # writes state_coupling_edges.jsonl (the coupled arm CNS actually reads)
        ("state-coupling-graph.py", ["--workspace", wss, "--emit"]),
    ]


def _autorun_producers(ws: Path) -> list[dict]:
    """Materialize the substrate by running the invariant producers on <ws>
    BEFORE the composition query. Returns a per-producer run log."""
    log: list[dict] = []
    for script, tail in _producer_commands(ws):
        path = _TOOLS_DIR / script
        if not path.is_file():
            log.append({"producer": script, "ok": False,
                        "reason": "producer-script-not-found"})
            continue
        try:
            cp = subprocess.run(
                [sys.executable, str(path), *tail],
                capture_output=True, text=True, timeout=900)
            log.append({"producer": script, "ok": cp.returncode == 0,
                        "returncode": cp.returncode,
                        "stderr_tail": (cp.stderr or "")[-400:]})
        except Exception as exc:  # noqa: BLE001 - report, never crash CNS
            log.append({"producer": script, "ok": False,
                        "reason": f"{type(exc).__name__}: {exc}"})
    return log

# ---------------------------------------------------------------------------
# Shared-lock / atomicity tokens: a token on BOTH ops (a lock they share) or a
# post-composition assertion node dominates the pair -> KILLS the survivor. Same
# vocabulary ATES uses for its atomicity-guard reachability negative.
# ---------------------------------------------------------------------------
_LOCK_TOKEN = re.compile(
    r"nonreentrant|reentrancyguard|_locked|_status\b|mutex|\block\b|"
    r"snapshot|checkpoint|commit(?:ment|reveal|hash)|"
    r"lastblock|blockheight|block\.number|blocknumber",
    re.IGNORECASE,
)


def _short(fn: str) -> str:
    s = (fn or "").strip()
    if ")." in s:
        s = s.rsplit(").", 1)[-1]
    return s.split("(")[0].replace("*", "").split(".")[-1].strip()


def _ref(file: str, line) -> str | None:
    if not file:
        return None
    return f"{file}:{line}" if line not in (None, "", 0) else str(file)


def _sym(name: str) -> str:
    """Normalise a state-symbol / cell to its bare comparable token."""
    s = (name or "").strip()
    s = s.split(".")[-1]
    s = re.sub(r"^external:", "", s)
    return s.lower()


# ---------------------------------------------------------------------------
# Invariant model
# ---------------------------------------------------------------------------
class Invariant:
    __slots__ = ("iid", "form", "text", "symbols", "coupled_members", "file",
                 "line", "novelty", "origin")

    def __init__(self, iid, form, text, symbols, coupled_members, file, line,
                 novelty, origin):
        self.iid = iid
        self.form = form
        self.text = text
        self.symbols = symbols                # set[str] normalised node tokens
        self.coupled_members = coupled_members  # set[str] must-move-together tokens
        self.file = file
        self.line = line
        self.novelty = novelty                # RESIDUAL / NOVEL / KNOWN / null
        self.origin = origin                  # pisvs | coupled-state-graph


def _load_pisvs_invariants(ws: Path) -> list[Invariant]:
    out: list[Invariant] = []
    p = ws / ".auditooor" / "pisvs" / "derived_invariants.jsonl"
    if not p.is_file():
        # fall back to the root novelty_obligations ledger PISVS also publishes
        p = ws / ".auditooor" / "novelty_obligations.jsonl"
    if not p.is_file():
        return out
    for line in p.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        form = str(d.get("form") or d.get("invariant_form") or "")
        text = str(d.get("statement") or d.get("invariant_text") or "")
        symbols: set[str] = set()
        for k in ("numerator", "denominator", "field"):
            v = d.get(k)
            if v:
                symbols.add(_sym(str(v)))
        for lf in (d.get("liability_fields") or []):
            symbols.add(_sym(str(lf)))
        site = d.get("site") or {}
        for k in ("numerator", "denominator", "field"):
            v = site.get(k)
            if v:
                symbols.add(_sym(str(v)))
        symbols.discard("")
        if not symbols:
            continue
        iid = str(d.get("invariant_id") or d.get("obligation_id") or
                  ("cns-inv-" + hashlib.sha1(text.encode()).hexdigest()[:10]))
        file = str(d.get("file") or (site.get("file") if site else "") or "")
        line_no = d.get("line") or (site.get("line") if site else None)
        # D1 (ratio) + D3 (supply) both constrain their symbol set as a coupled
        # group (numerator must-move-with denominator; supply must-move-with its
        # matched mint/burn). D2 escrow: balance must-move-with liability.
        out.append(Invariant(
            iid=iid, form=form, text=text, symbols=symbols,
            coupled_members=set(symbols), file=file, line=line_no,
            novelty=str(d.get("corpus_verdict") or d.get("verdict") or "").upper()
            or None,
            origin="pisvs"))
    return out


def _load_coupled_invariants(ws: Path) -> list[Invariant]:
    """Each state_coupling_edge is a must-move-together invariant over
    {cell_a, cell_b}."""
    out: list[Invariant] = []
    p = ws / ".auditooor" / "state_coupling_edges.jsonl"
    if not p.is_file():
        return out
    for line in p.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            edge = json.loads(line)
        except Exception:
            continue
        a, b = edge.get("cell_a"), edge.get("cell_b")
        if not a or not b:
            continue
        symbols = {_sym(str(a)), _sym(str(b))}
        symbols.discard("")
        if len(symbols) < 2:
            continue
        iid = "cns-cpl-" + str(edge.get("edge_id") or
                               hashlib.sha1(f"{a}{b}".encode()).hexdigest()[:10])
        text = str(edge.get("obligation") or f"{a} and {b} must move together")
        file = ""
        line_no = None
        for v in (edge.get("violators") or []):
            if v.get("file"):
                file, line_no = str(v["file"]), v.get("line")
                break
        out.append(Invariant(
            iid=iid, form="COUPLED_MUST_MOVE_TOGETHER", text=text,
            symbols=symbols, coupled_members=set(symbols), file=file,
            line=line_no, novelty=None, origin="coupled-state-graph"))
    return out


# ---------------------------------------------------------------------------
# Node -> writer/reader index (the shared-state-node index, REUSED from the
# coupled-state graph + value_moving_functions, not rebuilt).
# ---------------------------------------------------------------------------
class OpProfile:
    """Per-op relation to the state graph: which symbols it writes / reads, its
    lock evidence, and (per coupled edge) whether it is a single-op VIOLATOR.
    graph_writes = the subset of writes that came from the OWNED coupled-state
    graph (a value CELL), used to bound the op-pair enumeration to graph cells
    (the anti-explosion guard-rail: never all-pairs over generic struct fields)."""
    __slots__ = ("name", "writes", "graph_writes", "reads", "lock_hit",
                 "single_op_violator_of", "file", "line", "role")

    def __init__(self, name):
        self.name = name
        self.writes: set[str] = set()
        self.graph_writes: set[str] = set()   # writes sourced from coupled graph
        self.reads: set[str] = set()
        self.lock_hit = False
        self.single_op_violator_of: set[str] = set()  # symbols it mutates-with-omit
        self.file = ""
        self.line = None
        self.role = ""


# boundary-mover name signal: a fn whose semantics can push a coupled cell to a
# boundary another op's precondition assumed unchanged (mint/burn zero-supply,
# first-deposit, redeem-to-empty, key-rotation mid-round). A pair involving one is
# a genuine sequential-boundary candidate (static-differential), not merely two
# co-writers (needs_source).
_BOUNDARY_MOVER = re.compile(
    r"mint|burn|deposit|redeem|withdraw|swap|rotate|sign|slash|liquidat|"
    r"sweep|bridge|migrate|reconcile|rebalance|settle",
    re.IGNORECASE)


def _build_op_index(ws: Path) -> tuple[dict, dict, set]:
    """Return (ops, guarded_readers_by_symbol, graph_cells).
    graph_cells = the set of value-cell tokens that appear in the coupled-state
    graph (the ONLY nodes a composition op-pair may share)."""
    ops: dict[str, OpProfile] = {}
    guarded_readers: dict[str, set] = {}
    graph_cells: set[str] = set()

    def _op(n):
        n = _short(n)
        if n and n not in ops:
            ops[n] = OpProfile(n)
        return ops.get(n)

    # (a) coupled edges: writers_a write cell_a; writers_b write cell_b; violators
    #     mutate a subset and OMIT a member (single-op violator of that coupling).
    p = ws / ".auditooor" / "state_coupling_edges.jsonl"
    if p.is_file():
        for line in p.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                edge = json.loads(line)
            except Exception:
                continue
            ca, cb = _sym(str(edge.get("cell_a") or "")), _sym(str(edge.get("cell_b") or ""))
            for c in (ca, cb):
                if c:
                    graph_cells.add(c)
            for fn in (edge.get("writers_a") or []):
                o = _op(fn)
                if o and ca:
                    o.writes.add(ca)
                    o.graph_writes.add(ca)
            for fn in (edge.get("writers_b") or []):
                o = _op(fn)
                if o and cb:
                    o.writes.add(cb)
                    o.graph_writes.add(cb)
            for v in (edge.get("violators") or []):
                o = _op(v.get("fn"))
                if not o:
                    continue
                if v.get("file"):
                    o.file, o.line = str(v["file"]), v.get("line")
                for m in (v.get("mutates") or []):
                    o.writes.add(_sym(str(m)))
                    o.graph_writes.add(_sym(str(m)))
                # an OMIT means this op leaves a coupled member stale in isolation
                # -> it is a SINGLE-OP violator of that coupling (already the
                # coupled-state class; NOT composition-novel).
                for m in (v.get("omits") or []):
                    o.single_op_violator_of.add(_sym(str(m)))
            ev = edge.get("evidence") or {}
            for gr in (ev.get("guarded_readers") or []):
                for s in (ca, cb):
                    if s:
                        guarded_readers.setdefault(s, set()).add(_short(str(gr)))

    # (b) value_moving_functions: ledger_write_evidence fields = symbols the fn
    #     writes; the fn body/name carries lock evidence + read dependency.
    vp = ws / ".auditooor" / "value_moving_functions.json"
    if vp.is_file():
        try:
            vd = json.loads(vp.read_text(errors="replace"))
        except Exception:
            vd = {}
        for f in (vd.get("functions") or []):
            o = _op(f.get("function"))
            if not o:
                continue
            if f.get("file"):
                o.file = o.file or str(f.get("file"))
            o.line = o.line or f.get("line")
            for lf in (f.get("ledger_write_evidence") or []):
                o.writes.add(_sym(str(lf)))
            ev = " ".join(str(x) for x in (f.get("transfer_evidence") or []))
            blob = ev + " " + str(f.get("function") or "")
            if _LOCK_TOKEN.search(blob):
                o.lock_hit = True
            # read-dependency: a value-mover that READS a balance/ratio depends on
            # those symbols as a precondition (division/comparison feeders).
            for rd in (f.get("read_evidence") or f.get("reads") or []):
                o.reads.add(_sym(str(rd)))
    return ops, guarded_readers, graph_cells


# ---------------------------------------------------------------------------
# The composition query
# ---------------------------------------------------------------------------
def _single_op_safe(op: OpProfile, inv: Invariant) -> bool:
    """op preserves I in ISOLATION iff it is NOT a coupled-state single-op
    violator of any member of I (it does not mutate a member while omitting a
    coupled sibling of I in the same call)."""
    return not (op.single_op_violator_of & inv.coupled_members)


def _touches(op: OpProfile, inv: Invariant) -> set:
    return (op.writes | op.reads) & inv.symbols


def _op_lang(op: OpProfile) -> str:
    """VM/chain family of an op, from its source file extension. A composition
    sequence op_a;op_b only executes in ONE synchronous execution context, so two
    ops in different families (a Cosmos-Go keeper method and an EVM Solidity
    contract method) can NEVER form a real op_a;op_b sequence - any 'shared state
    node' matched only by a lowercased symbol name (e.g. Cosmos vault.TotalShares
    vs an EVM totalSupply) is a cross-language false coupling, not a real coupled
    cell. Root-caused NUVA 2026-07-14 (18 SwapIn x _doDeposit/triggerRedeem
    false-red composition obligations)."""
    f = (getattr(op, "file", "") or "").lower()
    if f.endswith(".go"):
        return "go"
    if f.endswith(".sol") or f.endswith(".vy") or f.endswith(".yul"):
        return "evm"
    if f.endswith(".rs"):
        return "rust"
    return ""


def analyse(ws: Path, src_root: Path | None = None) -> dict:
    invariants = _load_pisvs_invariants(ws) + _load_coupled_invariants(ws)
    ops, guarded_readers, graph_cells = _build_op_index(ws)

    census = {
        "invariants": len(invariants),
        "ops_indexed": len(ops),
        "graph_cells": len(graph_cells),
        "candidate_pairs": 0,
        "cross_lang_pairs_skipped": 0,
        "single_op_safe_pairs": 0,
        "composition_violating": 0,
        "survivors": 0,
    }

    survivors: list[dict] = []
    obligations: list[dict] = []

    for inv in invariants:
        # ANTI-EXPLOSION guard-rail: a composition op-pair may share ONLY a value
        # CELL that appears in the OWNED coupled-state graph AND is a symbol of I.
        # This bounds enumeration to the coupled graph (never all-pairs over a
        # generic struct handle / config field), per the spec's combinatorial
        # guard-rail. Both ops must be GRAPH WRITERS of that cell.
        inv_graph_nodes = inv.symbols & graph_cells
        if not inv_graph_nodes:
            continue
        related = [o for o in ops.values() if (o.graph_writes & inv_graph_nodes)]
        for a in related:
            for b in related:
                if a.name == b.name:
                    continue
                # CROSS-VM guard: op_a;op_b can only be a real sequence when both
                # ops run in the SAME synchronous execution context. A Cosmos-Go
                # keeper method and an EVM Solidity method never do, so a shared
                # node matched only by symbol name across the language boundary is
                # a false coupling (root-caused NUVA 2026-07-14). Skip when both
                # languages are known and differ; keep unknown-language pairs
                # (conservative - never suppress a same-family or unclassified pair).
                la, lb = _op_lang(a), _op_lang(b)
                if la and lb and la != lb:
                    census["cross_lang_pairs_skipped"] = \
                        census.get("cross_lang_pairs_skipped", 0) + 1
                    continue
                # op_a writes a cell that op_b also touches (writes/reads): the
                # shared node op_b's precondition assumed unchanged.
                a_writes = a.graph_writes & inv_graph_nodes
                b_touch = (b.graph_writes | b.reads) & inv_graph_nodes
                shared_node = a_writes & b_touch
                if not shared_node:
                    continue
                census["candidate_pairs"] += 1

                a_safe = _single_op_safe(a, inv)
                b_safe = _single_op_safe(b, inv)
                if not (a_safe and b_safe):
                    # at least one op is a single-op violator of I -> that is the
                    # already-covered coupled-state class, NOT composition-novel.
                    continue
                census["single_op_safe_pairs"] += 1

                # sequential-effect signal (HONEST, static). Without a symbolic
                # executor we CANNOT prove a numeric boundary crossing, so:
                #   static-differential = op_b READS the shared node (genuine
                #     read->use dependency) OR one op is a BOUNDARY-MOVER (its
                #     semantics can push the cell to a boundary the other op's
                #     precondition assumed unchanged - mint/burn/redeem/rotate).
                #   needs_source = only a write/write ordering can be established.
                b_reads_shared = bool(b.reads & shared_node)
                boundary = bool(_BOUNDARY_MOVER.search(a.name) or
                                _BOUNDARY_MOVER.search(b.name))
                if b_reads_shared or boundary:
                    effect_conf = "static-differential"
                else:
                    effect_conf = "needs_source"
                census["composition_violating"] += 1

                # DOMINATOR reachability-negative: a shared lock over BOTH ops, or
                # a post-composition assertion (guarded_reader over the shared
                # node) that covers the pair, KILLS the survivor.
                dominators = []
                if a.lock_hit and b.lock_hit:
                    dominators.append("shared-lock(both-ops)")
                grs = set()
                for s in shared_node:
                    grs |= guarded_readers.get(s, set())
                if grs & {a.name, b.name}:
                    dominators.append("post-composition-assertion(guarded-reader)")
                if dominators:
                    continue
                census["survivors"] += 1

                sid = "cns-" + hashlib.sha1(
                    f"{inv.iid}|{a.name}|{b.name}|{sorted(shared_node)}".encode()
                ).hexdigest()[:12]
                novelty = "COMPOSITION-NOVEL" if (inv.novelty in
                          ("RESIDUAL", "NOVEL")) else "COMPOSITION"
                row = {
                    "schema": SCHEMA,
                    "survivor_id": sid,
                    "invariant_id": inv.iid,
                    "invariant_form": inv.form,
                    "invariant_text": inv.text[:400],
                    "invariant_origin": inv.origin,
                    "op_a": a.name,
                    "op_b": b.name,
                    "shared_state_node": sorted(shared_node),
                    "invariant_symbols": sorted(inv.symbols),
                    "single_op_safe": {"op_a": a_safe, "op_b": b_safe},
                    "effect_confidence": effect_conf,
                    "dominated_by": [],
                    "novelty": novelty,
                    "attack_class": "novel-composition-violation",
                    "hypothesis": (
                        f"I({a.name})=ok AND I({b.name})=ok but the sequential "
                        f"effect {a.name};{b.name} can violate '{inv.form}' over "
                        f"shared node {sorted(shared_node)}: {a.name} moves the node "
                        f"while {b.name} assumes its pre-{a.name} value; no shared "
                        f"lock / post-composition assertion dominates the pair."),
                    "search_question": (
                        f"Find a reachable interleaving where {a.name} moves "
                        f"{sorted(shared_node)} between {b.name}'s read and use, "
                        f"violating {inv.form}. CONFIRMED requires an executed PoC."),
                    "source_refs": [x for x in
                                    [_ref(inv.file, inv.line),
                                     _ref(a.file, a.line), _ref(b.file, b.line)]
                                    if x],
                    "search_status": "needs-search",
                    "proof_status": "open",
                    "verdict": novelty,
                }
                survivors.append(row)
                obligations.append(row)

    # ---- substrate status (honest) ----
    # The substrate dependency is EXPLICIT and keyed to PRODUCER-FILE PRESENCE
    # (not to a parsed count): CNS owns NO substrate of its own - it REUSES the
    # ledgers written by PISVS + the coupled-state graph. If NONE of those
    # producer ledgers exist on disk, the producers never ran and CNS must
    # FAIL-LOUD (substrate_vacuous), never fabricate survivors. A present-but-
    # empty producer ledger is an honest cited-empty, not vacuous.
    missing = _missing_producers(ws)
    if missing:
        substrate = "substrate_vacuous"
        substrate_reason = (
            "substrate dependency UNMET: the invariant producers did not run - "
            "absent producer ledger(s): " + ", ".join(missing) + ". CNS owns no "
            "substrate of its own; run PISVS + coupled-state-completeness-graph "
            "first (or pass --autorun-producers), e.g.:\n"
            f"    protocol-invariant-synth-violation-search.py {ws}\n"
            f"    coupled-state-completeness-graph.py --workspace {ws}\n"
            f"    state-coupling-graph.py --workspace {ws} --emit\n"
            "FAIL-LOUD, not a pass (rc=2 under --fail-closed).")
    elif not survivors:
        substrate = "cited-empty"
        substrate_reason = (
            f"analysed {census['invariants']} invariants over {census['ops_indexed']} "
            f"indexed ops; {census['candidate_pairs']} candidate pairs, "
            f"{census['single_op_safe_pairs']} both-single-op-safe, "
            f"{census['composition_violating']} composition-violating, 0 survivors "
            f"(every composition-violating pair was dominated by a shared lock / "
            f"post-composition assertion, or no pair shared a written->read node).")
    else:
        substrate = "survivors"
        substrate_reason = (
            f"{census['survivors']} survivor op-pairs over "
            f"{census['invariants']} derived invariants.")

    return {
        "ok": True,
        "schema": SCHEMA,
        "workspace": str(ws),
        "census": census,
        "substrate_status": substrate,
        "substrate_reason": substrate_reason,
        "survivors": survivors,
        "obligations": obligations,
        "kept": [s["survivor_id"] for s in survivors],
        "note": ("advisory; every survivor proof_status=open / search_status="
                 "needs-search. effect_confidence=needs_source means the sequential "
                 "effect could not be confirmed statically. A CONFIRMED composition "
                 "bug REQUIRES a downstream executed PoC (never emitted here)."),
    }


def emit(ws: Path, res: dict) -> Path:
    out = ws / ".auditooor" / "composition_novelty"
    out.mkdir(parents=True, exist_ok=True)
    (out / "composition_survivors.jsonl").write_text(
        "".join(json.dumps(s) + "\n" for s in res["survivors"]))
    (out / "composition_novelty_obligations.jsonl").write_text(
        "".join(json.dumps(o) + "\n" for o in res["obligations"]))
    manifest = {k: res[k] for k in
                ("schema", "workspace", "census", "substrate_status",
                 "substrate_reason", "kept", "note")}
    (out / "composition_novelty_manifest.json").write_text(
        json.dumps(manifest, indent=1))
    # root ledger the logic-obligation-resolution gate + exploit-queue key on
    aud = ws / ".auditooor"
    aud.mkdir(parents=True, exist_ok=True)
    root_lines = [json.dumps(o) + "\n" for o in res["obligations"]]
    # Capability-vacuity-telltale: composition search RAN over derived invariants +
    # op-writers (substrate_status == "cited-empty") and produced 0 survivors. PERSIST
    # an explicit cited-empty examined-record so the reasoner-firing gate scores this
    # FIRED_CLEAN (ran, examined, recorded 0) not silently VACUOUS. substrate_vacuous
    # (no invariants/edges) is NOT greened - only a real cited-empty run.
    if not res["obligations"] and res.get("substrate_status") == "cited-empty":
        cen = res.get("census", {})
        root_lines.append(json.dumps({
            "schema": SCHEMA,
            "note": ("cited-empty: composition-novelty search ran over derived "
                     "invariants + op-writers, 0 composition survivors"),
            "survivors": [],
            "report": {"reasoner": "composition-novelty-search",
                       "substrate_status": res.get("substrate_status"),
                       "totals": {"examined": int(cen.get("invariants", 0) or 0),
                                  "candidate_pairs": int(cen.get("pairs", 0) or 0)}},
        }) + "\n")
    (aud / "composition_novelty_obligations.jsonl").write_text("".join(root_lines))
    return out


def _main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="CNS - novel 0-days from op-pair COMPOSITION over derived "
                    "invariants (class-agnostic).")
    ap.add_argument("--workspace", "-w", required=True)
    ap.add_argument("--src-root", default=None,
                    help="source root override (default: <workspace>/src or ws).")
    ap.add_argument("--emit", action="store_true",
                    help="write the obligation ledgers under .auditooor/.")
    ap.add_argument("--json", action="store_true",
                    help="print the full result as JSON.")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit 2 when substrate_status == substrate_vacuous.")
    ap.add_argument("--autorun-producers", action="store_true",
                    help="run PISVS + coupled-state-completeness-graph + "
                         "state-coupling-graph on <workspace> FIRST so the "
                         "substrate materializes, then run the composition query.")
    args = ap.parse_args(argv)

    ws = Path(args.workspace)
    if not ws.is_dir():
        print(f"ERROR: workspace not found: {ws}", file=sys.stderr)
        return 1
    producer_log = None
    if args.autorun_producers:
        producer_log = _autorun_producers(ws)
        for r in producer_log:
            status = "ok" if r.get("ok") else "FAIL"
            print(f"[CNS autorun] {r['producer']}: {status}"
                  + (f" ({r.get('reason') or 'rc=' + str(r.get('returncode'))})"
                     if not r.get("ok") else ""), file=sys.stderr)
    src_root = Path(args.src_root) if args.src_root else None
    res = analyse(ws, src_root)
    if producer_log is not None:
        res["autorun_producers"] = producer_log
    if args.emit:
        out = emit(ws, res)
        res["out_dir"] = str(out)

    if args.json:
        print(json.dumps(res, indent=1))
    else:
        c = res["census"]
        print(f"[CNS] {ws}")
        print(f"  invariants           : {c['invariants']}")
        print(f"  ops indexed          : {c['ops_indexed']}")
        print(f"  candidate pairs      : {c['candidate_pairs']}")
        print(f"  both single-op-safe  : {c['single_op_safe_pairs']}")
        print(f"  composition-violating: {c['composition_violating']}")
        print(f"  survivors            : {c['survivors']}")
        print(f"  substrate_status     : {res['substrate_status']}")
        print(f"  {res['substrate_reason']}")
        for s in res["survivors"][:20]:
            print(f"   - [{s['novelty']}/{s['effect_confidence']}] "
                  f"{s['op_a']} ; {s['op_b']}  breaks {s['invariant_form']} "
                  f"@ {s['shared_state_node']}")

    if args.fail_closed and res["substrate_status"] == "substrate_vacuous":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
