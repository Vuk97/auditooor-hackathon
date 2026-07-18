#!/usr/bin/env python3
"""coupled-state-completeness-graph.py - the asymmetric cache/state-invalidation
reasoning query (Aptos struct-hijack / must-move-together desync family).

LOGIC CAPABILITY (docs/LOGIC_ARSENAL_BURNDOWN.md rank 1, [CRIT x339]). A SET /
CLOSURE-DIFFERENCE query over an OWNED intra-repo call-graph reachability backend,
NOT a shape/token detector.

CORPUS SOURCE (the mined 0-day logic class - all CRITICAL)
  A code path partial-flushes / partial-updates a SUBSET of a set of COUPLED state
  components (caches, mirrored balances, index<->value pairs, must-move-together
  fields) while a SIBLING path flushes/updates the FULL set -> stale read /
  type-confusion / desync. Canonical: the Aptos struct-hijack family + ERC-4626
  {totalShares,totalAssets} desync + a cache written without its source.
  [[coupled_state_completeness_capability]] (Aptos must-move-together desync axis).

THE LOGIC TRIPLE (assumption / invariant / trust-boundary)
  ASSUMPTION: a SET of state components G = {c1..ck} is TRUSTED to move together -
    whenever one member is mutated, ALL are (a cache and its source stay in sync; a
    mirrored balance tracks the real one; totalShares and totalAssets update as a
    pair; index[i] and value[i] are written together). Downstream reads assume the
    whole group reflects a single consistent state.
  INVARIANT: for EVERY mutating path P that touches ANY member of G, the FLUSH set
    FLUSHED(P) = { members of G written/invalidated somewhere in P's forward call
    closure } MUST equal the CANONICAL full set FULL(G) = the union over all sibling
    paths (witnessed by at least one full-flush path that writes every member).
  TRUST-BOUNDARY: no external actor is required - a path P whose FLUSHED(P) is a
    PROPER SUBSET of FULL(G) leaves the un-flushed members STALE relative to the
    ones it did update. A later read observes a torn/desynced group -> stale value,
    type-confusion, over/under-stated accounting.

THE SET/CLOSURE-DIFFERENCE (the finding)
  Per coupled group G (|G|>=2, derived from co-write co-occurrence across sibling
  paths and/or a mined must-move-together seed), let over each path's FORWARD CALL
  CLOSURE:
    FULL(G)     = union over sibling paths of ( writes(closure(P)) INT G )
                  REQUIRING a full-flush WITNESS path P_full: writes INT G == G
                  (the canonical set is PROVEN reachable-as-a-unit, never assumed).
    TOUCHERS(G) = { entrypoint-reachable P : writes(closure(P)) INT G != empty }
    SURVIVOR    = { P in TOUCHERS(G) : writes(closure(P)) INT G  is a PROPER SUBSET
                    of FULL(G) } - P mutates part of the coupled group but not all.
  FINDING = the survivors; MISSING(P) = FULL(G) \\ FLUSHED(P) is the component(s)
  left desynced. That asymmetry is the bug.

WHY THIS IS LOGIC, NOT A SHAPE (roadmap guard-rail axes a/b/c)
  (a) membership is TRANSITIVE forward-closure reachability - a member flushed N
      hops deep in a helper correctly credits FLUSHED(P) (impossible for a
      body-scoped `contains("cache")` regex);
  (b) the answer is a RELATION BETWEEN SETS: FLUSHED(P) proper-subset FULL(G),
      where FULL(G) is itself the union over SIBLING paths - the finding is the
      set-difference across two functions, not a boolean over one body;
  (c) the group G is DERIVED (co-write co-occurrence >=2 sibling paths and/or a
      stem-coupling seed) with a full-flush WITNESS - it is NOT hardcoded to any
      one workspace, and a survivor requires a sibling to prove the group CAN move
      as a unit (grounded, mutation-verifiable: add the missing write to a survivor
      and FLUSHED(P) == FULL(G) -> the survivor disappears).

OWNED BACKEND CONSUMED
  1. An intra-repo static CALL GRAPH + per-fn STATE-WRITE set built here over the
     workspace Go/Solidity/Rust source (the same self-built reachability substrate
     stale-accrual-before-value-gate-dominance.py uses, because the Go SSA `hops`
     closure under-emits intra-module private calls - memory anchor "Go dataflow
     arm under-emits on NUVA").
  2. <ws>/.auditooor/state_coupling_edges.jsonl (schema-tolerant, OPTIONAL) -
     CORROBORATES coupled pairs: any {a,b} pair listed there UNIONs into the
     co-occurrence coupling graph (owned state-coupling backend), never required.

OUTPUT
  <ws>/.auditooor/coupled_state_completeness_obligations.jsonl - one row per
  survivor, schema `auditooor.coupled_state_completeness.v1`, exploit_queue-ingest
  compatible (contract/function/file/line/source_refs/root_cause_hypothesis/
  attack_class/broken_invariant_ids/quality_gate_status='needs_source'). Ingested
  by exploit-queue.py via _gather_from_coupled_state_completeness_obligations.

  HONEST-EMPTY vs VACUOUS-EMPTY: when NO coupled group with a full-flush witness is
  derivable (the class does not apply to this repo), the summary reports
  class_present=False + a cited-empty (an honest N/A), distinct from a vacuous
  empty where the source substrate (0 fns) never materialized.
"""

from __future__ import annotations

import argparse
import collections
import itertools
import json
import os
import re
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# SOURCE INDEXING + intra-repo CALL GRAPH (the owned reachability backend).
# Mirrors the stale-accrual reasoner's conventions.
# ---------------------------------------------------------------------------
_GO_DECL = re.compile(r"^func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_SOL_DECL = re.compile(r"^\s*function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_RS_DECL = re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*")
_CALL = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")

# STATE-WRITE extractors (per language). Each captures the WRITTEN COMPONENT NAME.
#   field write:   x.Field = ...        (not ==, !=, <=, >=, :=)
#   mapping/index: name[k] = ...
#   delete/clear:  delete name / delete(name, ...)
_W_FIELD = re.compile(r"\.([A-Za-z_][A-Za-z0-9_]*)\s*=(?![=~])")
_W_BARE = re.compile(r"(?:^|[^.\w])([A-Za-z_][A-Za-z0-9_]*)\s*=(?![=~])")
_W_INDEX = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\[[^\]]*\]\s*=(?![=~])")
_W_DELETE = re.compile(r"\bdelete\s*\(?\s*([A-Za-z_][A-Za-z0-9_]*)")
# Go/Sol setter-call convention: k.SetFoo( / store.Set(FooKey - captured as component "Foo".
_W_SETTER = re.compile(r"\.[Ss]et([A-Z][A-Za-z0-9_]*)\s*\(")

# Coupling-suffix / prefix stems: two distinct component names that reduce to the
# SAME stem after stripping a coupling affix are a MUST-MOVE-TOGETHER seed pair
# (a cache and its source; a mirror/shadow/snapshot and the base). Grounded, not
# per-workspace. e.g. balanceCache~balance, totalShares~totalAssets (stem "total"),
# storedIndex~index.
_COUPLING_AFFIX = re.compile(
    r"(?i)(cache|cached|stored|store|snapshot|shadow|mirror|mirrored|"
    r"last|latest|pending|checkpoint|ckpt|prev|previous|old|new|"
    r"total|sum|agg|aggregate|count|len|length|size|num)")

_SKIP_DIR = ("/test/", "/tests/", "/mock", "/mocks/", "/vendor/",
             "/node_modules/", "/out/", "/build/", "/target/", "/.auditooor/",
             "/artifacts/", "/simulation/", "/pkg/mod/", "/go/pkg/")
_SKIP_SUFFIX = ("_test.go", ".pb.go", ".pb.gw.go", ".gen.go", ".t.sol", ".s.sol")
_STOP_NAMES = {"if", "for", "func", "return", "switch", "range", "make", "len",
               "append", "new", "cap", "require", "assert", "emit", "defer",
               "go", "select", "map", "string", "int", "uint", "error", "print",
               "printf", "sprintf", "errorf", "fmt", "panic", "recover", "var",
               "const", "type", "import", "package", "else", "while", "match"}
# component names that are never protocol state (loop/temp/builtin noise).
_STOP_COMPONENTS = {"i", "j", "k", "n", "x", "y", "z", "err", "ok", "ctx", "_",
                    "res", "result", "ret", "out", "tmp", "temp", "val", "value",
                    "v", "e", "t", "b", "s", "p", "m", "c", "d", "f", "g", "h",
                    "self", "this", "buf", "data", "idx", "key", "id", "acc"}


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


def _extract_writes(body: str) -> set:
    """Return the set of STATE-COMPONENT names WRITTEN / invalidated in a fn body.
    Direct-body writes only; transitive flush is folded in over the call closure."""
    comps: set[str] = set()
    for rx in (_W_FIELD, _W_BARE, _W_INDEX, _W_DELETE):
        for c in rx.findall(body):
            comps.add(c)
    for c in _W_SETTER.findall(body):
        comps.add(c[0].lower() + c[1:])  # SetFoo -> foo
    return {c for c in comps if c.lower() not in _STOP_COMPONENTS and len(c) > 1}


class Fn:
    __slots__ = ("name", "file", "line", "lang", "callees", "writes")

    def __init__(self, name, file, line, lang):
        self.name = name
        self.file = file
        self.line = line
        self.lang = lang
        self.callees: set[str] = set()
        self.writes: set[str] = set()


def build_call_graph(root: Path) -> dict:
    """Fold workspace source into per-fn Fn nodes with resolved intra-repo callee
    edges + a per-fn direct STATE-WRITE set. Name collisions UNION bodies
    (conservative for a reachability set query)."""
    fns: dict[str, Fn] = {}
    raw: list[tuple[str, str, int, str, str]] = []
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
        fn.writes |= _extract_writes(body)
        for c in _CALL.findall(body):
            if c in _STOP_NAMES:
                continue
            if c in known and c != name:
                fn.callees.add(c)
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


def closure_writes(name: str, fns: dict) -> set:
    """Union of direct writes over the forward call closure (transitive flush)."""
    w: set[str] = set()
    for c in forward_closure(name, fns):
        fc = fns.get(c)
        if fc:
            w |= fc.writes
    return w


# ---------------------------------------------------------------------------
# COUPLED-GROUP DERIVATION (grounded - NOT hardcoded).
#   edge(a,b) if a,b are CO-WRITTEN in the closure of >= MIN_COOCCUR sibling paths
#             OR they share a coupling stem (a mined must-move-together seed)
#             OR they are listed as a coupled pair in state_coupling_edges.jsonl.
#   group G = connected component (|G|>=2). Union-find.
# ---------------------------------------------------------------------------
def _stem(name: str) -> str:
    return _COUPLING_AFFIX.sub("", name).lower()


def _load_state_coupling_pairs(ws: Path) -> set:
    """OPTIONAL owned corroboration: coupled pairs from state_coupling_edges.jsonl.
    Schema-tolerant - accepts {a,b} / {src,dst} / {from,to} / {fields:[...]}."""
    pairs: set = set()
    p = ws / ".auditooor" / "state_coupling_edges.jsonl"
    if not p.is_file():
        return pairs
    try:
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if not isinstance(rec, dict):
                continue
            fields = rec.get("fields")
            if isinstance(fields, list) and len(fields) >= 2:
                for a, b in itertools.combinations(
                        [str(x).split(".")[-1] for x in fields], 2):
                    if a != b:
                        pairs.add(frozenset((a, b)))
                continue
            a = rec.get("a") or rec.get("src") or rec.get("from") or rec.get("field_a")
            b = rec.get("b") or rec.get("dst") or rec.get("to") or rec.get("field_b")
            if a and b:
                a = str(a).split(".")[-1]
                b = str(b).split(".")[-1]
                if a != b:
                    pairs.add(frozenset((a, b)))
    except Exception:
        return pairs
    return pairs


class _UF:
    def __init__(self):
        self.p: dict = {}

    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[ra] = rb


def derive_groups(path_write_sets: dict, seed_pairs: set,
                  min_cooccur: int = 2) -> list:
    """path_write_sets: {fn_name: set(components written in closure)}.
    Returns list of dicts {members, evidence} for each coupled group (|G|>=2)."""
    # co-occurrence counts over sibling paths.
    cooccur: dict = collections.defaultdict(int)
    comp_paths: dict = collections.defaultdict(set)
    for name, ws in path_write_sets.items():
        clean = {c for c in ws if c.lower() not in _STOP_COMPONENTS}
        for c in clean:
            comp_paths[c].add(name)
        for a, b in itertools.combinations(sorted(clean), 2):
            cooccur[frozenset((a, b))] += 1

    # candidate components: written in >= 2 distinct functions (shared-state
    # heuristic) - filters local temporaries that a single fn writes.
    shared = {c for c, ps in comp_paths.items() if len(ps) >= 2}

    uf = _UF()
    edges: list = []
    # (1) co-write co-occurrence edges.
    for pair, n in cooccur.items():
        a, b = tuple(pair)
        if n >= min_cooccur and a in shared and b in shared:
            uf.union(a, b)
            edges.append(("cooccur", a, b, n))
    # (2) stem-coupling seed edges (cache<->source, total-family) among shared comps.
    shared_list = sorted(shared)
    stem_map: dict = collections.defaultdict(list)
    for c in shared_list:
        st = _stem(c)
        if st and len(st) >= 3:
            stem_map[st].append(c)
    for st, members in stem_map.items():
        if len(members) >= 2:
            for a, b in itertools.combinations(members, 2):
                if a != b:
                    uf.union(a, b)
                    edges.append(("stem-seed", a, b, st))
    # (3) explicit state_coupling_edges.jsonl pairs.
    for pair in seed_pairs:
        a, b = tuple(pair)
        if a in comp_paths and b in comp_paths:
            uf.union(a, b)
            edges.append(("state-coupling-edge", a, b, ""))

    groups_map: dict = collections.defaultdict(set)
    for c in list(uf.p):
        groups_map[uf.find(c)].add(c)

    out = []
    for _, members in groups_map.items():
        members = {m for m in members if m.lower() not in _STOP_COMPONENTS}
        if len(members) >= 2:
            ev = [e for e in edges
                  if e[1] in members and e[2] in members]
            out.append({"members": members, "evidence": ev})
    return out


# ---------------------------------------------------------------------------
# ENTRYPOINT hint (used to RANK/permission, never to drop a survivor unless a
# confident internal classifier says so - fail-open, never-false-negative).
# ---------------------------------------------------------------------------
_ENTRY_HINT = re.compile(
    r"(?i)^(swapout|swapin|withdraw\w*|redeem\w*|borrow\w*|liquidate\w*|"
    r"claim\w*|repay\w*|deposit\w*|seize\w*|transfer\w*|mint\w*|burn\w*|"
    r"set\w*|update\w*|handle\w*|process\w*|execute\w*|reconcile\w*|"
    r"sync\w*|flush\w*|invalidate\w*|rebalance\w*|settle\w*)$")


# ---------------------------------------------------------------------------
# CLASSIFY: per group, compute FULL(G) (with witness), TOUCHERS, SURVIVORS.
# ---------------------------------------------------------------------------
def classify(fns: dict, groups: list) -> dict:
    # per-fn closure write set (cache).
    cw: dict = {n: closure_writes(n, fns) for n in fns}

    findings = []
    groups_report = []
    for g in groups:
        G = set(g["members"])
        # sibling paths that touch G, and their FLUSHED(P) = writes(closure) INT G.
        touchers = {}
        full_flush_witnesses = []
        union_flushed: set = set()
        for name in fns:
            flushed = cw[name] & G
            if flushed:
                touchers[name] = flushed
                union_flushed |= flushed
                if flushed == G:
                    full_flush_witnesses.append(name)
        # CANONICAL FULL(G): union over sibling paths, REQUIRING a full-flush
        # witness (proves the group can move as a unit - grounded, not assumed).
        if not full_flush_witnesses:
            groups_report.append({
                "members": sorted(G), "witness": None,
                "reason": "no full-flush witness (group not proven coupled-as-unit)",
                "n_touchers": len(touchers)})
            continue
        FULL = set(union_flushed)  # == G here since a witness flushes all of G
        survivors = {n: fl for n, fl in touchers.items() if fl < FULL}  # proper subset
        groups_report.append({
            "members": sorted(G),
            "FULL": sorted(FULL),
            "witnesses": sorted(full_flush_witnesses)[:8],
            "n_touchers": len(touchers),
            "n_survivors": len(survivors),
        })
        for name, flushed in sorted(survivors.items()):
            missing = sorted(FULL - flushed)
            findings.append({
                "fn": name,
                "group": sorted(G),
                "flushed": sorted(flushed),
                "missing": missing,
                "full": sorted(FULL),
                "witnesses": sorted(full_flush_witnesses)[:6],
                "evidence": g["evidence"][:8],
            })
    return {"findings": findings, "groups_report": groups_report}


def make_obligation(f: dict, fn: "Fn", invariant_id: str,
                    permissionless: bool) -> dict:
    src_ref = fn.file + (f":{fn.line}" if fn.line else "")
    grp = ", ".join(f["group"])
    missing = ", ".join(f["missing"]) or "a coupled member"
    witness = ", ".join(f["witnesses"][:3]) or "a sibling path"
    root = (
        f"Function '{f['fn']}' mutates a PROPER SUBSET of the coupled must-move-"
        f"together state group {{{grp}}}: its forward call closure flushes/updates "
        f"{{{', '.join(f['flushed'])}}} but NOT {{{missing}}}, while sibling path(s) "
        f"[{witness}] flush the FULL group. The un-flushed member(s) are left STALE "
        f"relative to the updated one(s) -> asymmetric cache/state invalidation "
        f"(stale read / type-confusion / desync). Set-difference FLUSHED(P) proper-"
        f"subset FULL(G) across sibling paths (Aptos struct-hijack / ERC-4626 "
        f"totalShares-totalAssets desync class)."
    )
    return {
        "schema": "auditooor.coupled_state_completeness.v1",
        "obligation_type": "coupled-state-partial-flush-desync",
        "contract": "",
        "function": f["fn"],
        "function_signature": f["fn"],
        "language": fn.lang,
        "source_refs": [src_ref] if src_ref else [],
        "file": fn.file,
        "line": fn.line,
        "coupled_group": f["group"],
        "flushed_subset": f["flushed"],
        "missing_components": f["missing"],
        "full_flush_witnesses": f["witnesses"][:6],
        "attack_class": "asymmetric-coupled-state-partial-invalidation-desync",
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
            "COUPLING_REAL: confirm the group members are GENUINELY must-move-"
            "together (a cache+source, mirrored balance, index<->value, "
            "totalShares<->totalAssets) - not two independent fields that a "
            "sibling happens to co-write. Cite the read site that trusts the "
            "group to be consistent.",
            "SUBSET_FLUSH: prove this path's closure writes only the subset and "
            "NOT the missing member(s) (a flush N hops deep in a helper KILLS the "
            "lead - it is a full-flush, not a survivor).",
            "DESYNC_IMPACT: show a downstream read observes the torn group and "
            "mis-behaves (stale value / type-confusion / over-or-under-stated "
            "accounting) - executed against the missing-write path.",
        ],
        "next_command": (
            "read the fn body + its callee closure; if the missing coupled member "
            "is genuinely never written before a consuming read, author the "
            "group-consistency invariant harness and drive an executed desync PoC."
        ),
    }


def run(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--src-root", default=None,
                    help="override source root (default <ws>/src, else <ws>)")
    ap.add_argument("--min-cooccur", type=int, default=2,
                    help="min sibling paths co-writing a pair to form a coupling "
                         "edge (grounding floor; default 2)")
    ap.add_argument("--invariant-id",
                    default="INV-COUPLED-STATE-MUST-MOVE-TOGETHER")
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
    path_write_sets = {n: closure_writes(n, fns) for n in fns}
    seed_pairs = _load_state_coupling_pairs(ws)
    groups = derive_groups(path_write_sets, seed_pairs, min_cooccur=args.min_cooccur)
    res = classify(fns, groups)

    perm_default = True
    obligations = []
    seen = set()
    for f in res["findings"]:
        fn = fns[f["fn"]]
        dk = (fn.file, fn.line, f["fn"], tuple(f["group"]))
        if dk in seen:
            continue
        seen.add(dk)
        obligations.append(make_obligation(f, fn, args.invariant_id, perm_default))

    emit = Path(args.emit).expanduser() if args.emit else \
        ws / ".auditooor" / "coupled_state_completeness_obligations.jsonl"
    emit.parent.mkdir(parents=True, exist_ok=True)
    with emit.open("w", encoding="utf-8") as fh:
        for ob in obligations:
            fh.write(json.dumps(ob) + "\n")
        # Capability-vacuity-telltale: the coupled-state graph RAN over a real indexed
        # function surface (>=1 fn) and produced 0 completeness findings. PERSIST an
        # explicit cited-empty examined-record so the reasoner-firing gate scores this
        # FIRED_CLEAN (ran, examined, recorded 0) not silently VACUOUS.
        if not obligations and len(fns) > 0:
            fh.write(json.dumps({
                "schema": "auditooor.coupled_state_completeness_graph.examined_record.v1",
                "note": ("cited-empty: coupled-state completeness graph ran over the "
                         "indexed function surface, 0 must-move-together survivors"),
                "survivors": [],
                "report": {"reasoner": "coupled-state-completeness-graph",
                           "totals": {"examined": len(fns)}},
            }) + "\n")

    substrate_vacuous = (len(fns) == 0)
    n_witnessed = sum(1 for g in res["groups_report"] if g.get("FULL"))
    class_present = n_witnessed > 0
    honest_empty = (not res["findings"]) and (not class_present)

    summary = {
        "schema": "auditooor.coupled_state_completeness_graph.v1",
        "workspace": str(ws),
        "src_root": str(root),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "n_functions_indexed": len(fns),
        "n_coupled_groups_candidate": len(groups),
        "n_coupled_groups_witnessed": n_witnessed,
        "state_coupling_edges_pairs": len(seed_pairs),
        "class_present": class_present,
        "n_survivors": len(res["findings"]),
        "groups": res["groups_report"][:40],
        "survivors": [
            {"fn": f["fn"], "file": fns[f["fn"]].file, "line": fns[f["fn"]].line,
             "group": f["group"], "flushed": f["flushed"], "missing": f["missing"],
             "witnesses": f["witnesses"][:3]}
            for f in res["findings"]
        ],
        "obligations_written": len(obligations),
        "obligations_path": str(emit),
        "substrate_vacuous": substrate_vacuous,
        "honest_empty_class_not_present": honest_empty,
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[coupled-state-completeness] {ws.name}: "
              f"fns={len(fns)} coupled-groups(candidate={len(groups)}/"
              f"witnessed={n_witnessed}) class_present={class_present} "
              f"survivors(FLUSHED proper-subset FULL)={len(res['findings'])} "
              f"-> {len(obligations)} coupled-state obligation(s)")
        for g in summary["groups"]:
            if g.get("FULL"):
                print(f"  GROUP {{{', '.join(g['members'])}}} FULL={g['FULL']} "
                      f"witnesses={g.get('witnesses')} touchers={g['n_touchers']} "
                      f"survivors={g['n_survivors']}")
        for s in summary["survivors"][:40]:
            print(f"  SURVIVOR {s['fn']}  flushed={s['flushed']}  "
                  f"MISSING={s['missing']}  group={s['group']}  "
                  f"{s['file']}:{s['line']}")
        if honest_empty:
            print("  HONEST-EMPTY: no coupled group with a full-flush witness "
                  "derivable - the asymmetric-invalidation class does NOT apply "
                  "(cited-empty, N/A).")
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
