#!/usr/bin/env python3
"""WSITB B1 enforcement-plane emitter, increment-1 (CONSERVATION class ONLY).

THE METHOD ("a TRUSTED ENFORCEMENT is bypassable or its private invariant is unsound"):
this tool materializes the coverage PLANE over ENFORCEMENT POINTS (not impacts). One node
per conserved-with coupled set. Each node carries the 8-question WSITB skeleton; a node
whose q8 verdict is still 'unanalyzed' AND that is severity-eligible is an un-analyzed
enforcement point the L37 gate (check_enforcement_point) fails-closed on under strict.

DEDUP - this REUSES, does not rebuild:
  - state_coupling_schema.read_edges(ws, kinds=['conserved-with'],
    min_confidence='semantic-ssa') -> the coupled edges (with per-violator fn/file/line).
  - dataflow_schema.read_paths(ws) -> storage-hop paths; grouped by source.var to get
    writers (source.fn) / readers (sink.fn) per term.
  - slither_predicates.has_guard_in_closure(fn) -> guard-in-closure per violator fn (from
    ONE Slither compile of the violator files; canonical_name -> Function index).

JOIN:
  1. read conserved-with semantic-ssa edges.
  2. union-find over pairwise (cell_a, cell_b) -> recompose each coupled conservation SET.
  3. read_paths grouped by source.var (via=='storage') -> writers/readers per member term.
  4. ONE Slither run over the violator files -> per violator fn guard_in_closure.
  5. emit one invariant_node per set.

Artifacts (all under <ws>/.auditooor/):
  wsitb_enforcement_plane.json      - the full node list.
  wsitb_enforcement_points.jsonl    - one row per severity-eligible UN-ANALYZED point.
  wsitb_enforcement_accounting.json - feeder health (so a starved feeder cannot
                                      masquerade as a clean 0).

FAIL-OPEN on any tooling absence (advisory): missing substrate -> 0 nodes + accounting
that names the missing feeder; Slither absent -> guard_in_closure=None (not a crash).
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, _HERE / filename)
    if not (spec and spec.loader):
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


# ---- substrate readers (reuse) --------------------------------------------
_SCS = _load("_wsitb_scs", "state_coupling_schema.py")
_DFS = _load("_wsitb_dfs", "dataflow_schema.py")
_WS_SCHEMA = _load("_wsitb_schema", "wsitb_schema.py")
_SCOPE = _load("_wsitb_scope", "scope_authority.py")


def _source_in_scope(ws: Path, file: str | None) -> bool:
    """Apply the workspace's authoritative source manifest when available.

    A missing manifest is a setup failure handled by the producer/gate; this
    consumer must not invent a scope decision in that case. When present,
    exact path identity is required so legacy duplicate trees cannot enter the
    enforcement plane through basename fallback.
    """
    if not file or _SCOPE is None:
        return True
    try:
        manifest = _SCOPE.load_inscope(ws)
        if not manifest.present:
            return True
        return bool(_SCOPE.is_inscope_file(ws, file, exact=True))
    except Exception:
        return True


# ---- union-find over pairwise coupled cells -------------------------------
class _UF:
    def __init__(self):
        self.parent = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def _short_fn(name: str) -> str:
    """Reduce a canonical name (Contract.fn(args)) or full-name (fn(args)) to the bare
    function identifier, so a violator fn ('erc4626Deposit') matches a Slither Function."""
    if not name:
        return ""
    n = str(name)
    if "(" in n:
        n = n.split("(", 1)[0]
    if "." in n:
        n = n.rsplit(".", 1)[1]
    return n.strip()


def _readers_writers_by_term(ws: Path):
    """Group storage-hop dataflow paths by source.var -> {writers:set, readers:set}."""
    out: dict[str, dict[str, set]] = {}
    if _DFS is None:
        return out, False
    try:
        rows = _DFS.read_paths(ws, skip_degraded=True)
    except Exception:
        return out, True  # feeder present but errored -> degraded
    for r in rows:
        hops = r.get("hops") or []
        via_storage = any(isinstance(h, dict) and h.get("via") == "storage"
                          for h in hops)
        if not via_storage:
            continue
        src = r.get("source") or {}
        sink = r.get("sink") or {}
        term = src.get("var")
        if not term:
            continue
        d = out.setdefault(term, {"writers": set(), "readers": set()})
        if src.get("fn"):
            d["writers"].add(_short_fn(src["fn"]))
        if sink.get("fn"):
            d["readers"].add(_short_fn(sink["fn"]))
    return out, False


# ---- ONE Slither run: canonical_name -> Function index --------------------
def _build_guard_index(violator_files: list[str], acct: dict) -> dict:
    """ONE Slither compile over the union of violator files -> {short_fn_name:
    has_guard_in_closure(bool)}. Fail-OPEN: on any absence/failure returns {} and marks
    the accounting slither_degraded_inscope. has_guard_in_closure -> DEGRADED (falsy)
    collapses to None (unknown)."""
    acct["slither_files_seen"] = len(violator_files)
    acct["slither_degraded_inscope"] = False
    if not violator_files:
        return {}
    sp = _load("_wsitb_sp", "slither_predicates.py")
    if sp is None or not hasattr(sp, "has_guard_in_closure"):
        acct["slither_degraded_inscope"] = True
        acct["slither_note"] = "slither_predicates.has_guard_in_closure unavailable"
        return {}
    try:
        from slither import Slither
    except Exception:
        acct["slither_degraded_inscope"] = True
        acct["slither_note"] = "slither not importable"
        return {}
    functions = []
    compiled = 0
    for f in violator_files:
        if not os.path.isfile(f):
            continue
        try:
            sl = Slither(f)
            compiled += 1
        except Exception:
            continue  # this unit doesn't compile standalone -> skip (R80)
        for c in getattr(sl, "contracts", []) or []:
            functions.extend(getattr(c, "functions", []) or [])
    acct["slither_units_compiled"] = compiled
    if compiled == 0:
        acct["slither_degraded_inscope"] = True
        acct["slither_note"] = "no violator file compiled standalone"
        return {}
    index: dict[str, object] = {}
    for fn in functions:
        index.setdefault(_short_fn(getattr(fn, "name", "") or ""), fn)
    DEGRADED = getattr(sp, "DEGRADED", object())
    out: dict[str, object] = {}
    for name, fn in index.items():
        if not name:
            continue
        try:
            g = sp.has_guard_in_closure(fn)
        except Exception:
            g = None
        out[name] = None if g is DEGRADED else bool(g)
    return out


def emit_plane(ws: Path) -> dict:
    acct: dict = {
        "workspace": str(ws),
        "invariant_class": "conservation",
        "edges_read": 0,
        "nodes_emitted": 0,
        "severity_eligible_unanalyzed": 0,
        "slice_resolution_status": "not-run",
        "slither_degraded_inscope": False,
    }
    if _SCS is None or _WS_SCHEMA is None:
        acct["slice_resolution_status"] = "0-schema-module-absent"
        # nothing to emit; still write empty artifacts so a consumer sees a real 0.
        if _WS_SCHEMA is not None:
            _WS_SCHEMA.write_plane(ws, [], acct)
        return acct

    edges = _SCS.read_edges(ws, kinds=["conserved-with"],
                            min_confidence="semantic-ssa")
    acct["edges_read"] = len(edges)
    if not edges:
        acct["slice_resolution_status"] = "0-no-conserved-edges"
        _WS_SCHEMA.write_plane(ws, [], acct)
        return acct

    # (2) union-find -> recompose coupled conservation sets.
    uf = _UF()
    edge_by_pair: list[dict] = []
    for e in edges:
        a, b = e.get("cell_a"), e.get("cell_b")
        if not a or not b:
            continue
        uf.union(a, b)
        edge_by_pair.append(e)
    comp: dict[str, list[dict]] = {}
    for e in edge_by_pair:
        root = uf.find(e.get("cell_a"))
        comp.setdefault(root, []).append(e)

    # (3) writers/readers per term from storage-hop dataflow.
    rw_by_term, df_degraded = _readers_writers_by_term(ws)
    acct["dataflow_terms_grouped"] = len(rw_by_term)
    acct["dataflow_degraded"] = df_degraded

    # value-mover set (for severity_eligible) - reuse the persisted set if present.
    value_movers: set = set()
    vm_p = ws / ".auditooor" / "value_moving_functions.json"
    try:
        if vm_p.is_file():
            vm = json.loads(vm_p.read_text(encoding="utf-8"))
            for f in vm.get("functions") or []:
                value_movers.add(_short_fn(f.get("function") or ""))
    except (OSError, ValueError):
        value_movers = set()
    acct["value_movers_loaded"] = len(value_movers)

    # (4) ONE Slither run over the union of violator files.
    violator_files: list[str] = []
    seen_files: set = set()
    for es in comp.values():
        for e in es:
            for v in e.get("violators") or []:
                f = v.get("file")
                if f and f not in seen_files:
                    seen_files.add(f)
                    violator_files.append(f)
    guard_index = _build_guard_index(violator_files, acct)

    # (5) emit one node per coupled conservation set.
    nodes: list[dict] = []
    for root, es in sorted(comp.items()):
        members: set = set()
        writers: dict[str, dict] = {}
        for e in es:
            members.add(e.get("cell_a"))
            members.add(e.get("cell_b"))
            for v in e.get("violators") or []:
                fn = _short_fn(v.get("fn") or "")
                if not fn:
                    continue
                writers[fn] = {
                    "fn": fn,
                    "file": v.get("file"),
                    "line": v.get("line"),
                    "guard_in_closure": guard_index.get(fn),
                }
            # writers_a/writers_b names (no file/line) -> ensure presence, no guard.
            for wn in (e.get("writers_a") or []) + (e.get("writers_b") or []):
                sn = _short_fn(wn)
                if sn and sn not in writers:
                    writers[sn] = {"fn": sn, "file": None, "line": None,
                                   "guard_in_closure": guard_index.get(sn)}
        members = {m for m in members if m}
        writer_names = set(writers)

        # readers/writers per term from the dataflow grouping.
        readers: set = set()
        for m in members:
            rw = rw_by_term.get(m)
            if rw:
                readers |= rw["readers"]
                writer_names |= rw["writers"]

        # owner = source-of-truth writer: the violator writer common to the most members
        # (falls back to the lexicographically-first writer). A "value-mover" owner is
        # what makes the set severity-eligible.
        # q3: any violator over the set partial-flushes (mutates a strict subset).
        q3 = any(
            (set(v.get("mutates") or []) != set(v.get("omits") or []))
            for e in es for v in (e.get("violators") or [])
        )
        # pick owner: prefer a value-mover writer, else the first violator fn, else any.
        violator_fns = [
            _short_fn(v.get("fn") or "")
            for e in es for v in (e.get("violators") or [])
            if v.get("fn")
        ]
        owner = ""
        for cand in violator_fns:
            if cand in value_movers:
                owner = cand
                break
        if not owner and violator_fns:
            owner = sorted(violator_fns)[0]
        if not owner and writer_names:
            owner = sorted(writer_names)[0]

        # q6: a reader outside the writer set observes the desync.
        q6 = bool(readers - writer_names)
        # q7: attacker-reachable - owner is a value-mover (proxy for an externally-driven
        # value-moving entrypoint) OR a non-internal (non-underscore) writer.
        q7 = bool(owner in value_movers or (owner and not owner.startswith("_")))
        severity_eligible = bool(owner in value_movers) if value_movers else bool(q3)

        term = " + ".join(sorted(members))
        node = _WS_SCHEMA.new_node(
            node_id=f"wsitb-conservation:{root}",
            term=term,
            owner=owner,
            writers=sorted(writers.values(), key=lambda w: w["fn"]),
            readers=sorted(readers),
            coupled_set=sorted(members),
            q3_partial_flush=q3,
            q6_reader_blind=q6,
            q7_attacker_reachable=q7,
            q8_verdict="unanalyzed",
            severity_eligible=severity_eligible,
            confidence="semantic-ssa",
            evidence={"root_cell": root, "edge_count": len(es)},
        )
        nodes.append(node)

    acct["nodes_emitted"] = len(nodes)
    acct["severity_eligible_unanalyzed"] = sum(
        1 for n in nodes if not n["analyzed"] and n["severity_eligible"])
    # violated_points: enforcement points with a CONFIRMED partial-flush (q3 - a writer
    # mutates a strict subset of the coupled set). This is a STRONGER signal than merely
    # un-analyzed and it MOVES with a coupled-writer drop (the B1-inc2 kill), so surfacing
    # it distinctly lets a consumer separate a confirmed desync from an un-hunted point. The
    # violation itself gates at check_state_coupling (the violation gate); this plane is the
    # coverage plane, so violated_points is reported for visibility, not to re-gate here.
    acct["violated_points"] = sum(
        1 for n in nodes if n.get("q3_partial_flush") and n["severity_eligible"])
    acct["slice_resolution_status"] = (
        "resolved" if not acct["slither_degraded_inscope"] else "slither-degraded")
    _WS_SCHEMA.write_plane(ws, nodes, acct)
    return acct


# ===========================================================================
# GENERAL enforcement-point COVERAGE PLANE (increment-2)
# ===========================================================================
# This is the GENERAL coverage plane the conservation emitter above is the
# increment-1 seed of. It does NOT re-detect: it CONSOLIDATES the already-emitted
# enforcement-point signals into ONE deduped plane of concrete points, attaches
# the 8 TRUSTED-ENFORCER QUESTIONS per point, and marks each point analyzed or
# un-analyzed via a coverage marker (agent verdict / hunt sidecar / disposition /
# mechanism_scan). It is advisory-first: a JSON report at rc 0 by default, and it
# fails closed (rc 1 / verdict incomplete) under a named legacy strict env when a
# SEVERITY-ELIGIBLE point is still un-analyzed. Explicit --strict also rejects
# starved/degraded or syntactic-only substrates and non-terminal/uncited closure.
#
# Consolidated sources (REUSED artifacts, never re-run here):
#   A2  .auditooor/cross_module_trust_seams.jsonl  (+ encode_decode_seams.jsonl)
#   A3  .auditooor/authority_blast_radius_hypotheses.jsonl
#   SCG .auditooor/state_coupling_edges.jsonl
#   ELC .auditooor/enforcement_layer_census.json
#
# Consolidation key (dedup): a normalized (target, line, kind) tuple, where kind is
# a namespaced enforcement-point role - trust-seam | authority-guard |
# coupled-state-edge | enforcement-layer. Concrete points carry file+line; the
# category-only ELC layer degrades to (unit_id, None, kind).

CONSOLIDATED_SCHEMA = "auditooor.enforcement_point_coverage_plane.v1"

# The 8 trusted-enforcer questions (the north-star). GENERAL - one checklist for
# EVERY point regardless of shape; `salient` marks the subset the point's kind
# most directly opens. q8 is the terminal verdict (the analyzed bijection lives on
# q8_verdict, mirroring wsitb_schema).
TRUSTED_ENFORCER_QUESTIONS = (
    ("q1_delegated_property", "delegated-property",
     "What safety property does the trusting site delegate to this enforcer?"),
    ("q2_private_invariant", "private-invariant",
     "What private invariant must the enforcer hold for that delegation to be sound?"),
    ("q3_partial_update_coupled_set",
     "attacker-drivable-mutation-partial-updates-a-coupled-set",
     "Can an attacker-drivable mutation update a strict subset of a must-move-together set?"),
    ("q4_recycled_identity_stale_ref", "recycled-identity-stale-ref",
     "Can a recycled identity or a stale reference be replayed past its validity?"),
    ("q5_type_erased_silent_cast", "type-erased-silent-cast",
     "Can a type-erased or silently-cast value slip past the enforcer (decode/serialization)?"),
    ("q6_upstream_blind_to_lower_layer", "upstream-blind-to-lower-layer",
     "Does an upstream reader trust this layer while blind to a lower-layer desync?"),
    ("q7_attacker_reachability", "attacker-reachability",
     "Is the point reachable on an attacker-driven path (not purely privileged)?"),
    ("q8_invariant_soundness", "invariant-soundness",
     "Terminal verdict: is the enforcement bypassable or its private invariant unsound?"),
)

# Q8 terminal verdicts: the wsitb set + 'covered' (a hunt/disposition/mechanism_scan
# examined the point but did not assign a safety verdict - it is NOT un-hunted, but
# the terminal safe/bypassable claim still needs an agent verdict). A node is
# ANALYZED iff q8_verdict != 'unanalyzed' (bijection).
CONSOLIDATED_Q8 = {
    "unanalyzed", "safe", "bypassable", "invariant-unsound", "not-applicable",
    "covered",
}

_TERMINAL_Q8 = {"safe", "bypassable", "invariant-unsound", "not-applicable"}
_TERMINAL_EMPTY_STATUSES = {"clean", "cited-empty", "not-applicable", "n/a", "na"}
_EVIDENCE_KEYS = (
    "source_refs", "source_cites", "citations", "evidence", "grounding",
    "rationale", "note", "proof", "artifact", "evidence_refs",
)

# which of the 8 questions each kind most directly opens (all 8 are attached).
_KIND_OPEN_QS = {
    "trust-seam": ["q1_delegated_property", "q2_private_invariant",
                   "q5_type_erased_silent_cast", "q6_upstream_blind_to_lower_layer",
                   "q8_invariant_soundness"],
    "authority-guard": ["q1_delegated_property", "q2_private_invariant",
                        "q7_attacker_reachability", "q8_invariant_soundness"],
    "coupled-state-edge": ["q1_delegated_property", "q2_private_invariant",
                           "q3_partial_update_coupled_set",
                           "q6_upstream_blind_to_lower_layer",
                           "q8_invariant_soundness"],
    "enforcement-layer": ["q1_delegated_property", "q2_private_invariant",
                          "q7_attacker_reachability", "q8_invariant_soundness"],
}


def _read_jsonl(p: Path) -> list[dict]:
    if not p.is_file():
        return []
    out: list[dict] = []
    try:
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if isinstance(rec, dict):
                out.append(rec)
    except OSError:
        return []
    return out


def _non_placeholder(value) -> bool:
    if isinstance(value, str):
        return value.strip().lower() not in {
            "", "n/a", "na", "none", "null", "unknown", "tbd", "todo", "?",
        }
    return value not in (None, False, [], {})


def _has_evidence(record: dict) -> bool:
    """A typed terminal result must carry a citable proof, not just a verdict."""
    if not isinstance(record, dict):
        return False
    for key in _EVIDENCE_KEYS:
        value = record.get(key)
        if isinstance(value, (list, tuple)):
            if any(_non_placeholder(item) for item in value):
                return True
        elif isinstance(value, dict):
            if _has_evidence(value):
                return True
        elif _non_placeholder(value):
            return True
    return False


def _typed_empty_closure(ws: Path) -> tuple[str | None, str | None]:
    """Return a typed cited-empty/N/A closure for a genuinely empty plane."""
    aud = ws / ".auditooor"
    for path in (
        aud / "enforcement_point_terminal.json",
        aud / "enforcement_point_coverage_accounting.json",
    ):
        if not path.is_file():
            continue
        try:
            rec = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(rec, dict):
            continue
        status = str(
            rec.get("terminal_status") or rec.get("substrate_status") or
            rec.get("assessment_status") or rec.get("status") or
            rec.get("verdict") or ""
        ).strip().lower()
        if status in _TERMINAL_EMPTY_STATUSES and _has_evidence(rec):
            return status, str(path)
    return None, None


def _semantic_substrate_issues(ws: Path, nodes: list[dict], acct: dict,
                               terminal_status: str | None = None) -> list[str]:
    """Reject absent, degraded, or syntactic-only producer input in explicit strict mode."""
    issues: list[str] = []
    source_files = {
        "cross_module_trust_seam": ws / ".auditooor" / "cross_module_trust_seams.jsonl",
        "encode_decode_seam": ws / ".auditooor" / "encode_decode_seams.jsonl",
        "freshness_toctou_seam": ws / ".auditooor" / "freshness_toctou_seams.jsonl",
        "authority_blast_radius": ws / ".auditooor" / "authority_blast_radius_hypotheses.jsonl",
        "state_coupling_graph": ws / ".auditooor" / "state_coupling_edges.jsonl",
        "enforcement_layer_census": ws / ".auditooor" / "enforcement_layer_census.json",
    }
    present = [p for p in source_files.values() if p.is_file()]
    semantic_rows = 0
    degraded = bool(acct.get("dataflow_degraded") or acct.get("degraded"))
    for path in present:
        if path.suffix == ".jsonl":
            rows = _read_jsonl(path)
            for row in rows:
                if row.get("degraded") or str(row.get("status") or "").lower() in {
                    "degraded", "failed", "error", "blocked", "timeout",
                }:
                    degraded = True
                if row.get("confidence") == "semantic-ssa" and not row.get("degraded"):
                    semantic_rows += 1
        else:
            try:
                doc = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                degraded = True
                continue
            if isinstance(doc, dict) and (doc.get("degraded") or
                                           str(doc.get("status") or "").lower()
                                           in {"degraded", "failed", "error", "blocked"}):
                degraded = True

    receipts = [
        ws / ".auditooor" / "language_backend_receipts.jsonl",
        ws / ".auditooor" / "language_backend_receipts" / "dataflow.jsonl",
    ]
    for path in receipts:
        for row in _read_jsonl(path):
            if row.get("degraded") or str(row.get("status") or "").lower() in {
                "degraded", "failed", "error", "blocked", "timeout",
            }:
                degraded = True
            if row.get("confidence") == "semantic-ssa" and row.get("status") == "pass":
                semantic_rows += 1

    if degraded:
        issues.append("semantic substrate is degraded")
    if not present:
        status = terminal_status or _typed_empty_closure(ws)[0]
        if not status:
            issues.append("semantic substrate missing: no source artifacts or cited empty/N/A closure")
    elif semantic_rows == 0:
        issues.append("semantic substrate missing: inputs are syntactic-only")
    if acct.get("substrate_starved") and not (terminal_status or _typed_empty_closure(ws)[0]):
        issues.append("semantic substrate is starved")
    if not nodes and present and semantic_rows == 0:
        issues.append("no semantic rows established an applicable enforcement surface")
    if not nodes and not terminal_status:
        issues.append("semantic terminal closure is untyped or uncited")
    return issues


def _terminal_verdict_has_evidence(node: dict) -> bool:
    evidence = node.get("evidence") or {}
    return bool(
        _has_evidence(evidence.get("terminal_verdict") or {}) or
        _has_evidence(evidence.get("terminal_evidence") or {})
    )


def _split_file_line(fl) -> tuple:
    """Split A3's 'short:ln' (or 'file:ln') file_line into (file, int line|None)."""
    if not fl or not isinstance(fl, str):
        return (None, None)
    if ":" not in fl:
        return (fl or None, None)
    head, _sep, tail = fl.rpartition(":")
    try:
        return (head or None, int(tail))
    except ValueError:
        return (fl, None)


def _norm_file(f) -> str | None:
    if not f:
        return None
    return str(f).strip() or None


def _questions_block(kind: str) -> dict:
    open_qs = set(_KIND_OPEN_QS.get(kind, [q[0] for q in TRUSTED_ENFORCER_QUESTIONS]))
    return {
        qid: {"question": prompt, "axis": axis,
              "salient": qid in open_qs, "answer": None}
        for (qid, axis, prompt) in TRUSTED_ENFORCER_QUESTIONS
    }


def _mk_point(kind, *, target, line, file, fn, term, delegated, private_inv,
              severity_eligible, layer, source_signal, evidence=None) -> dict:
    line_key = "-" if line is None else str(line)
    pid = f"{kind}|{target}|{line_key}"
    return {
        "schema": CONSOLIDATED_SCHEMA,
        "point_id": pid,
        "kind": kind,
        "enforcement_layer": layer,
        "consolidation_key": [target, line, kind],
        "file": file,
        "line": line,
        "fn": fn,
        "term": term,
        "owner": fn,  # surface-compat with check_enforcement_point renderers
        "delegated_property": delegated,
        "private_invariant": private_inv,
        "questions": _questions_block(kind),
        "open_questions": list(_KIND_OPEN_QS.get(kind, [])),
        "q8_verdict": "unanalyzed",
        "analyzed": False,
        "analyzed_by": None,
        "severity_eligible": bool(severity_eligible),
        "confidence": "consolidated",
        "source_signals": [source_signal],
        "evidence": evidence or {},
        "advisory": True,
    }


def _consolidate_a2(ws: Path) -> list[dict]:
    """A2 cross-module trust seams (+ A5 encode/decode + A17 freshness TOCTOU) ->
    trust-seam points. A17 rows land here via the SHARED ``unguarded_consumer_sink``
    key so a value validated-fresh-at-T1 / consumed-stale-at-T2 becomes a
    severity-eligible enforcement point (fail-closed under the dedicated
    enforcement-point env, NOT a raw L37 gate)."""
    pts: list[dict] = []
    for rel, sink_key in (("cross_module_trust_seams.jsonl", "unguarded_consumer_sink"),
                          ("encode_decode_seams.jsonl", "decoder_consumer"),
                          ("freshness_toctou_seams.jsonl", "unguarded_consumer_sink")):
        for row in _read_jsonl(ws / ".auditooor" / rel):
            sink = row.get(sink_key) or {}
            file = _norm_file(sink.get("file"))
            if file and not _source_in_scope(ws, file):
                continue
            line = sink.get("line")
            fn = sink.get("fn")
            var = (row.get("state_var") or row.get("codec_stem")
                   or row.get("freshness_quantity") or "delegated-state")
            target = file or (row.get("seam_id") or "seam")
            pts.append(_mk_point(
                "trust-seam", target=target, line=line, file=file, fn=fn,
                term=f"trust-seam[{var}] -> {fn or '?'}",
                delegated=(f"consumer sink {fn or '?'} trusts that a guarded producer "
                           f"validated '{var}' upstream"),
                private_inv=(f"the consumer must re-check '{var}' at point of use; a "
                             f"bypass entrypoint must not reach it un-re-validated"),
                severity_eligible=True, layer="cross-module-trust",
                source_signal={"signal": "cross-module-trust-seam",
                               "seam_id": row.get("seam_id"), "state_var": var},
                evidence={"trust_edge": row.get("trust_edge"),
                          "confidence": row.get("confidence")}))
    return pts


def _consolidate_a3(ws: Path) -> list[dict]:
    """A3 authority-blast-radius roles -> authority-guard points (one per sink fn)."""
    pts: list[dict] = []
    for row in _read_jsonl(ws / ".auditooor" / "authority_blast_radius_hypotheses.jsonl"):
        role = row.get("role") or "?"
        flag = row.get("flag_kind") or "authority"
        for s in (row.get("sink_fns") or []):
            if not isinstance(s, dict):
                continue
            file, line = _split_file_line(s.get("file_line"))
            file = _norm_file(file)
            if file and not _source_in_scope(ws, file):
                continue
            fn = s.get("fn")
            contract = s.get("contract") or ""
            target = file or f"{contract}.{fn}"
            pts.append(_mk_point(
                "authority-guard", target=target, line=line, file=file, fn=fn,
                term=f"authority[{role}] -> {contract}.{fn or '?'} ({flag})",
                delegated=(f"callers of {contract}.{fn or '?'} delegate authorization "
                           f"to role '{role}'"),
                private_inv=(f"role '{role}' must guard a single impact class and never "
                             f"be grantable by a strictly lower-privilege role"),
                severity_eligible=True, layer="access-control",
                source_signal={"signal": "authority-blast-radius", "role": role,
                               "flag_kind": flag,
                               "guard_confirmed": s.get("guard_confirmed")},
                evidence={"impacts": s.get("impacts"),
                          "distinct_impact_classes": row.get("distinct_impact_classes")}))
    return pts


def _consolidate_scg(ws: Path) -> list[dict]:
    """SCG coupled-state edges -> coupled-state-edge points (one per violator)."""
    pts: list[dict] = []
    for edge in _read_jsonl(ws / ".auditooor" / "state_coupling_edges.jsonl"):
        # B1 is the conservation enforcement plane.  Reuse the same promotion
        # contract as state-coupling-completeness-check.py: advisory SCG arms
        # (freshness/interruption/shared-cursor/handle-freshness), syntactic
        # edges, and non-promotable rows are hunt fuel, not B1 enforcement
        # points.  Consuming them here made the downstream plane disagree with
        # its producer and turned advisory evidence into a false hard blocker.
        if edge.get("kind") != "conserved-with":
            continue
        evidence = edge.get("evidence") or {}
        # Older schema fixtures omitted evidence.promotable; semantic-SSA is
        # sufficient for those producer records. A producer that explicitly
        # marks the edge false is advisory and must stay out of B1.
        if edge.get("confidence") != "semantic-ssa" or evidence.get("promotable") is False:
            continue
        cell_a = edge.get("cell_a")
        cell_b = edge.get("cell_b")
        ekind = edge.get("kind") or "coupled"
        impact = edge.get("impact_class")
        obligation = edge.get("obligation")
        for v in (edge.get("violators") or []):
            if not isinstance(v, dict):
                continue
            file = _norm_file(v.get("file"))
            if file and not _source_in_scope(ws, file):
                continue
            line = v.get("line")
            fn = v.get("fn")
            partial = set(v.get("mutates") or []) != set(v.get("omits") or [])
            target = file or (edge.get("edge_id") or "edge")
            pts.append(_mk_point(
                "coupled-state-edge", target=target, line=line, file=file, fn=fn,
                term=f"coupled[{cell_a}+{cell_b}] -> {fn or '?'} ({ekind})",
                delegated=(f"readers trust that {cell_a} and {cell_b} move together "
                           f"under coupling '{ekind}'"),
                private_inv=(obligation or
                             f"writer {fn or '?'} must mutate both {cell_a} and {cell_b}; "
                             f"a strict-subset write partial-flushes the set"),
                severity_eligible=bool(impact) or partial,
                layer=impact or "conservation",
                source_signal={"signal": "state-coupling-graph",
                               "edge_id": edge.get("edge_id"), "kind": ekind,
                               "confidence": edge.get("confidence")},
                evidence={"mutates": v.get("mutates"), "omits": v.get("omits"),
                          "partial_flush": partial, "impact_class": impact}))
    return pts


def _consolidate_elc(ws: Path) -> list[dict]:
    """ELC census -> one CATEGORY point per PRESENT enforcement layer (degraded key,
    no file:line). analyzed later iff the layer has >=1 mapped hunt sidecar."""
    pts: list[dict] = []
    p = ws / ".auditooor" / "enforcement_layer_census.json"
    if not p.is_file():
        return pts
    try:
        census = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return pts
    layers = (census or {}).get("layers") or {}
    for layer, d in layers.items():
        if not isinstance(d, dict) or not d.get("present"):
            continue
        sc = int(d.get("sidecar_count") or 0)
        sh = int(d.get("source_hits") or 0)
        pts.append(_mk_point(
            "enforcement-layer", target=f"enforcement-layer::{layer}", line=None,
            file=None, fn=None,
            term=f"enforcement-layer[{layer}]",
            delegated=(f"the '{layer}' enforcement layer present in source is trusted "
                       f"to have been hunted"),
            private_inv=(f"a layer present in in-scope source (>=1 cue hit) must have "
                         f">=1 mapped hunt sidecar or it is un-hunted"),
            severity_eligible=True, layer=layer,
            source_signal={"signal": "enforcement-layer-census", "layer": layer,
                           "flagged": bool(d.get("flagged"))},
            evidence={"source_hits": sh, "sidecar_count": sc,
                      "flagged": bool(d.get("flagged"))}))
    return pts


def _coverage_index(ws: Path) -> tuple:
    """Build the coverage marker sets from REUSED coverage artifacts:
      - hunt sidecars (.auditooor/hunt_findings_sidecars + hunt_findings_sidecars)
      - mechanism_scan/*.json findings
      - mechanism_dispositions.jsonl / finding_dispositions*.jsonl
    Returns (line_set{(file,line)->source}, fnfile_set{(file,fn)->source})."""
    line_src: dict[tuple, str] = {}
    fnfile_src: dict[tuple, str] = {}

    def _add(file, line, fn, source):
        file = _norm_file(file)
        if not file:
            return
        base = os.path.basename(file)
        if line is not None:
            try:
                ln = int(line)
                line_src.setdefault((file, ln), source)
                line_src.setdefault((base, ln), source)
            except (TypeError, ValueError):
                pass
        if fn:
            fnfile_src.setdefault((file, str(fn)), source)
            fnfile_src.setdefault((base, str(fn)), source)

    def _from_rec(rec, source):
        if not isinstance(rec, dict):
            return
        _add(rec.get("file"), rec.get("line"), rec.get("function") or rec.get("fn"),
             source)
        fl = rec.get("file_line")
        if isinstance(fl, str):
            f, l = _split_file_line(fl)
            _add(f, l, rec.get("function") or rec.get("fn"), source)
        # function_anchor {file, function}: the per-function hunt-sidecar schema
        # nests the source-review anchor HERE, not at top level (783/1260 nuva
        # sidecars). Accept a dict OR a JSON-stringified anchor; skip the '?'
        # placeholder. Mirrors hunt-coverage-gate.py:1507 / function-coverage-
        # completeness.py - without it a genuine per-fn hunt scores un-analyzed,
        # a serving-join false-red (near-intents 2026-06-26; nuva BridgeBurnShares
        # credited 0 of 1264 until this branch).
        anchor = rec.get("function_anchor")
        if isinstance(anchor, str):
            try:
                anchor = json.loads(anchor)
            except (TypeError, ValueError):
                anchor = None
        if isinstance(anchor, dict):
            af = str(anchor.get("file") or "").strip()
            afn = str(anchor.get("function") or anchor.get("fn") or "").strip()
            if af and af != "?":
                _add(af, anchor.get("line"),
                     (afn if afn and afn != "?" else None), source)
        # nested ``result`` carries the finding as a dict OR a stringified JSON
        # (760/1260 nuva sidecars store the disposition/anchor there); recurse so
        # its own file/fn/function_anchor credit through this same path.
        res = rec.get("result")
        if isinstance(res, str) and res.strip():
            try:
                res = json.loads(res)
            except (TypeError, ValueError):
                res = None
        if isinstance(res, dict):
            _from_rec(res, source)
        for ref in (rec.get("source_refs") or []):
            if isinstance(ref, str):
                f, l = _split_file_line(ref)
                _add(f, l, None, source)
            elif isinstance(ref, dict):
                _add(ref.get("file"), ref.get("line"),
                     ref.get("function") or ref.get("fn"), source)
        for f in (rec.get("findings") or []):
            _from_rec(f, source)

    for d in (ws / ".auditooor" / "hunt_findings_sidecars",
              ws / "hunt_findings_sidecars"):
        if d.is_dir():
            for path in sorted(d.glob("*.json")):
                try:
                    _from_rec(json.loads(path.read_text(encoding="utf-8",
                                                         errors="replace")),
                              "hunt-sidecar")
                except (OSError, ValueError):
                    continue
    msd = ws / ".auditooor" / "mechanism_scan"
    if msd.is_dir():
        for path in sorted(msd.glob("*.json")):
            try:
                _from_rec(json.loads(path.read_text(encoding="utf-8",
                                                    errors="replace")),
                          "mechanism_scan")
            except (OSError, ValueError):
                continue
    for rel in ("mechanism_dispositions.jsonl", "finding_dispositions.jsonl"):
        for rec in _read_jsonl(ws / ".auditooor" / rel):
            _from_rec(rec, "disposition")
    return line_src, fnfile_src


def _verdicts_path(ws: Path) -> Path:
    return ws / ".auditooor" / "enforcement_point_verdicts.jsonl"


def _load_verdicts(ws: Path) -> dict:
    """point_id (or consolidation-key string) -> terminal q8 verdict, from the ingest
    file. Mirrors coupled-state-completeness _check's gaps-file lookup."""
    vmap: dict[str, dict] = {}
    for rec in _read_jsonl(_verdicts_path(ws)):
        v = (rec.get("q8_verdict") or rec.get("probe_verdict")
             or rec.get("verdict") or "")
        v = str(v).strip()
        if v not in CONSOLIDATED_Q8 or v == "unanalyzed":
            continue
        key = rec.get("point_id")
        if not key:
            ck = rec.get("consolidation_key")
            if isinstance(ck, list) and len(ck) == 3:
                line_key = "-" if ck[1] is None else str(ck[1])
                key = f"{ck[2]}|{ck[0]}|{line_key}"
        if key:
            # Preserve the citation fields through ingest so explicit strict mode
            # can distinguish a terminal verdict from a hand-written q8 label.
            vmap[str(key)] = {
                "q8_verdict": v,
                "evidence": rec.get("evidence"),
                "source_refs": rec.get("source_refs"),
                "source_cites": rec.get("source_cites"),
                "rationale": rec.get("rationale"),
                "note": rec.get("note"),
                "proof": rec.get("proof"),
            }
    return vmap


def _mark_coverage(ws: Path, nodes: list[dict]) -> None:
    """Flip q8_verdict/analyzed on each node via the coverage marker, in priority
    order: (1) an ingested agent q8 verdict; (2) ELC layer sidecar_count>0;
    (3) a hunt sidecar / mechanism_scan / disposition at the point's (file,line) or
    (file,fn). Anything else stays q8='unanalyzed' (un-hunted)."""
    vmap = _load_verdicts(ws)
    line_src, fnfile_src = _coverage_index(ws)
    for n in nodes:
        pid = n.get("point_id")
        # (1) explicit agent verdict.
        if pid in vmap:
            verdict_record = vmap[pid]
            n["q8_verdict"] = verdict_record["q8_verdict"]
            if any(_non_placeholder(verdict_record.get(k)) for k in _EVIDENCE_KEYS):
                n.setdefault("evidence", {})["terminal_verdict"] = verdict_record
            n["analyzed"] = True
            n["analyzed_by"] = "agent-verdict"
            continue
        # (2) ELC layer: covered iff >=1 mapped sidecar.
        if n.get("kind") == "enforcement-layer":
            if int((n.get("evidence") or {}).get("sidecar_count") or 0) > 0:
                n["q8_verdict"] = "covered"
                n["analyzed"] = True
                n["analyzed_by"] = "layer-sidecar"
            continue
        # (3) concrete-point coverage match.
        file = n.get("file")
        line = n.get("line")
        fn = n.get("fn")
        src = None
        base = os.path.basename(file) if file else None
        if file is not None and line is not None:
            src = line_src.get((file, line)) or (line_src.get((base, line))
                                                 if base else None)
        if src is None and file is not None and fn:
            src = fnfile_src.get((file, str(fn))) or (fnfile_src.get((base, str(fn)))
                                                      if base else None)
        if src is not None:
            n["q8_verdict"] = "covered"
            n["analyzed"] = True
            n["analyzed_by"] = src


def consolidate_plane(ws: Path) -> tuple:
    """Consolidate the emitted enforcement-point signals into ONE deduped plane,
    attach the 8 trusted-enforcer questions, and mark each point analyzed/un-analyzed.
    Returns (nodes, accounting). Fail-OPEN per source (a missing artifact -> that
    source contributes 0 points and is recorded absent in the accounting)."""
    a2 = _consolidate_a2(ws)
    a3 = _consolidate_a3(ws)
    scg = _consolidate_scg(ws)
    elc = _consolidate_elc(ws)
    sources_present = {
        "cross-module-trust-seam": bool(a2),
        "authority-blast-radius": bool(a3),
        "state-coupling-graph": bool(scg),
        "enforcement-layer-census": (ws / ".auditooor"
                                     / "enforcement_layer_census.json").is_file(),
    }
    # dedup on consolidation key (point_id); merge provenance + OR severity.
    merged: dict[str, dict] = {}
    for n in a2 + a3 + scg + elc:
        pid = n["point_id"]
        if pid in merged:
            merged[pid]["source_signals"].extend(n["source_signals"])
            merged[pid]["severity_eligible"] = (
                merged[pid]["severity_eligible"] or n["severity_eligible"])
        else:
            merged[pid] = n
    nodes = sorted(merged.values(), key=lambda x: x["point_id"])
    _mark_coverage(ws, nodes)

    by_kind: dict[str, int] = {}
    for n in nodes:
        by_kind[n["kind"]] = by_kind.get(n["kind"], 0) + 1
    sev = [n for n in nodes if n["severity_eligible"]]
    open_pts = [n for n in sev if not n["analyzed"]]
    acct = {
        "schema": "auditooor.enforcement_point_coverage_accounting.v1",
        "workspace": str(ws),
        "sources_present": sources_present,
        "substrate_starved": not any(sources_present.values()),
        "points_total": len(nodes),
        "by_kind": by_kind,
        "severity_eligible": len(sev),
        "severity_eligible_analyzed": len(sev) - len(open_pts),
        "severity_eligible_unanalyzed": len(open_pts),
        "analyzed_by_counts": _count_analyzed_by(nodes),
        "advisory": True,
    }
    return nodes, acct


def _count_analyzed_by(nodes: list[dict]) -> dict:
    out: dict[str, int] = {}
    for n in nodes:
        k = n.get("analyzed_by") or "un-analyzed"
        out[k] = out.get(k, 0) + 1
    return out


def _consolidated_paths(ws: Path) -> tuple:
    a = ws / ".auditooor"
    return (a / "enforcement_point_coverage_plane.json",
            a / "enforcement_point_coverage_accounting.json",
            a / "enforcement_point_open.jsonl")


def write_consolidated(ws: Path, nodes: list[dict], acct: dict) -> None:
    plane_p, acct_p, open_p = _consolidated_paths(ws)
    plane_p.parent.mkdir(parents=True, exist_ok=True)
    plane_p.write_text(json.dumps(
        {"schema": CONSOLIDATED_SCHEMA, "points": nodes},
        sort_keys=True, default=str, indent=2), encoding="utf-8")
    acct_p.write_text(json.dumps(acct, sort_keys=True, default=str, indent=2),
                      encoding="utf-8")
    open_pts = [n for n in nodes if n["severity_eligible"] and not n["analyzed"]]
    open_p.write_text(
        "\n".join(json.dumps(n, sort_keys=True, default=str) for n in open_pts)
        + ("\n" if open_pts else ""), encoding="utf-8")


def ingest_verdicts(ws: Path, verdicts: Path) -> int:
    """Fold per-point terminal q8 verdicts into the verdicts file (mirrors
    coupled-state-completeness._ingest), then refresh the plane so `analyzed` flips
    through the coverage marker. Additive: existing verdicts are preserved unless a
    row re-specifies the same point_id."""
    existing = {}
    for rec in _read_jsonl(_verdicts_path(ws)):
        if rec.get("point_id"):
            existing[rec["point_id"]] = rec
    added = 0
    for rec in _read_jsonl(verdicts):
        pid = rec.get("point_id")
        if not pid:
            ck = rec.get("consolidation_key")
            if isinstance(ck, list) and len(ck) == 3:
                line_key = "-" if ck[1] is None else str(ck[1])
                pid = f"{ck[2]}|{ck[0]}|{line_key}"
        v = (rec.get("q8_verdict") or rec.get("probe_verdict")
             or rec.get("verdict") or "")
        if not pid or str(v).strip() not in CONSOLIDATED_Q8 or str(v).strip() == "unanalyzed":
            continue
        existing[pid] = {
            "point_id": pid,
            "q8_verdict": str(v).strip(),
            **{k: rec[k] for k in _EVIDENCE_KEYS if rec.get(k)},
        }
        added += 1
    _verdicts_path(ws).parent.mkdir(parents=True, exist_ok=True)
    _verdicts_path(ws).write_text(
        "\n".join(json.dumps(r, sort_keys=True) for r in existing.values())
        + ("\n" if existing else ""), encoding="utf-8")
    nodes, acct = consolidate_plane(ws)
    write_consolidated(ws, nodes, acct)
    print(f"[enforcement-point] ingested {added} verdict(s); "
          f"{acct['severity_eligible_unanalyzed']} severity-eligible point(s) "
          f"still un-analyzed")
    return 0


def _strict_env() -> bool:
    return (os.environ.get("AUDITOOOR_ENFORCEMENT_POINT_STRICT", "").strip() == "1"
            or os.environ.get("AUDITOOOR_L37_STRICT", "").strip() == "1")


def check_consolidated(ws: Path, *, strict: bool | None = None) -> int:
    """Advisory-first gate. Rebuilds the plane, then:
      - default (no strict env): WARN + JSON report, rc 0 (never blocks).
      - legacy strict env: rc 1 / verdict incomplete iff a SEVERITY-ELIGIBLE point is
        un-analyzed.
      - explicit strict=True: also requires semantic substrate health and cited terminal
        verdicts."""
    terminal_status, _terminal_path = _typed_empty_closure(ws)
    nodes, acct = consolidate_plane(ws)
    write_consolidated(ws, nodes, acct)
    open_pts = [n for n in nodes if n["severity_eligible"] and not n["analyzed"]]
    explicit_strict = strict is True
    if strict is None:
        strict = _strict_env()
    strict_failures = []
    if strict and explicit_strict:
        strict_failures.extend(_semantic_substrate_issues(ws, nodes, acct, terminal_status))
        for n in nodes:
            if not n.get("severity_eligible"):
                continue
            q8 = str(n.get("q8_verdict") or "unanalyzed").strip().lower()
            if q8 == "unanalyzed":
                strict_failures.append(
                    f"unresolved required probe: {n.get('point_id', '?')} is unanalyzed")
            elif q8 == "covered":
                strict_failures.append(
                    f"unresolved required probe: {n.get('point_id', '?')} has coverage only")
            elif q8 in _TERMINAL_Q8 and q8 == "not-applicable" \
                    and not _terminal_verdict_has_evidence(n):
                strict_failures.append(
                    f"not-applicable verdict is uncited: {n.get('point_id', '?')}")
            elif q8 in _TERMINAL_Q8 and not _terminal_verdict_has_evidence(n):
                strict_failures.append(
                    f"terminal verdict is uncited: {n.get('point_id', '?')}")
    if open_pts and strict:
        strict_failures.insert(0, f"{len(open_pts)} severity-eligible point(s) remain open")
    verdict = "complete"
    rc = 0
    if strict_failures:
        verdict = "incomplete"
        rc = 1
    report = {
        "verdict": verdict,
        "strict": strict,
        "explicit_strict": explicit_strict,
        "strict_failures": strict_failures,
        "severity_eligible_unanalyzed": len(open_pts),
        "points_total": acct["points_total"],
        "by_kind": acct["by_kind"],
        "sources_present": acct["sources_present"],
        "open_points": [{"point_id": n["point_id"], "kind": n["kind"],
                         "file": n["file"], "line": n["line"], "fn": n["fn"],
                         "term": n["term"]} for n in open_pts[:10]],
    }
    print(json.dumps({"ok": rc == 0, "report": report}, indent=2, default=str))
    if rc == 0 and not open_pts:
        print("pass-enforcement-point-coverage")
    elif rc == 0:
        print(f"WARN: {len(open_pts)} severity-eligible enforcement point(s) "
              f"un-analyzed (advisory; set AUDITOOOR_ENFORCEMENT_POINT_STRICT=1 "
              f"to fail closed)")
    else:
        print(f"NOT-DONE: {len(open_pts)} severity-eligible enforcement point(s) "
              f"un-analyzed under strict")
    return rc


def consolidate_and_report(ws: Path) -> int:
    nodes, acct = consolidate_plane(ws)
    write_consolidated(ws, nodes, acct)
    print(json.dumps({"ok": True, "accounting": acct}, indent=2, default=str))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", "--ws", dest="workspace", required=True,
                    help="workspace root (reads/writes <ws>/.auditooor/)")
    ap.add_argument("--emit-plane", action="store_true",
                    help="emit the increment-1 conservation enforcement plane "
                         "(DEFAULT when no other mode is given)")
    ap.add_argument("--consolidate", action="store_true",
                    help="GENERAL coverage plane: consolidate the emitted A2/A3/SCG/ELC "
                         "enforcement-point signals into one deduped 8-question plane")
    ap.add_argument("--ingest", type=Path, metavar="VERDICTS.jsonl",
                    help="fold per-point terminal q8 verdicts (mirrors coupled-state "
                         "ingest), then refresh the consolidated plane")
    ap.add_argument("--check", action="store_true",
                    help="gate over the consolidated plane; legacy env strictness blocks "
                         "open points, --strict also checks substrate and terminal evidence")
    ap.add_argument("--strict", action="store_true",
                    help="fail on open/coverage-only points, starved/degraded semantic input, "
                         "or uncited terminal closure")
    args = ap.parse_args(argv)
    ws = Path(args.workspace)
    if not ws.exists():
        print(f"[wsitb] workspace not found: {ws}", file=sys.stderr)
        return 2
    if args.ingest is not None:
        return ingest_verdicts(ws, args.ingest)
    if args.check:
        return check_consolidated(ws, strict=True if args.strict else None)
    if args.consolidate:
        if args.strict:
            return check_consolidated(ws, strict=True)
        return consolidate_and_report(ws)
    # DEFAULT (and explicit --emit-plane): the increment-1 conservation emit. This
    # preserves the exact behavior the registered check_enforcement_point relies on
    # (it calls main(["--workspace", ws]) and reads wsitb_enforcement_plane.json).
    acct = emit_plane(ws)
    print(json.dumps({"ok": True, "accounting": acct}, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
