#!/usr/bin/env python3
"""per-function-hacker-questions.py - emit adversarial questions per function.

r36-rebuttal: registered lane mimo-harness-build-2026-05-27.

Operator's "what would an attacker ask?" gap. Wraps invariant-auto-synth
output and the hacker-question corpus to produce a per-function adversarial
question list:

  1. Read invariants.jsonl (output of invariant-auto-synth.py)
  2. For each function record, generate questions like:
     - "How would I bypass INV-X?"
     - "What if param Y is at min/max boundary?"
     - "What if external call Z reenters before state write?"
  3. Cross-reference with the workspace's `audit/corpus_tags/hackerman_q/`
     hacker-question corpus (if present) to attach corpus-question IDs
  4. Emit JSONL ready to feed llm-fanout-dispatcher / MIMO harness

Schema: auditooor.per_fn_hacker_questions.v1

USAGE:
  python3 tools/per-function-hacker-questions.py \
    --invariants invariants.jsonl --output questions.jsonl
"""
from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

SCHEMA = "auditooor.per_fn_hacker_questions.v1"

AUDITOOOR_ROOT = Path(__file__).resolve().parent.parent

_IMPACT_RENDERER_CACHE = "unset"


def _impact_renderer():
    """Lazy-load tools/hacker_question_renderer.render_impact_questions (or None).

    Cached. Returns None when the module is unavailable so a tree without the
    renderer keeps the legacy (impact-free) corpus - byte-identical, no regression.
    """
    global _IMPACT_RENDERER_CACHE
    if _IMPACT_RENDERER_CACHE != "unset":
        return _IMPACT_RENDERER_CACHE
    fn = None
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "hacker_question_renderer",
            str(AUDITOOOR_ROOT / "tools" / "hacker_question_renderer.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
        fn = getattr(mod, "render_impact_questions", None)
    except Exception:
        fn = None
    _IMPACT_RENDERER_CACHE = fn
    return fn


def _render_impact_for_fn(fn_rec: dict, scope_text: str, max_impact: int) -> list[dict]:
    """Emit per-impact methodology questions for ONE function in the producer's
    own row shape (so the ranker + downstream consume them uniformly), carrying
    the provenance markers (`question_source: impact-methodology`, `impact_id`)
    that the impact-methodology corpus-provenance gate asserts.

    Default-on; disable with AUDITOOOR_PERFN_Q_NO_IMPACT=1. Returns [] when the
    renderer is unavailable, disabled, or attaches nothing (e.g. a view function).
    """
    import os
    if os.environ.get("AUDITOOOR_PERFN_Q_NO_IMPACT"):
        return []
    render = _impact_renderer()
    if render is None:
        return []
    fn = fn_rec.get("function", "") or ""
    file_ = fn_rec.get("file", "") or ""
    lang = fn_rec.get("language", "") or ""
    sig = fn_rec.get("signature", "") or fn_rec.get("function_signature", "") or ""
    try:
        imp_rows = render(
            function_name=fn, function_signature=sig, language=lang,
            scope_text=scope_text, file_path=file_, max_questions=max_impact,
        )
    except Exception:
        return []
    out: list[dict] = []
    for r in imp_rows or []:
        q = str(r.get("question") or "").strip()
        if not q:
            continue
        out.append({
            "schema": SCHEMA,
            "function": fn,
            "file": file_,
            "language": lang,
            "question": q,
            "question_class": "impact-methodology",
            "question_source": "impact-methodology",
            "impact_id": r.get("impact_id", ""),
            "impact_severity_hint": r.get("impact_severity_hint", ""),
            "reasoning_axis": r.get("reasoning_axis", "impact"),
            "proof_obligation": r.get("proof_obligation", ""),
            "kill_condition": r.get("kill_condition", ""),
            "rubric_row_hint": r.get("rubric_row_hint", ""),
        })
    return out


def _impact_methodology_fallback_for_unit(fn_rec: dict) -> list[dict]:
    """Emit ONE generic impact-methodology fallback question for an in-scope unit
    that ``_render_impact_for_fn`` classified as nothing (returned []).

    WHY: the in-scope supplemental pass relies on ``_render_impact_for_fn``, which
    returns [] for unclassified internal-pure leaf helpers (e.g.
    AccountingLib.splitValuatedNavOut, RoundingGuard.preferOriginalWithin1Wei,
    UD60x18Ext.max, ChainlinkAprProviderLib). Those in-scope value-movers would
    otherwise reach the hunt with ZERO questions. This minimal fallback row keeps
    every in-scope unit covered by at least one question. Keyed to the unit so the
    ranker / downstream consume it uniformly; the empty ``impact_id`` /
    ``kill_condition`` mark it as a generic fallback (not an invariant-/impact-
    derived row). ADDITIVE - callers only use this when ``_render_impact_for_fn``
    attached nothing AND the unit is in-scope (OOS / mutant units still get none).
    """
    fn = fn_rec.get("function", "") or ""
    file_ = fn_rec.get("file", "") or ""
    lang = fn_rec.get("language", "") or ""
    return [{
        "schema": SCHEMA,
        "function": fn,
        "file": file_,
        "language": lang,
        "question": (
            f"What adversary-reachable input or call ordering could make "
            f"{fn or 'this in-scope unit'} return an incorrect, rounding-biased, "
            f"or overflowing value that a downstream value-moving caller relies "
            f"on (accounting/NAV/share/price), and what concrete loss results?"
        ),
        "question_class": "impact-methodology",
        "question_source": "impact-methodology-fallback",
        "impact_id": "",
        "impact_severity_hint": "",
        "reasoning_axis": "impact",
        "proof_obligation": "",
        "kill_condition": "",
        "rubric_row_hint": "",
    }]


def _read_inscope_units(workspace: str | None) -> list[dict]:
    """Read the workspace's in-scope (file, function) units from
    ``<ws>/.auditooor/inscope_units.jsonl`` (the canonical enumerator output).

    Each row is ``{"file","function","file_line","lang",...}``. Returns [] when
    the workspace is unset, the sidecar is absent, or it is unreadable - so a tree
    without the sidecar yields zero supplemental questions (default-off, the
    invariant-derived output stays byte-identical).
    """
    if not workspace:
        return []
    p = Path(workspace) / ".auditooor" / "inscope_units.jsonl"
    if not p.is_file():
        return []
    rows: list[dict] = []
    try:
        with p.open() as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(rec, dict):
                    rows.append(rec)
    except OSError:
        return []
    return rows


def _inscope_unit_to_fn_rec(unit: dict) -> dict:
    """Project an inscope_units.jsonl row onto the function-record shape the
    impact renderer consumes (`function`, `file`, `language`).

    The enumerator uses ``lang``; the invariant/fn-record path uses ``language``.
    Normalize so ``_render_impact_for_fn`` keys uniformly. ADDITIVE - the original
    invariant-derived rows are untouched.
    """
    return {
        "function": unit.get("function", "") or "",
        "file": unit.get("file", "") or "",
        "language": unit.get("lang", "") or unit.get("language", "") or "",
        # Carry a signature through when the enumerator recorded one, so the
        # impact renderer can classify the function (value-mover vs view). Absent
        # a signature the renderer falls back to name/scope heuristics.
        "signature": unit.get("signature", "")
        or unit.get("function_signature", "") or "",
    }


def _scope_exclusion_skip(file_rel: str) -> bool:
    """Return True when ``file_rel`` is a non-production unit that must NOT seed
    hacker questions: a mutation-test artifact (``*Mutant*.sol``), a test/mock
    file, or a generated/tool artifact tree.

    WHY: the per-fn question producer emits one record set per ``--invariants``
    row; if the invariant generator absorbed the audit's OWN ``*Mutant*.sol``
    mutation artifacts (they live in-tree under contracts/modules/), those leak
    into the scoped hunt plan and the orchestrator spends real Agent budget
    hunting an intentionally-unsafe contract (observed on SSV: 4 SSVClustersMutantA
    rows reached the n40 plan and one batch hunted the deliberate unchecked-underflow
    ``withdraw``). This is the same EXCLUDE surface tools/per-function-attack-worklist.py
    already enforces; here we apply the canonical tools/lib/scope_exclusion predicate
    as a FINAL emit-time guard so it holds regardless of the upstream enumerator.

    Fail-OPEN by design: empty/"?" path, missing lib, or any error -> False (no
    filtering), so a tree without scope_exclusion stays byte-identical. Disable
    entirely with AUDITOOOR_PERFN_Q_NO_SCOPE_FILTER=1.
    """
    import os
    if os.environ.get("AUDITOOOR_PERFN_Q_NO_SCOPE_FILTER"):
        return False
    if not file_rel or file_rel == "?":
        return False
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "scope_exclusion",
            str(AUDITOOOR_ROOT / "tools" / "lib" / "scope_exclusion.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
    except Exception:
        return False
    rel = str(file_rel).strip()
    try:
        if mod.is_mutation_artifact(rel):
            return True
        if mod.is_test(rel):
            return True
        if hasattr(mod, "is_tool_artifact") and mod.is_tool_artifact(rel):
            return True
    except Exception:
        return False
    return False


# --- Bidirectional wiring 49a: flow-seeded question SOURCE ---------------------
# The data-flow slice (tools/dataflow-slice.py) emits one DefUsePath record per
# tainted-source -> value-moving-sink slice to <ws>/.auditooor/dataflow_paths.jsonl,
# with `unguarded` ALREADY closure-corrected (dataflow_schema.new_path sets
# unguarded = not(any guard_node OR any hop guarded) over the WHOLE inter-procedural
# slice). The ROOT FLAW this arm fixes (P3): per-fn questions were generated by
# SYMBOL/SHAPE, not by adversary-reachable FLOW - the coverage-theater root flaw.
# This source emits ONE targeted question anchored at the REAL sink file:line for
# every UNGUARDED reachable flow into a value-moving / storage-value sink.
#
# FLOW-FED BY DEFAULT (P3): whenever a dataflow slice is PRESENT (via --workspace
# auto-discovery or an explicit --dataflow-paths), gen_flow_seeded_questions runs
# unconditionally - there is NO env gate that would degrade it to symbol-only.
# The symbol/shape synth-template questions remain as a FALLBACK layer, never the
# sole source when a slice exists. Two SIBLING flow-fed seed sources join the
# DefUsePath arm (both default-on-when-present, byte-identical when their sidecar
# is absent):
#   - state_coupling_edges.jsonl  -> coupled-state co-write |G|>=2 violators that
#     OMIT a coupled sibling  (question_source 'coupled-seeded'), and
#   - oracle_reachability_hypotheses.jsonl -> attacker-movable oracle reads reaching
#     a value-loss sink       (question_source 'oracle-seeded').
#
# FAIL-CLOSED (P3): a PRESENT-but-EMPTY dataflow slice must NOT silently degrade to
# symbol-only. main() detects "slice file on disk but zero flow-fed seeds of ANY
# kind" and writes a loud WARNING to stderr, so a broken/empty slice producer is
# surfaced instead of quietly leaving the flow arm dark.
#
# ADDITIVE + default-off WHEN ABSENT: with no sidecar on disk, zero seeded questions
# are produced and the symbol-based output is byte-identical to before.
#
# Sink kinds that MOVE VALUE (token transfer / mint / burn / raw call) or write an
# economic storage var. Mirrors dataflow-slice.py VALUE_MOVING_CALLEES + the
# `storage-value` sink kind + the low-level call kinds (_sink_kind). A sink whose
# kind is NOT in this set (a generic read, a non-economic state write) is not a
# value-mover and is not seeded.
FLOW_VALUE_MOVER_SINK_KINDS = frozenset({
    "transfer", "transferFrom", "send", "safeTransfer", "safeTransferFrom",
    "mint", "burn", "_mint", "_burn", "delegatecall", "sendValue", "call",
    "low_level_call", "staticcall", "storage-value",
})


def _read_dataflow_paths(workspace: str | None):
    """Read non-degraded DefUsePath records from the workspace slice sidecar.

    Uses dataflow_schema.read_paths (the canonical reader) so degraded rows are
    dropped (R80) and only schema-valid records are returned. Returns [] when the
    sidecar is absent, the reader is unavailable, or the workspace is unset - so a
    no-slice workspace yields zero seeded questions (default-off, byte-identical).

    P3 sibling seed sources (read separately, wired alongside this arm in main so
    the per-fn hunt is FLOW-FED, not symbol-only): _read_state_coupling_edges
    (coupled-state co-write violators -> 'coupled-seeded') and
    _read_oracle_hypotheses (attacker-movable oracle reads -> 'oracle-seeded').
    """
    if not workspace:
        return []
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "dataflow_schema", str(AUDITOOOR_ROOT / "tools" / "dataflow_schema.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
    except Exception:
        return []
    try:
        return mod.read_paths(workspace, skip_degraded=True)
    except Exception:
        return []


def _flow_path_is_seedable(path: dict) -> bool:
    """A DefUsePath is seedable iff it is a genuine UNGUARDED reachable flow into a
    value-moving sink. Honest filter (R80):

      - degraded == False                  (advisory-empty records never seed)
      - confidence != "heuristic"          (name-substring fallback is advisory)
      - unguarded == True                  (closure-corrected: NO guard dominates
                                            the inter-procedural slice)
      - sink.kind in the value-mover set   (the sink actually moves value / writes
                                            an economic storage var)

    A role-gated sink (require(onlyOwner)/role-check dominating the path) has
    unguarded==False and is excluded - so a closure-guarded flow yields no false
    unguarded question.

    P3: the coupled-state and oracle-reachability seed sources apply their OWN
    honesty filters (_coupling_violators_omitting_sibling drops `heuristic` edges;
    _oracle_hyp_is_seedable requires a concrete read_site) - they do not route
    through this DefUsePath predicate.
    """
    if not isinstance(path, dict):
        return False
    if path.get("degraded"):
        return False
    if path.get("confidence") == "heuristic":
        return False
    if path.get("unguarded") is not True:
        return False
    sink = path.get("sink") or {}
    return str(sink.get("kind") or "") in FLOW_VALUE_MOVER_SINK_KINDS


def _suggest_attack_class(sink_kind: str, callee: str | None):
    """Map a DefUsePath sink.kind -> a CANONICAL attack class (edge 9, R38).

    Lazy-imports tools/lib/dataflow_attack_class so a tree without that module (or
    without the corpus taxonomy) simply yields no suggestion. Returns the canonical
    class string (verbatim-matched against the taxonomy) or None - NEVER an invented
    class. ADDITIVE: callers tag the suggestion provenance="dataflow_sink_kind".
    """
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "dataflow_attack_class",
            str(AUDITOOOR_ROOT / "tools" / "lib" / "dataflow_attack_class.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
    except Exception:
        return None
    try:
        return mod.suggest_attack_class(sink_kind, callee=callee)
    except Exception:
        return None


def _suggest_boundary_attack_class(sink_kind: str, callee: str | None):
    """Map a BOUNDARY-SUSPECT DefUsePath -> a CANONICAL off-by-one/boundary attack
    class (verbatim-matched against the taxonomy, omitted when none exists - R38).
    ADDITIVE: callers tag provenance="dataflow_boundary_suspect"."""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "dataflow_attack_class",
            str(AUDITOOOR_ROOT / "tools" / "lib" / "dataflow_attack_class.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
    except Exception:
        return None
    try:
        return mod.suggest_boundary_attack_class(sink_kind, callee=callee)
    except Exception:
        return None


def _flow_anchor_fns(path: dict) -> set[str]:
    """Return the function identities (source.fn + sink.fn) this path touches,
    so a question can be attributed to the function-record under analysis."""
    out: set[str] = set()
    for end in ("source", "sink"):
        fn = ((path.get(end) or {}).get("fn") or "").strip()
        if fn:
            out.add(fn)
    return out


def gen_flow_seeded_questions(seedable_paths: list) -> list[dict]:
    """Emit ONE targeted hacker-question per UNGUARDED value-mover DefUsePath.

    The question is anchored at the REAL sink file:line, names the source ->
    hops -> sink chain, and carries flow_seeded=True + dataflow_path_id so the
    ranker can boost it and the hunter brief can attach the path context. R76:
    the anchors are taken verbatim from the slice (real file:line); the hunter
    is instructed to verify at source.

    Default-off: an empty seedable_paths list yields [].
    """
    out: list[dict] = []
    for path in seedable_paths:
        src = path.get("source") or {}
        sink = path.get("sink") or {}
        sink_fn = (sink.get("fn") or "").strip()
        src_fn = (src.get("fn") or "").strip()
        # Attribute the question to the SINK function when known (that is where
        # the value moves and where the hunter should drill), else the source fn.
        anchor_fn = sink_fn or src_fn or "?"
        sink_file = sink.get("file") or "?"
        sink_line = sink.get("line")
        src_file = src.get("file") or "?"
        src_line = src.get("line")
        sink_kind = sink.get("kind") or "value-mover"
        sink_callee = sink.get("callee") or sink.get("var") or sink_kind
        src_var = src.get("var") or "input"
        hops = path.get("call_depth", 0)
        path_id = path.get("path_id") or "dfp-?"
        sink_anchor = f"{sink_file}:{sink_line}" if sink_line is not None else sink_file
        src_anchor = f"{src_file}:{src_line}" if src_line is not None else src_file
        q = (
            f"Data-flow slice {path_id}: an unprivileged caller drives "
            f"`{src_fn or '?'}({src_var})` @ {src_anchor} -> {hops} hop(s) -> "
            f"`{sink_kind}` sink `{sink_callee}` @ {sink_anchor} with NO guard "
            f"dominating the path (closure-checked: unguarded). Can an attacker "
            f"exploit THIS specific unguarded flow to move value / corrupt the "
            f"economic state? Verify the flow at source per R76 before claiming it."
        )
        rec = {
            "schema_version": SCHEMA,
            "function": anchor_fn,
            # The question's `file` field anchors at the REAL SINK file:line so the
            # ranker's file_line cross-pin / scanner join keys on the value site.
            "file": sink_anchor,
            "language": path.get("language", "?"),
            "anchor_invariant": f"flow:{path_id}",
            "question": q,
            "question_class": f"unguarded-{sink_kind}",
            "question_source": "flow-seeded",
            "flow_seeded": True,
            "dataflow_path_id": path_id,
            "flow_source_fn": src_fn,
            "flow_source_anchor": src_anchor,
            "flow_sink_fn": sink_fn,
            "flow_sink_anchor": sink_anchor,
            "flow_sink_kind": sink_kind,
            "flow_call_depth": hops,
            "flow_confidence": path.get("confidence", ""),
        }
        # Edge 9 (R38): additive sink-kind -> canonical attack-class SUGGESTION.
        # Verbatim-matched against the taxonomy; omitted entirely when no canonical
        # class matches (never invented). Tagged provenance so a downstream
        # consumer can tell it came from the dataflow sink kind, not a hunter.
        ac = _suggest_attack_class(sink_kind, sink_callee)
        if ac:
            rec["attack_class"] = ac
            rec["attack_class_provenance"] = "dataflow_sink_kind"
        out.append(rec)
    return out


# --- P3 sibling seed source #1: COUPLED-STATE co-write violators ---------------
# tools/state-coupling-graph.py emits one StateCouplingEdge per coupled state-cell
# pair to <ws>/.auditooor/state_coupling_edges.jsonl. Each edge couples cell_a <->
# cell_b (a |G|>=2 co-write group) under a completeness OBLIGATION, and carries
# `violators`: the writer functions that mutate ONE endpoint but OMIT the coupled
# sibling (the partial-update desync - the Aptos-class must-move-together break).
# This source turns each such violator into ONE targeted hacker-question anchored at
# the violator's REAL file:line, so the per-fn hunt is FED BY the coupled-state
# completeness signal instead of by symbol/shape. ADDITIVE + default-on when the
# sidecar is present; absent the sidecar zero coupled-seeded questions are produced.


def _read_state_coupling_edges(workspace: str | None):
    """Read StateCouplingEdge records from the workspace sidecar.

    Uses state_coupling_schema.read_edges (the canonical reader) so malformed rows
    are dropped. Returns [] when the sidecar is absent, the reader is unavailable,
    or the workspace is unset - so a no-graph workspace yields zero coupled-seeded
    questions (default-on-when-present, byte-identical when absent).
    """
    if not workspace:
        return []
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "state_coupling_schema",
            str(AUDITOOOR_ROOT / "tools" / "state_coupling_schema.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
    except Exception:
        return []
    try:
        return mod.read_edges(workspace)
    except Exception:
        return []


def _coupling_violators_omitting_sibling(edge: dict) -> list[dict]:
    """The subset of an edge's violators that MUTATE one endpoint but OMIT the
    coupled sibling - each is a concrete partial-update desync writer.

    Honest filter (R80): a `heuristic` (name-only) edge is NEVER cited, so it seeds
    nothing. The edge must couple a genuine |G|>=2 group (BOTH cell_a and cell_b
    present) and each returned violator must carry a non-empty `omits` plus a
    concrete anchor (fn or file).
    """
    if not isinstance(edge, dict):
        return []
    if edge.get("confidence") == "heuristic":
        return []
    if not (edge.get("cell_a") and edge.get("cell_b")):
        return []
    out: list[dict] = []
    for v in edge.get("violators") or []:
        if not isinstance(v, dict):
            continue
        if not v.get("omits"):
            continue
        if not (v.get("fn") or v.get("file")):
            continue
        out.append(v)
    return out


def _fmt_cells(val) -> str:
    """Render a violator's `mutates`/`omits` (a list of cell names, or a scalar)
    into a compact human string for the question text."""
    if isinstance(val, (list, tuple, set)):
        items = [str(x) for x in val if str(x).strip()]
        return ", ".join(items) if items else "?"
    s = str(val).strip()
    return s or "?"


def gen_coupled_seeded_questions(edges: list) -> list[dict]:
    """Emit ONE coupled-state hacker-question per (edge, violator-that-omits-sibling).

    The question is anchored at the violator's REAL file:line, names the coupled
    cell pair, the coupling kind, and exactly which cell(s) the writer mutates vs
    omits, and carries flow_seeded=True + coupled_seeded=True + the edge id so the
    ranker can boost it and the hunter brief can attach the coupling obligation.
    R76: anchors taken verbatim from the edge; the hunter is told to verify at
    source. This is a LEAD, never a finding.

    Default-on-when-present: an empty edges list yields [].
    """
    out: list[dict] = []
    for edge in edges or []:
        cell_a = edge.get("cell_a") or "?"
        cell_b = edge.get("cell_b") or "?"
        kind = edge.get("kind") or "coupled"
        edge_id = edge.get("edge_id") or "sce-?"
        impact_class = edge.get("impact_class") or "coupled-state-partial-update"
        lang = edge.get("language") or "?"
        obligation = (edge.get("obligation") or "").strip()
        for v in _coupling_violators_omitting_sibling(edge):
            vfn = (v.get("fn") or "?")
            vfile = v.get("file") or "?"
            vline = v.get("line")
            mutates = _fmt_cells(v.get("mutates"))
            omits = _fmt_cells(v.get("omits"))
            anchor = f"{vfile}:{vline}" if vline is not None else vfile
            q = (
                f"Coupled-state edge {edge_id} ({kind}): cells `{cell_a}` and "
                f"`{cell_b}` are coupled and MUST move together, but writer "
                f"`{vfn}` @ {anchor} mutates `{mutates}` while OMITTING the "
                f"coupled sibling `{omits}` - a partial-update desync. Can an "
                f"attacker drive `{vfn}` to leave the coupled pair inconsistent "
                f"(stale/double-counted/under-counted) and turn that desync into "
                f"a value-conservation break, wrong accounting, or a stuck/"
                f"drainable state ({impact_class})? "
                + (f"Obligation: {obligation} " if obligation else "")
                + "Verify at source per R76 first (read the writer body; confirm "
                f"it truly never writes `{omits}` and that no sibling writer / "
                "same-tx call re-establishes the coupling)."
            )
            rec = {
                "schema_version": SCHEMA,
                "function": vfn,
                "file": anchor,
                "language": lang,
                "anchor_invariant": f"coupled:{edge_id}",
                "question": q,
                "question_class": impact_class,
                "question_source": "coupled-seeded",
                "flow_seeded": True,
                "coupled_seeded": True,
                "state_coupling_edge_id": edge_id,
                "coupling_kind": kind,
                "coupling_cell_a": cell_a,
                "coupling_cell_b": cell_b,
                "coupling_mutates": mutates,
                "coupling_omits": omits,
                "coupling_confidence": edge.get("confidence", ""),
            }
            out.append(rec)
    return out


# --- P3 sibling seed source #2: ORACLE-REACHABILITY hypotheses ------------------
# tools/oracle-reachability-lane.py (ORL) emits one reachability hypothesis per
# value-moving function that READS an attacker-movable oracle/price to
# <ws>/.auditooor/oracle_reachability_hypotheses.jsonl. ORL is fail-closed by
# design: a GUARDED read produces 0 hypotheses, and every row carries
# verdict="needs-fuzz" (never auto-confirmed). This source turns each hypothesis
# into ONE targeted hacker-question anchored at the REAL read_site, so the per-fn
# hunt is FED BY the oracle-reachability signal instead of by symbol/shape.
# ADDITIVE + default-on when the sidecar is present; absent it, zero produced.


def _read_oracle_hypotheses(workspace: str | None) -> list[dict]:
    """Read oracle-reachability hypotheses from the workspace sidecar.

    Plain JSONL (ORL emits a flat dict per line; there is no shared schema module).
    Malformed lines are skipped. Returns [] when the sidecar is absent or the
    workspace is unset - so a no-oracle workspace yields zero oracle-seeded
    questions (default-on-when-present, byte-identical when absent).
    """
    if not workspace:
        return []
    p = Path(workspace) / ".auditooor" / "oracle_reachability_hypotheses.jsonl"
    if not p.is_file():
        return []
    rows: list[dict] = []
    try:
        with p.open() as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(rec, dict):
                    rows.append(rec)
    except OSError:
        return []
    return rows


def _oracle_hyp_is_seedable(hyp: dict) -> bool:
    """An oracle hypothesis is seedable iff it names a concrete consuming function
    AND a concrete read_site (file:line). ORL only emits reachable, movable,
    UNGUARDED reads (guarded reads produce 0 hypotheses), so no extra guard filter
    is needed here; we only reject rows missing the load-bearing anchor fields."""
    if not isinstance(hyp, dict):
        return False
    if not (hyp.get("function") and hyp.get("read_site")):
        return False
    return True


def gen_oracle_seeded_questions(hyps: list) -> list[dict]:
    """Emit ONE oracle-manipulation hacker-question per ORACLE-REACHABILITY
    hypothesis.

    The question is anchored at the REAL read_site, names the read kind, the
    movability reason, the value-loss path, and the sub-class, and carries
    flow_seeded=True + oracle_seeded=True + verdict='needs-fuzz' so the ranker can
    boost it and the hunter brief can attach the reachability context. R76: anchors
    taken verbatim from the hypothesis; the hunter is told to verify at source.
    This is a LEAD, never a finding.

    Default-on-when-present: an empty hyps list yields [].
    """
    out: list[dict] = []
    for hyp in hyps or []:
        if not _oracle_hyp_is_seedable(hyp):
            continue
        fn = hyp.get("function") or "?"
        read_site = hyp.get("read_site") or (hyp.get("file") or "?")
        lang = hyp.get("language") or "?"
        read_kind = hyp.get("read_kind") or "an oracle/price read"
        sub_class = hyp.get("sub_class") or "movable-spot"
        movability = (hyp.get("movability_reason") or "").strip()
        value_loss = (hyp.get("value_loss_path") or "").strip()
        snippet = (hyp.get("read_snippet") or "").strip()
        attack_class = hyp.get("attack_class") or "oracle-price-manipulation"
        q = (
            f"Oracle-reachability hypothesis ({sub_class}): `{fn}` reads "
            f"{read_kind} @ {read_site}"
            + (f" (`{snippet}`)" if snippet else "")
            + ". "
            + (f"That source is attacker-movable: {movability}. " if movability else "")
            + (f"It drives value: {value_loss}. " if value_loss else "")
            + f"Can an attacker move the reported price/value (flash-loan, thin-"
            f"liquidity swing, stale round, decimal/sequencer edge) so `{fn}` "
            f"transacts on a manipulated value and realizes a loss "
            f"({attack_class})? Verify at source per R76 first (read the actual "
            "read + how the value feeds the value-moving arithmetic; confirm no "
            "TWAP / freshness / bounds guard neutralizes it). verdict=needs-fuzz."
        )
        rec = {
            "schema_version": SCHEMA,
            "function": fn,
            "file": read_site,
            "language": lang,
            "anchor_invariant": f"oracle:{read_site}",
            "question": q,
            "question_class": f"oracle-{sub_class}",
            "question_source": "oracle-seeded",
            "flow_seeded": True,
            "oracle_seeded": True,
            "oracle_read_site": read_site,
            "oracle_read_kind": read_kind,
            "oracle_sub_class": sub_class,
            "oracle_attack_class": attack_class,
            "oracle_verdict": hyp.get("verdict", "needs-fuzz"),
        }
        out.append(rec)
    return out


def _flow_path_is_boundary_suspect(path: dict) -> bool:
    """A DefUsePath is boundary-suspect-seedable iff the closure pass stamped it
    `boundary_suspect == True` (its dominating value-bound guard uses a `<=`/`>=`
    where a `<`/`>` may have been intended - a guard-CORRECTNESS lead).

    Distinct from `_flow_path_is_seedable` (which is the NO-guard case): a
    boundary-suspect path IS guarded (`unguarded` is typically False) but the
    guard may still be off-by-one exploitable. Honest filter (R80): degraded
    records and heuristic-confidence records never seed.
    """
    if not isinstance(path, dict):
        return False
    if path.get("degraded"):
        return False
    if path.get("confidence") == "heuristic":
        return False
    return path.get("boundary_suspect") is True


def gen_boundary_suspect_questions(suspect_paths: list) -> list[dict]:
    """Emit ONE off-by-one/boundary hacker-question per BOUNDARY-SUSPECT DefUsePath.

    The question is anchored at the guard comparator's file:line, names the
    suspect op + the strict counterpart, and carries boundary_suspect=True +
    dataflow_path_id so the ranker can boost it and the hunter brief can attach
    the path context. R76: anchors taken verbatim from the slice; the hunter is
    told to verify at source. This is a LEAD, never an auto-finding.

    Default-off: an empty suspect_paths list yields [].
    """
    out: list[dict] = []
    for path in suspect_paths:
        src = path.get("source") or {}
        sink = path.get("sink") or {}
        gc = path.get("guard_comparator") or {}
        sink_fn = (sink.get("fn") or "").strip()
        src_fn = (src.get("fn") or "").strip()
        op = gc.get("op") or "<="
        suggested = gc.get("suggested_op") or "<"
        guard_line = gc.get("line")
        at_fn_label = gc.get("at_fn") or "source"
        # Anchor at the guard's file:line; the guard lives in whichever end the
        # closure pass flagged (source or sink).
        guard_end = src if at_fn_label == "source" else sink
        guard_file = guard_end.get("file") or "?"
        anchor_fn = (sink_fn or src_fn or "?")
        guard_anchor = (f"{guard_file}:{guard_line}"
                        if guard_line is not None else guard_file)
        sink_kind = sink.get("kind") or "value-mover"
        sink_callee = sink.get("callee") or sink.get("var") or sink_kind
        path_id = path.get("path_id") or "dfp-?"
        q = (
            f"Data-flow slice {path_id}: the value-moving path into "
            f"`{sink_kind}` sink `{sink_callee}` is dominated by a NON-STRICT "
            f"bound `{op}` @ {guard_anchor}. Is this an off-by-one cap bypass - "
            f"was `{suggested}` intended? Can the attacker pass the boundary "
            f"value (cap exactly) to move 1 unit more than the cap allows, or "
            f"trip an inverted/strict-vs-non-strict edge? Verify the comparator "
            f"AND the intended bound at source per R76 before claiming it."
        )
        rec = {
            "schema_version": SCHEMA,
            "function": anchor_fn,
            "file": guard_anchor,
            "language": path.get("language", "?"),
            "anchor_invariant": f"boundary:{path_id}",
            "question": q,
            "question_class": "boundary-off-by-one",
            "question_source": "flow-seeded-boundary",
            "flow_seeded": True,
            "boundary_suspect": True,
            "dataflow_path_id": path_id,
            "flow_source_fn": src_fn,
            "flow_sink_fn": sink_fn,
            "flow_sink_kind": sink_kind,
            "guard_comparator_op": op,
            "guard_comparator_suggested_op": suggested,
            "guard_comparator_anchor": guard_anchor,
            "flow_confidence": path.get("confidence", ""),
        }
        # Edge 9 (R38): additive sink-kind -> canonical attack-class SUGGESTION,
        # PLUS a boundary/off-by-one class candidate (verbatim-matched; omitted
        # when no canonical class exists - never invented).
        ac = _suggest_boundary_attack_class(sink_kind, sink_callee)
        if ac:
            rec["attack_class"] = ac
            rec["attack_class_provenance"] = "dataflow_boundary_suspect"
        out.append(rec)
    return out


def _suggest_downcast_attack_class(sink_kind: str, callee: str | None):
    """Map an UNSAFE-DOWNCAST path -> a CANONICAL truncation/overflow attack class
    (verbatim-matched against the taxonomy, omitted when none exists - R38).
    ADDITIVE: callers tag provenance="dataflow_downcast_suspect"."""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "dataflow_attack_class",
            str(AUDITOOOR_ROOT / "tools" / "lib" / "dataflow_attack_class.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
    except Exception:
        return None
    try:
        return mod.suggest_downcast_attack_class(sink_kind, callee=callee)
    except Exception:
        return None


def _flow_path_is_downcast_suspect(path: dict) -> bool:
    """A DefUsePath is downcast-suspect-seedable iff the closure pass stamped it
    `downcast_suspect == True` (the value-flow crosses a LOSSY cast - a uint256->
    uint64 truncation or an int<->uint sign-flip on a value-moving operand).

    Honest filter (R80): degraded records and heuristic-confidence records never
    seed. This is a guard-INDEPENDENT lead (a downcast bug is exploitable whether
    or not the path is access-guarded), so unguarded is not consulted here.
    """
    if not isinstance(path, dict):
        return False
    if path.get("degraded"):
        return False
    if path.get("confidence") == "heuristic":
        return False
    return path.get("downcast_suspect") is True


def gen_downcast_suspect_questions(suspect_paths: list) -> list[dict]:
    """Emit ONE truncation/sign-flip hacker-question per UNSAFE-DOWNCAST DefUsePath.

    The question is anchored at the cast's file:line, names the from->to type
    narrowing (or sign-flip) and the value-moving operand, and carries
    downcast_suspect=True + dataflow_path_id so the ranker can boost it and the
    hunter brief can attach the path context. R76: anchors taken verbatim from the
    slice; the hunter is told to verify at source. This is a LEAD, never a finding.

    Default-off: an empty suspect_paths list yields [].
    """
    out: list[dict] = []
    for path in suspect_paths:
        src = path.get("source") or {}
        sink = path.get("sink") or {}
        dc = path.get("downcast") or {}
        sink_fn = (sink.get("fn") or "").strip()
        src_fn = (src.get("fn") or "").strip()
        var = dc.get("var") or "value"
        from_t = dc.get("from") or "uintN"
        to_t = dc.get("to") or "uintM"
        kind = dc.get("kind") or "narrowing"
        cast_line = dc.get("line")
        at_fn_label = dc.get("at_end") or "source"
        # Anchor at the cast's file:line; the cast lives in whichever end the
        # closure pass flagged (source or sink) - use that end's file.
        cast_end = src if at_fn_label == "source" else sink
        cast_file = cast_end.get("file") or "?"
        anchor_fn = (sink_fn or src_fn or "?")
        cast_anchor = (f"{cast_file}:{cast_line}"
                       if cast_line is not None else cast_file)
        sink_kind = sink.get("kind") or "value-mover"
        sink_callee = sink.get("callee") or sink.get("var") or sink_kind
        path_id = path.get("path_id") or "dfp-?"
        if kind == "sign-flip":
            why = (f"a SIGN-FLIP cast `{from_t}` -> `{to_t}` (a negative value can "
                   f"be re-interpreted as a huge positive, or vice-versa)")
        else:
            why = (f"a NARROWING downcast `{from_t}` -> `{to_t}` (the high bits of "
                   f"`{var}` are silently TRUNCATED)")
        q = (
            f"Data-flow slice {path_id}: the value-moving operand `{var}` reaching "
            f"`{sink_kind}` sink `{sink_callee}` crosses {why} @ {cast_anchor}. Can "
            f"an attacker pass a `{var}` larger than `{to_t}` can hold so the cast "
            f"wraps/truncates - moving a DIFFERENT amount than intended, minting "
            f"more than paid, or corrupting accounting? Confirm it is a RAW cast "
            f"(not SafeCast.toUintN / not bound-checked) at source per R76 first."
        )
        rec = {
            "schema_version": SCHEMA,
            "function": anchor_fn,
            "file": cast_anchor,
            "language": path.get("language", "?"),
            "anchor_invariant": f"downcast:{path_id}",
            "question": q,
            "question_class": "unsafe-downcast-truncation",
            "question_source": "flow-seeded-downcast",
            "flow_seeded": True,
            "downcast_suspect": True,
            "dataflow_path_id": path_id,
            "flow_source_fn": src_fn,
            "flow_sink_fn": sink_fn,
            "flow_sink_kind": sink_kind,
            "downcast_var": var,
            "downcast_from": from_t,
            "downcast_to": to_t,
            "downcast_kind": kind,
            "downcast_anchor": cast_anchor,
            "flow_confidence": path.get("confidence", ""),
        }
        # Edge 9 (R38): additive truncation/overflow canonical class (verbatim-
        # matched against the taxonomy; omitted when no canonical class exists -
        # never invented).
        ac = _suggest_downcast_attack_class(sink_kind, sink_callee)
        if ac:
            rec["attack_class"] = ac
            rec["attack_class_provenance"] = "dataflow_downcast_suspect"
        out.append(rec)
    return out


def _suggest_div_before_mul_attack_class(sink_kind: str, callee: str | None):
    """Map a DIVIDE-BEFORE-MULTIPLY path -> a CANONICAL precision-loss / rounding
    attack class (verbatim-matched against the taxonomy, omitted when none exists -
    R38). ADDITIVE: callers tag provenance="dataflow_div_before_mul_suspect"."""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "dataflow_attack_class",
            str(AUDITOOOR_ROOT / "tools" / "lib" / "dataflow_attack_class.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
    except Exception:
        return None
    try:
        return mod.suggest_div_before_mul_attack_class(sink_kind, callee=callee)
    except Exception:
        return None


def _flow_path_is_div_before_mul_suspect(path: dict) -> bool:
    """A DefUsePath is divide-before-multiply-suspect-seedable iff the closure pass
    stamped it `div_before_mul_suspect == True` (the value-flow's source/sink fn -
    or an intermediate hop - computes `(a / b) * c`, truncating before scaling).

    Honest filter (R80): degraded records and heuristic-confidence records never
    seed. This is a guard-INDEPENDENT lead (a precision bug is exploitable whether or
    not the path is access-guarded), so unguarded is not consulted here.
    """
    if not isinstance(path, dict):
        return False
    if path.get("degraded"):
        return False
    if path.get("confidence") == "heuristic":
        return False
    return path.get("div_before_mul_suspect") is True


def gen_div_before_mul_questions(suspect_paths: list) -> list[dict]:
    """Emit ONE precision-loss hacker-question per DIVIDE-BEFORE-MULTIPLY DefUsePath.

    The question is anchored at the DIVISION's file:line, names the divide-before-
    multiply ordering, and carries div_before_mul_suspect=True + dataflow_path_id so
    the ranker can boost it and the hunter brief can attach the path context. R76:
    anchors taken verbatim from the slice; the hunter is told to verify at source.
    This is a LEAD, never a finding.

    Default-off: an empty suspect_paths list yields [].
    """
    out: list[dict] = []
    for path in suspect_paths:
        src = path.get("source") or {}
        sink = path.get("sink") or {}
        dbm = path.get("div_before_mul") or {}
        sink_fn = (sink.get("fn") or "").strip()
        src_fn = (src.get("fn") or "").strip()
        div_line = dbm.get("div_line")
        mul_line = dbm.get("mul_line")
        value_moving = dbm.get("value_moving", "unknown")
        at_fn_label = dbm.get("at_end") or "source"
        # Anchor at the DIVISION's file:line; the op lives in whichever end the
        # closure pass flagged (source or sink) - use that end's file.
        div_end = src if at_fn_label == "source" else sink
        div_file = div_end.get("file") or "?"
        anchor_fn = (sink_fn or src_fn or "?")
        div_anchor = (f"{div_file}:{div_line}"
                      if div_line is not None else div_file)
        sink_kind = sink.get("kind") or "value-mover"
        sink_callee = sink.get("callee") or sink.get("var") or sink_kind
        path_id = path.get("path_id") or "dfp-?"
        vm_note = ("value-moving" if value_moving is True
                   else ("non-value" if value_moving is False else "unconfirmed-value"))
        q = (
            f"Data-flow slice {path_id}: reaching `{sink_kind}` sink `{sink_callee}`, "
            f"an integer DIVISION @ {div_anchor} has its quotient MULTIPLIED at line "
            f"{mul_line} - a `(a / b) * c` divide-before-multiply that TRUNCATES "
            f"before scaling (the operand is {vm_note}). Can an attacker pick inputs "
            f"so the truncated quotient rounds the scaled result down (or to zero), "
            f"shorting a payout / inflating a price / mis-accounting shares vs the "
            f"correct `(a * c) / b`? Confirm the ordering at source per R76 first "
            f"(mul-before-div `(a * b) / c` is the CORRECT form and is NOT a bug)."
        )
        rec = {
            "schema_version": SCHEMA,
            "function": anchor_fn,
            "file": div_anchor,
            "language": path.get("language", "?"),
            "anchor_invariant": f"div-before-mul:{path_id}",
            "question": q,
            "question_class": "precision-divide-before-multiply",
            "question_source": "flow-seeded-div-before-mul",
            "flow_seeded": True,
            "div_before_mul_suspect": True,
            "dataflow_path_id": path_id,
            "flow_source_fn": src_fn,
            "flow_sink_fn": sink_fn,
            "flow_sink_kind": sink_kind,
            "div_before_mul_div_line": div_line,
            "div_before_mul_mul_line": mul_line,
            "div_before_mul_value_moving": value_moving,
            "div_before_mul_anchor": div_anchor,
            "flow_confidence": path.get("confidence", ""),
        }
        # Edge I2 (R38): additive precision-loss canonical class (verbatim-matched
        # against the taxonomy; omitted when no canonical class exists - never
        # invented).
        ac = _suggest_div_before_mul_attack_class(sink_kind, sink_callee)
        if ac:
            rec["attack_class"] = ac
            rec["attack_class_provenance"] = "dataflow_div_before_mul_suspect"
        out.append(rec)
    return out


def _suggest_asm_attack_class(asm_kind: str, callee: str | None):
    """Map an INLINE-ASSEMBLY / YUL suspect path -> a CANONICAL proxy/upgradeability,
    storage-collision, or fund-transfer attack class (verbatim-matched against the
    taxonomy, omitted when none exists - R38).
    ADDITIVE: callers tag provenance="dataflow_asm_suspect"."""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "dataflow_attack_class",
            str(AUDITOOOR_ROOT / "tools" / "lib" / "dataflow_attack_class.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
    except Exception:
        return None
    try:
        return mod.suggest_asm_attack_class(asm_kind, callee=callee)
    except Exception:
        return None


def _suggest_intra_cei_attack_class(sink_kind: str, callee: str | None):
    """Map a SAME-FN CEI-violation path -> a CANONICAL reentrancy attack class
    (verbatim-matched against the taxonomy, omitted when none exists - R38).
    ADDITIVE: callers tag provenance="dataflow_intra_cei_suspect"."""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "dataflow_attack_class",
            str(AUDITOOOR_ROOT / "tools" / "lib" / "dataflow_attack_class.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
    except Exception:
        return None
    try:
        return mod.suggest_intra_cei_attack_class(sink_kind, callee=callee)
    except Exception:
        return None


def _suggest_unbounded_loop_attack_class(sink_kind: str, callee: str | None):
    """Map an UNBOUNDED-LOOP path -> a CANONICAL DoS / gas-griefing attack class
    (verbatim-matched against the taxonomy, omitted when none exists - R38).
    ADDITIVE: callers tag provenance="dataflow_unbounded_loop_suspect"."""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "dataflow_attack_class",
            str(AUDITOOOR_ROOT / "tools" / "lib" / "dataflow_attack_class.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
    except Exception:
        return None
    try:
        return mod.suggest_unbounded_loop_attack_class(sink_kind, callee=callee)
    except Exception:
        return None


def _flow_path_is_asm_suspect(path: dict) -> bool:
    """A DefUsePath is asm-suspect-seedable iff the closure pass stamped it
    `asm_suspect == True` (the value-flow crosses an inline-assembly (Yul) block
    with a delegatecall - proxy/upgrade backdoor - a literal-slot sstore - storage-
    slot collision - or a raw value-moving call).

    Honest filter (R80): degraded records and heuristic-confidence records never
    seed. This is a guard-INDEPENDENT lead (a Yul delegatecall / storage-collision
    is exploitable whether or not the path is access-guarded), so unguarded is not
    consulted here.
    """
    if not isinstance(path, dict):
        return False
    if path.get("degraded"):
        return False
    if path.get("confidence") == "heuristic":
        return False
    return path.get("asm_suspect") is True


def gen_asm_suspect_questions(suspect_paths: list) -> list[dict]:
    """Emit ONE asm-delegatecall / storage-collision hacker-question per INLINE-
    ASSEMBLY / YUL DefUsePath.

    The question is anchored at the Yul block's file:line, names the asm sink kind
    (delegatecall / literal-slot sstore / raw call) and the slot when present, and
    carries asm_suspect=True + dataflow_path_id so the ranker can boost it and the
    hunter brief can attach the path context. R76: anchors taken verbatim from the
    slice; the hunter is told to verify at source. This is a LEAD, never a finding.

    Default-off: an empty suspect_paths list yields [].
    """
    out: list[dict] = []
    for path in suspect_paths:
        src = path.get("source") or {}
        sink = path.get("sink") or {}
        asm = path.get("asm") or {}
        sink_fn = (sink.get("fn") or "").strip()
        src_fn = (src.get("fn") or "").strip()
        kind = asm.get("kind") or "delegatecall"
        slot = asm.get("slot")
        asm_line = asm.get("line")
        at_fn_label = asm.get("at_end") or "source"
        # Anchor at the asm block's file:line; it lives in whichever end the
        # closure pass flagged (source or sink) - use that end's file.
        asm_end = src if at_fn_label == "source" else sink
        asm_file = asm_end.get("file") or "?"
        anchor_fn = (sink_fn or src_fn or "?")
        asm_anchor = (f"{asm_file}:{asm_line}"
                      if asm_line is not None else asm_file)
        sink_kind = sink.get("kind") or "value-mover"
        sink_callee = sink.get("callee") or sink.get("var") or sink_kind
        path_id = path.get("path_id") or "dfp-?"
        if kind == "delegatecall":
            why = ("a Yul `delegatecall(` inside inline assembly (a proxy/upgrade "
                   "primitive the solidity-level delegatecall predicate is BLIND "
                   "to)")
            ask = ("Does the delegatecall target an address an attacker can set / "
                   "influence (an upgrade backdoor), or execute attacker-supplied "
                   "calldata in this contract's storage context")
            qclass = "asm-delegatecall-backdoor"
        elif kind == "sstore-literal":
            why = (f"a Yul `sstore(` to a LITERAL/constant slot `{slot}` inside "
                   "inline assembly (a storage-slot COLLISION shape - a hardcoded "
                   "slot can alias a declared state var's compiler slot)")
            ask = (f"Can the literal slot `{slot}` collide with a declared storage "
                   "variable's slot, letting this write corrupt unrelated "
                   "accounting / an owner / an implementation pointer")
            qclass = "asm-storage-collision"
        else:  # asm-call
            why = ("a raw Yul `call(` inside inline assembly (native value can "
                   "leave the contract bypassing the solidity-level call "
                   "predicates)")
            ask = ("Can an attacker steer the raw asm call's target / value to "
                   "move funds the attacker does not own")
            qclass = "asm-raw-call"
        q = (
            f"Data-flow slice {path_id}: the value-flow reaching `{sink_kind}` "
            f"sink `{sink_callee}` crosses {why} @ {asm_anchor}. {ask}? Confirm at "
            f"source per R76 first (read the actual Yul block; verify the "
            f"delegatecall target / slot operand)."
        )
        rec = {
            "schema_version": SCHEMA,
            "function": anchor_fn,
            "file": asm_anchor,
            "language": path.get("language", "?"),
            "anchor_invariant": f"asm:{path_id}",
            "question": q,
            "question_class": qclass,
            "question_source": "flow-seeded-asm",
            "flow_seeded": True,
            "asm_suspect": True,
            "dataflow_path_id": path_id,
            "flow_source_fn": src_fn,
            "flow_sink_fn": sink_fn,
            "flow_sink_kind": sink_kind,
            "asm_kind": kind,
            "asm_slot": slot,
            "asm_anchor": asm_anchor,
            "flow_confidence": path.get("confidence", ""),
        }
        # Edge 9 (R38): additive proxy/upgradeability or storage-collision canonical
        # class (verbatim-matched against the taxonomy; omitted when no canonical
        # class exists - never invented).
        ac = _suggest_asm_attack_class(kind, sink_callee)
        if ac:
            rec["attack_class"] = ac
            rec["attack_class_provenance"] = "dataflow_asm_suspect"
        out.append(rec)
    return out


def _flow_path_is_intra_cei_suspect(path: dict) -> bool:
    """A DefUsePath is intra-cei-suspect-seedable iff the closure pass stamped it
    `intra_cei_suspect == True` (the value-flow's source/sink fn - or an
    intermediate hop - has a STATE-WRITE AFTER an EXTERNAL CALL within ONE function
    with NO reentrancy guard: the same-fn CEI violation the cross-fn closure
    reentrancy oracle misses).

    Honest filter (R80): degraded records and heuristic-confidence records never
    seed. Guard-INDEPENDENT lead (a same-fn reentrancy is exploitable whether or
    not the path is access-guarded), so `unguarded` is not consulted here.
    """
    if not isinstance(path, dict):
        return False
    if path.get("degraded"):
        return False
    if path.get("confidence") == "heuristic":
        return False
    return path.get("intra_cei_suspect") is True


def gen_intra_cei_questions(suspect_paths: list) -> list[dict]:
    """Emit ONE same-fn-reentrancy hacker-question per SAME-FN CEI DefUsePath.

    The question is anchored at the post-call state-write `file:line`, names the
    written state var + the preceding external call, and carries
    intra_cei_suspect=True + dataflow_path_id so the ranker can boost it and the
    hunter brief can attach the path context. R76: anchors taken verbatim from the
    slice; the hunter is told to verify at source. This is a LEAD, never a finding.
    It COMPLEMENTS the cross-fn closure reentrancy oracle (adds the same-fn
    ordering it misses) - not a duplicate.

    Default-off: an empty suspect_paths list yields [].
    """
    out: list[dict] = []
    for path in suspect_paths:
        src = path.get("source") or {}
        sink = path.get("sink") or {}
        cei = path.get("intra_cei") or {}
        sink_fn = (sink.get("fn") or "").strip()
        src_fn = (src.get("fn") or "").strip()
        var = cei.get("var") or "state"
        ext_line = cei.get("ext_call_line")
        write_line = cei.get("state_write_line")
        at_fn = cei.get("at_fn") or "?"
        at_end_label = cei.get("at_end") or "source"
        # Anchor at the file of whichever end the closure pass flagged.
        cei_end = src if at_end_label == "source" else sink
        cei_file = cei_end.get("file") or "?"
        anchor_fn = (sink_fn or src_fn or "?")
        write_anchor = (f"{cei_file}:{write_line}"
                        if write_line is not None else cei_file)
        ext_anchor = (f"{cei_file}:{ext_line}" if ext_line is not None else cei_file)
        sink_kind = sink.get("kind") or "value-mover"
        sink_callee = sink.get("callee") or sink.get("var") or sink_kind
        path_id = path.get("path_id") or "dfp-?"
        # ADDITIVE (Glider gap W4): when the external call is reached TRANSITIVELY
        # through an internal helper, name the helper in the question text so the
        # hunter knows the call is not in `at_fn`'s own body. question_class /
        # attack_class are UNCHANGED (still same-fn-reentrancy / reentrancy).
        via_helper = cei.get("via") if cei.get("transitive") is True else None
        ext_clause = (
            f"makes an EXTERNAL CALL via internal helper `{via_helper}` @ {ext_anchor}"
            if via_helper
            else f"makes an EXTERNAL CALL @ {ext_anchor}"
        )
        q = (
            f"Data-flow slice {path_id}: function `{at_fn}` {ext_clause} and THEN "
            f"writes state `{var}` @ {write_anchor} within "
            f"the SAME function, with NO reentrancy guard (a same-fn "
            f"checks-effects-interactions violation the cross-fn closure reentrancy "
            f"oracle is BLIND to). Can an attacker re-enter during the external call "
            f"and observe / exploit the stale `{var}` before it is updated (classic "
            f"reentrancy)? Confirm at source per R76 first (read the actual "
            f"statement order; verify no guard / lock dominates the write)."
        )
        rec = {
            "schema_version": SCHEMA,
            "function": anchor_fn,
            # Anchor at the post-call state-write site (where the stale read bites).
            "file": write_anchor,
            "language": path.get("language", "?"),
            "anchor_invariant": f"intra-cei:{path_id}",
            "question": q,
            "question_class": "same-fn-reentrancy",
            "question_source": "flow-seeded-intra-cei",
            "flow_seeded": True,
            "intra_cei_suspect": True,
            "dataflow_path_id": path_id,
            "flow_source_fn": src_fn,
            "flow_sink_fn": sink_fn,
            "flow_sink_kind": sink_kind,
            "intra_cei_var": var,
            "intra_cei_ext_anchor": ext_anchor,
            "intra_cei_write_anchor": write_anchor,
            "flow_confidence": path.get("confidence", ""),
        }
        # Edge 9 (R38): additive canonical reentrancy class (verbatim-matched
        # against the taxonomy; omitted when no canonical class exists - never
        # invented). `reentrancy` is live in the corpus today.
        ac = _suggest_intra_cei_attack_class(sink_kind, sink_callee)
        if ac:
            rec["attack_class"] = ac
            rec["attack_class_provenance"] = "dataflow_intra_cei_suspect"
        out.append(rec)
    return out


def _flow_path_is_unbounded_loop_suspect(path: dict) -> bool:
    """A DefUsePath is unbounded-loop-suspect-seedable iff the closure pass stamped
    it `unbounded_loop_suspect == True` (the value-flow's source/sink fn - or an
    intermediate hop - has a loop bounded by an attacker-growable
    `<state-collection>.length` with an effect inside).

    Honest filter (R80): degraded records and heuristic-confidence records never
    seed. Guard-INDEPENDENT lead (a gas-griefing DoS is exploitable whether or not
    the path is access-guarded), so `unguarded` is not consulted here.
    """
    if not isinstance(path, dict):
        return False
    if path.get("degraded"):
        return False
    if path.get("confidence") == "heuristic":
        return False
    return path.get("unbounded_loop_suspect") is True


def gen_unbounded_loop_questions(suspect_paths: list) -> list[dict]:
    """Emit ONE unbounded-loop-gas hacker-question per UNBOUNDED-LOOP DefUsePath.

    The question is anchored at the loop `file:line`, names the attacker-growable
    bound collection, and carries unbounded_loop_suspect=True + dataflow_path_id so
    the ranker can boost it and the hunter brief can attach the path context. R76:
    anchors taken verbatim from the slice; the hunter is told to verify at source.
    This is a LEAD, never a finding.

    Default-off: an empty suspect_paths list yields [].
    """
    out: list[dict] = []
    for path in suspect_paths:
        src = path.get("source") or {}
        sink = path.get("sink") or {}
        ul = path.get("unbounded_loop") or {}
        sink_fn = (sink.get("fn") or "").strip()
        src_fn = (src.get("fn") or "").strip()
        bound_var = ul.get("bound_var") or "collection"
        loop_line = ul.get("loop_line")
        at_fn = ul.get("at_fn") or "?"
        at_end_label = ul.get("at_end") or "source"
        ul_end = src if at_end_label == "source" else sink
        ul_file = ul_end.get("file") or "?"
        anchor_fn = (sink_fn or src_fn or "?")
        loop_anchor = (f"{ul_file}:{loop_line}"
                       if loop_line is not None else ul_file)
        sink_kind = sink.get("kind") or "value-mover"
        sink_callee = sink.get("callee") or sink.get("var") or sink_kind
        path_id = path.get("path_id") or "dfp-?"
        q = (
            f"Data-flow slice {path_id}: function `{at_fn}` loops over the "
            f"attacker-growable `{bound_var}.length` @ {loop_anchor} with a "
            f"state-write / external-call effect inside the body. Can an attacker "
            f"grow `{bound_var}` (via a public add / push / register path) until the "
            f"loop exceeds the block gas limit, permanently bricking this function "
            f"(an unbounded-loop gas-griefing DoS)? Confirm at source per R76 first "
            f"(read the actual loop bound; verify `{bound_var}` is attacker-growable "
            f"and uncapped, and that the per-iteration effect is non-trivial)."
        )
        rec = {
            "schema_version": SCHEMA,
            "function": anchor_fn,
            "file": loop_anchor,
            "language": path.get("language", "?"),
            "anchor_invariant": f"unbounded-loop:{path_id}",
            "question": q,
            "question_class": "unbounded-loop-gas",
            "question_source": "flow-seeded-unbounded-loop",
            "flow_seeded": True,
            "unbounded_loop_suspect": True,
            "dataflow_path_id": path_id,
            "flow_source_fn": src_fn,
            "flow_sink_fn": sink_fn,
            "flow_sink_kind": sink_kind,
            "unbounded_loop_bound_var": bound_var,
            "unbounded_loop_anchor": loop_anchor,
            "flow_confidence": path.get("confidence", ""),
        }
        # Edge 9 (R38): additive canonical DoS / gas-griefing class (verbatim-
        # matched; omitted when no canonical class exists - never invented). `dos`
        # is live in the corpus today.
        ac = _suggest_unbounded_loop_attack_class(sink_kind, sink_callee)
        if ac:
            rec["attack_class"] = ac
            rec["attack_class_provenance"] = "dataflow_unbounded_loop_suspect"
        out.append(rec)
    return out


def _suggest_enumset_remove_in_loop_attack_class(sink_kind: str, callee: str | None):
    """Map an ENUMERABLESET REMOVE-IN-LOOP path (Glider gap W5) -> a CANONICAL
    iteration-skip / functional-correctness attack class (verbatim-matched against
    the taxonomy, omitted when none exists - R38). ADDITIVE: callers tag
    provenance="dataflow_enumset_remove_in_loop_suspect"."""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "dataflow_attack_class",
            str(AUDITOOOR_ROOT / "tools" / "lib" / "dataflow_attack_class.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
    except Exception:
        return None
    try:
        return mod.suggest_enumset_remove_in_loop_attack_class(sink_kind, callee=callee)
    except Exception:
        return None


def _flow_path_is_enumset_remove_in_loop_suspect(path: dict) -> bool:
    """A DefUsePath is enumset-remove-in-loop-suspect-seedable iff the closure pass
    stamped it `enumset_remove_in_loop_suspect == True` (the value-flow's
    source/sink fn - or an intermediate hop - has a FORWARD loop that reads
    `<coll>.at(i)` AND `<coll>.remove(...)` on the SAME collection while the counter
    advances monotonically, so the swapped-in element is skipped).

    Honest filter (R80): degraded records and heuristic-confidence records never
    seed. Guard-INDEPENDENT lead (an iteration-skip is a functional break whether or
    not the path is access-guarded), so `unguarded` is not consulted here.
    """
    if not isinstance(path, dict):
        return False
    if path.get("degraded"):
        return False
    if path.get("confidence") == "heuristic":
        return False
    return path.get("enumset_remove_in_loop_suspect") is True


def gen_enumset_remove_in_loop_questions(suspect_paths: list) -> list[dict]:
    """Emit ONE iteration-skip hacker-question per ENUMERABLESET REMOVE-IN-LOOP
    DefUsePath.

    The question is anchored at the `remove` `file:line`, names the collection, and
    carries enumset_remove_in_loop_suspect=True + dataflow_path_id so the ranker can
    boost it and the hunter brief can attach the path context. R76: anchors taken
    verbatim from the slice; the hunter is told to verify at source. This is a LEAD,
    never a finding.

    Default-off: an empty suspect_paths list yields [].
    """
    out: list[dict] = []
    for path in suspect_paths:
        src = path.get("source") or {}
        sink = path.get("sink") or {}
        er = path.get("enumset_remove_in_loop") or {}
        sink_fn = (sink.get("fn") or "").strip()
        src_fn = (src.get("fn") or "").strip()
        collection = er.get("collection") or "set"
        loop_line = er.get("loop_line")
        at_line = er.get("at_line")
        remove_line = er.get("remove_line")
        at_fn = er.get("at_fn") or "?"
        at_end_label = er.get("at_end") or "source"
        er_end = src if at_end_label == "source" else sink
        er_file = er_end.get("file") or "?"
        anchor_fn = (sink_fn or src_fn or "?")
        # Anchor at the remove file:line (the load-bearing mutation site).
        remove_anchor = (f"{er_file}:{remove_line}"
                         if remove_line is not None else er_file)
        loop_anchor = (f"{er_file}:{loop_line}"
                       if loop_line is not None else er_file)
        at_anchor = (f"{er_file}:{at_line}"
                     if at_line is not None else er_file)
        sink_kind = sink.get("kind") or "collection-mutator"
        sink_callee = sink.get("callee") or sink.get("var") or sink_kind
        path_id = path.get("path_id") or "dfp-?"
        q = (
            f"Data-flow slice {path_id}: function `{at_fn}` runs a FORWARD loop "
            f"@ {loop_anchor} that reads `{collection}.at(i)` ({at_anchor}) AND "
            f"calls `{collection}.remove(...)` ({remove_anchor}) on the SAME "
            f"collection while the counter increments. EnumerableSet.remove swaps "
            f"the LAST element into slot `i`, so the swapped-in element is SKIPPED "
            f"(iteration-skip): some `{collection}` entries are silently never "
            f"processed - a partial clear-all / unhandled-state correctness break. "
            f"Confirm at source per R76 first (read the actual loop: verify the "
            f"counter advances forward, that `.at(i)` indexes by that counter, and "
            f"that `.remove` mutates the SAME `{collection}`; a backward `i--` loop "
            f"is the safe pattern and is NOT a bug)."
        )
        rec = {
            "schema_version": SCHEMA,
            "function": anchor_fn,
            "file": remove_anchor,
            "language": path.get("language", "?"),
            "anchor_invariant": f"enumset-remove-in-loop:{path_id}",
            "question": q,
            "question_class": "enumerable-set-remove-in-loop",
            "question_source": "flow-seeded-enumset-remove-in-loop",
            "flow_seeded": True,
            "enumset_remove_in_loop_suspect": True,
            "dataflow_path_id": path_id,
            "flow_source_fn": src_fn,
            "flow_sink_fn": sink_fn,
            "flow_sink_kind": sink_kind,
            "enumset_collection": collection,
            "enumset_loop_anchor": loop_anchor,
            "enumset_at_anchor": at_anchor,
            "enumset_remove_anchor": remove_anchor,
            "flow_confidence": path.get("confidence", ""),
        }
        # Edge (R38): additive canonical iteration-skip class (verbatim-matched;
        # omitted when no canonical class exists - never invented).
        # `protocol-invariant-bypass` is live in the corpus today.
        ac = _suggest_enumset_remove_in_loop_attack_class(sink_kind, sink_callee)
        if ac:
            rec["attack_class"] = ac
            rec["attack_class_provenance"] = "dataflow_enumset_remove_in_loop_suspect"
        out.append(rec)
    return out


def _suggest_unchecked_return_attack_class(sink_kind: str, callee: str | None):
    """Map an UNCHECKED-RETURN-VALUE path (Glider gap W6 P1) -> a CANONICAL
    silent-failure attack class (verbatim-matched against the taxonomy, omitted
    when none exists - R38). ADDITIVE: callers tag
    provenance="dataflow_unchecked_return_value_suspect". NOTE: none of the
    candidate classes exists in the corpus today, so this returns None (honest -
    no fabrication); the I1 question + annotation still fire, so this is NOT an
    orphan. It auto-lights-up if the corpus later adds one of the candidates."""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "dataflow_attack_class",
            str(AUDITOOOR_ROOT / "tools" / "lib" / "dataflow_attack_class.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
    except Exception:
        return None
    try:
        return mod.suggest_unchecked_return_attack_class(sink_kind, callee=callee)
    except Exception:
        return None


def _flow_path_is_unchecked_return_value_suspect(path: dict) -> bool:
    """A DefUsePath is unchecked-return-value-suspect-seedable iff the closure pass
    stamped it `unchecked_return_value_suspect == True` (the value-flow's
    source/sink fn - or an intermediate hop in its forward callee closure - makes a
    transfer / transferFrom / .call / .send / delegatecall whose boolean success
    RETURN value is never consumed by a require/assert/if-revert/return/read).

    Honest filter (R80): degraded records and heuristic-confidence records never
    seed. Guard-INDEPENDENT lead (a silently-dropped failure is a correctness break
    whether or not the path is access-guarded), so `unguarded` is not consulted.
    """
    if not isinstance(path, dict):
        return False
    if path.get("degraded"):
        return False
    if path.get("confidence") == "heuristic":
        return False
    return path.get("unchecked_return_value_suspect") is True


def gen_unchecked_return_questions(suspect_paths: list) -> list[dict]:
    """Emit ONE unchecked-return-value hacker-question per UNCHECKED-RETURN-VALUE
    DefUsePath.

    The question is anchored at the call `file:line`, names the callee + kind, and
    carries unchecked_return_value_suspect=True + dataflow_path_id so the ranker can
    boost it and the hunter brief can attach the path context. R76: anchors taken
    verbatim from the slice; the hunter is told to verify at source. This is a LEAD,
    never a finding.

    Default-off: an empty suspect_paths list yields [].
    """
    out: list[dict] = []
    for path in suspect_paths:
        src = path.get("source") or {}
        sink = path.get("sink") or {}
        ur = path.get("unchecked_return_value") or {}
        sink_fn = (sink.get("fn") or "").strip()
        src_fn = (src.get("fn") or "").strip()
        callee = ur.get("callee") or "transfer"
        kind = ur.get("kind") or "transfer"
        call_line = ur.get("call_line")
        at_fn = ur.get("at_fn") or "?"
        at_end_label = ur.get("at_end") or "source"
        ur_end = src if at_end_label == "source" else sink
        ur_file = ur_end.get("file") or "?"
        anchor_fn = (sink_fn or src_fn or "?")
        # Anchor at the call file:line (the load-bearing unconsumed-return site).
        call_anchor = (f"{ur_file}:{call_line}"
                       if call_line is not None else ur_file)
        sink_kind = sink.get("kind") or "external-call"
        sink_callee = sink.get("callee") or sink.get("var") or callee
        path_id = path.get("path_id") or "dfp-?"
        q = (
            f"Data-flow slice {path_id}: function `{at_fn}` calls "
            f"`{callee}(...)` ({kind}) @ {call_anchor} but NEVER consumes its "
            f"boolean success RETURN value (no require/assert/if-revert/return "
            f"reads it). On a callee that returns false on failure (a standard "
            f"non-reverting ERC20 `transfer`/`transferFrom`, or a `.call`/`.send`/"
            f"`delegatecall` to a reverting/empty target) the failure is SILENTLY "
            f"swallowed and execution continues as if the call succeeded "
            f"(unchecked-return-value). Confirm at source per R76 first (read the "
            f"actual call: verify the bool result is truly discarded, that the "
            f"callee is not a revert-on-failure token, and that no SafeERC20 "
            f"wrapper or downstream guard consumes it; an `address.transfer` that "
            f"reverts itself is NOT a bug)."
        )
        rec = {
            "schema_version": SCHEMA,
            "function": anchor_fn,
            "file": call_anchor,
            "language": path.get("language", "?"),
            "anchor_invariant": f"unchecked-return-value:{path_id}",
            "question": q,
            "question_class": "unchecked-return-value",
            "question_source": "flow-seeded-unchecked-return-value",
            "flow_seeded": True,
            "unchecked_return_value_suspect": True,
            "dataflow_path_id": path_id,
            "flow_source_fn": src_fn,
            "flow_sink_fn": sink_fn,
            "flow_sink_kind": sink_kind,
            "unchecked_return_callee": callee,
            "unchecked_return_kind": kind,
            "unchecked_return_call_anchor": call_anchor,
            "flow_confidence": path.get("confidence", ""),
        }
        # Edge (R38): additive canonical silent-failure class (verbatim-matched;
        # omitted when no canonical class exists - never invented). The candidate
        # classes do not exist in the corpus today, so this is None (honest).
        ac = _suggest_unchecked_return_attack_class(sink_kind, sink_callee)
        if ac:
            rec["attack_class"] = ac
            rec["attack_class_provenance"] = "dataflow_unchecked_return_value_suspect"
        out.append(rec)
    return out


def _suggest_logic_tautology_attack_class(sink_kind: str, callee: str | None):
    """Map a LOGIC-TAUTOLOGY / DEAD-COMPARISON path (Glider gap W6 P2) -> a
    CANONICAL access-control attack class (verbatim-matched against the taxonomy,
    omitted when none exists - R38). ADDITIVE: callers tag
    provenance="dataflow_logic_tautology_suspect"."""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "dataflow_attack_class",
            str(AUDITOOOR_ROOT / "tools" / "lib" / "dataflow_attack_class.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
    except Exception:
        return None
    try:
        return mod.suggest_logic_tautology_attack_class(sink_kind, callee=callee)
    except Exception:
        return None


def _flow_path_is_logic_tautology_suspect(path: dict) -> bool:
    """A DefUsePath is logic-tautology-suspect-seedable iff the closure pass
    stamped it `logic_tautology_suspect == True` (the value-flow's source/sink
    fn - or an intermediate closure hop - contains a guard whose BOOLEAN LOGIC
    is broken: either an always-true OR tautology or a dead comparison whose
    result is discarded).

    Honest filter (R80): degraded records and heuristic-confidence records never
    seed. Guard-logic lead (the guard is present but broken), so this seeds
    regardless of the path's own `unguarded` flag - the slice-local pass may
    have seen the guard without recognizing that its logic is vacuous.
    """
    if not isinstance(path, dict):
        return False
    if path.get("degraded"):
        return False
    if path.get("confidence") == "heuristic":
        return False
    return path.get("logic_tautology_suspect") is True


def gen_logic_tautology_questions(suspect_paths: list) -> list[dict]:
    """Emit ONE logic-tautology/dead-comparison hacker-question per
    LOGIC-TAUTOLOGY-SUSPECT DefUsePath.

    The question is anchored at the broken guard's file:line, names the kind
    (always-true-or or dead-comparison), and carries
    logic_tautology_suspect=True + dataflow_path_id so the ranker can boost it
    and the hunter brief can attach the path context. R76: anchors taken
    verbatim from the slice; the hunter is told to verify at source.
    question_class is "broken-access-control-logic". This is a LEAD, never a
    finding.

    Default-off: an empty suspect_paths list yields []. NOTE: no question is
    emitted when the slice record is absent (the function has no DefUsePath).
    """
    out: list[dict] = []
    for path in suspect_paths:
        src = path.get("source") or {}
        sink = path.get("sink") or {}
        lt = path.get("logic_tautology") or {}
        sink_fn = (sink.get("fn") or "").strip()
        src_fn = (src.get("fn") or "").strip()
        kind = lt.get("kind") or "unknown"
        at_line = lt.get("at_line")
        contract = lt.get("contract") or ""
        function = lt.get("function") or sink_fn or src_fn or "?"
        expr = lt.get("expr") or ""
        caller_name = lt.get("caller_name") or "msg.sender"
        op = lt.get("op") or ""
        # Anchor at the source-end's file if kind is dead-comparison; at the
        # sink-end if kind is always-true-or (the guard is usually at the entry
        # side). Fall back to sink file.
        guard_file = src.get("file") or sink.get("file") or "?"
        guard_anchor = f"{guard_file}:{at_line}" if at_line is not None else guard_file
        sink_kind = sink.get("kind") or "value-mover"
        sink_callee = sink.get("callee") or sink.get("var") or sink_kind
        path_id = path.get("path_id") or "dfp-?"
        if kind == "always-true-or":
            q = (
                f"Data-flow slice {path_id}: `{contract}.{function}` has an "
                f"ALWAYS-TRUE access guard @ {guard_anchor}: "
                f"`{expr}`. The OR of two NOT-EQUAL comparisons on the same "
                f"caller identity (`{caller_name}`) is always satisfied (no "
                f"address can simultaneously equal both bounds), nullifying the "
                f"access check. Any caller passes this guard trivially. Was "
                f"`&&` intended instead of `||`? Verify the guard logic at "
                f"source per R76, confirm the expression is as shown, and check "
                f"whether an unprivileged caller can reach the value-moving / "
                f"state-changing effect that the guard was supposed to protect."
            )
        else:
            q = (
                f"Data-flow slice {path_id}: `{contract}.{function}` has a "
                f"DEAD comparison @ {guard_anchor}: "
                f"`{expr}`. The `{op}` result is discarded (not wrapped in "
                f"require/assert/if), so the intended access check is never "
                f"enforced. Any caller proceeds past this point regardless of "
                f"the comparison outcome. Verify at source per R76 that the "
                f"expression is as shown and confirm whether a "
                f"`require({expr})` was intended. Check if an unprivileged "
                f"caller can reach the value-moving / state-changing effect "
                f"the missing guard was supposed to protect."
            )
        rec = {
            "schema_version": SCHEMA,
            "function": function,
            "file": guard_anchor,
            "language": path.get("language", "?"),
            "anchor_invariant": f"logic-tautology:{path_id}",
            "question": q,
            "question_class": "broken-access-control-logic",
            "question_source": "flow-seeded-logic-tautology",
            "flow_seeded": True,
            "logic_tautology_suspect": True,
            "dataflow_path_id": path_id,
            "flow_source_fn": src_fn,
            "flow_sink_fn": sink_fn,
            "flow_sink_kind": sink_kind,
            "logic_tautology_kind": kind,
            "logic_tautology_anchor": guard_anchor,
            "flow_confidence": path.get("confidence", ""),
        }
        # Additive canonical access-control class (verbatim-matched; omitted
        # when no canonical class exists - never invented). `access-control` is
        # live in the corpus today.
        ac = _suggest_logic_tautology_attack_class(sink_kind, sink_callee)
        if ac:
            rec["attack_class"] = ac
            rec["attack_class_provenance"] = "dataflow_logic_tautology_suspect"
        out.append(rec)
    return out


def _suggest_override_dropped_guard_attack_class(sink_kind: str, callee: str | None):
    """Map an OVERRIDE-DROPPED-GUARD path (Glider gap W1) -> a CANONICAL
    access-control attack class (verbatim-matched against the taxonomy, omitted
    when none exists - R38). ADDITIVE: callers tag
    provenance="dataflow_override_dropped_guard_suspect"."""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "dataflow_attack_class",
            str(AUDITOOOR_ROOT / "tools" / "lib" / "dataflow_attack_class.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
    except Exception:
        return None
    try:
        return mod.suggest_override_dropped_guard_attack_class(sink_kind, callee=callee)
    except Exception:
        return None


def _flow_path_is_override_dropped_guard_suspect(path: dict) -> bool:
    """A DefUsePath is override-dropped-guard-suspect-seedable iff the closure pass
    stamped it `override_dropped_guard_suspect == True` (the value-flow's
    source/sink fn is a concrete override whose base version enforced a
    caller-identity access-control guard that the override DROPPED).

    Honest filter (R80): degraded records and heuristic-confidence records never
    seed. Guard-state lead (the override now runs unguarded), so this seeds
    regardless of the path's own `unguarded` flag - the slice-local pass may have
    seen the post-drop state without recognizing the dropped base guard.
    """
    if not isinstance(path, dict):
        return False
    if path.get("degraded"):
        return False
    if path.get("confidence") == "heuristic":
        return False
    return path.get("override_dropped_guard_suspect") is True


def gen_override_dropped_guard_questions(suspect_paths: list) -> list[dict]:
    """Emit ONE override-dropped-guard hacker-question per OVERRIDE-DROPPED-GUARD
    DefUsePath.

    The question is anchored at the override's declaration `file:line`, names the
    base contract + the dropped guard, and carries
    override_dropped_guard_suspect=True + dataflow_path_id so the ranker can boost
    it and the hunter brief can attach the path context. R76: anchors taken
    verbatim from the slice; the hunter is told to verify at source. This is a
    LEAD, never a finding.

    Default-off: an empty suspect_paths list yields [].
    """
    out: list[dict] = []
    for path in suspect_paths:
        src = path.get("source") or {}
        sink = path.get("sink") or {}
        odg = path.get("override_dropped_guard") or {}
        sink_fn = (sink.get("fn") or "").strip()
        src_fn = (src.get("fn") or "").strip()
        contract = odg.get("contract") or "?"
        function = odg.get("function") or sink_fn or src_fn or "?"
        base_contract = odg.get("base_contract") or "?"
        base_fn = odg.get("base_fn") or function
        dropped = odg.get("dropped_guard") or "an access-control guard"
        at_file = odg.get("at_file") or "?"
        at_line = odg.get("at_line")
        drop_anchor = (f"{at_file}:{at_line}" if at_line is not None else at_file)
        sink_kind = sink.get("kind") or "value-mover"
        sink_callee = sink.get("callee") or sink.get("var") or sink_kind
        path_id = path.get("path_id") or "dfp-?"
        q = (
            f"Data-flow slice {path_id}: `{contract}.{function}` OVERRIDES "
            f"`{base_contract}.{base_fn}` but DROPS the base guard "
            f"`{dropped}` @ {drop_anchor} - the concrete dispatch target now runs "
            f"with NO caller-identity check, while the base version enforced one. "
            f"Can an unprivileged caller invoke `{contract}.{function}` directly to "
            f"reach the value-moving / state-changing effect the base guard "
            f"protected (an access-control bypass via a dropped override guard)? "
            f"Confirm at source per R76 first (read the override body and the base "
            f"version; verify the override re-adds no equivalent guard under a "
            f"different name and moves none into a forward callee)."
        )
        rec = {
            "schema_version": SCHEMA,
            "function": function,
            "file": drop_anchor,
            "language": path.get("language", "?"),
            "anchor_invariant": f"override-dropped-guard:{path_id}",
            "question": q,
            "question_class": "override-dropped-guard",
            "question_source": "flow-seeded-override-dropped-guard",
            "flow_seeded": True,
            "override_dropped_guard_suspect": True,
            "dataflow_path_id": path_id,
            "flow_source_fn": src_fn,
            "flow_sink_fn": sink_fn,
            "flow_sink_kind": sink_kind,
            "override_dropped_guard_contract": contract,
            "override_dropped_guard_base_contract": base_contract,
            "override_dropped_guard_dropped": dropped,
            "override_dropped_guard_anchor": drop_anchor,
            "flow_confidence": path.get("confidence", ""),
        }
        # Additive canonical access-control class (verbatim-matched; omitted when
        # no canonical class exists - never invented). `access-control` is live in
        # the corpus today.
        ac = _suggest_override_dropped_guard_attack_class(sink_kind, sink_callee)
        if ac:
            rec["attack_class"] = ac
            rec["attack_class_provenance"] = "dataflow_override_dropped_guard_suspect"
        out.append(rec)
    return out


def _suggest_oracle_swallow_attack_class(sink_kind: str, callee: str | None):
    """Map an ORACLE TRY/CATCH-SWALLOW path (Glider gap W2) -> a CANONICAL
    stale-oracle attack class (verbatim-matched against the taxonomy, omitted when
    none exists - R38). ADDITIVE: callers tag
    provenance="dataflow_oracle_swallow_suspect"."""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "dataflow_attack_class",
            str(AUDITOOOR_ROOT / "tools" / "lib" / "dataflow_attack_class.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
    except Exception:
        return None
    try:
        return mod.suggest_oracle_swallow_attack_class(sink_kind, callee=callee)
    except Exception:
        return None


def _flow_path_is_oracle_swallow_suspect(path: dict) -> bool:
    """A DefUsePath is oracle-swallow-suspect-seedable iff the closure pass stamped
    it `oracle_swallow_suspect == True` (the value-flow's source/sink fn - or an
    intermediate closure hop - wraps an ORACLE / price read in a try whose catch
    SWALLOWS the failure, so execution proceeds on a stale/zero/default value).

    Honest filter (R80): degraded records and heuristic-confidence records never
    seed. Failure-handling lead (the function proceeds on a stale value), so this
    seeds regardless of the path's own `unguarded` flag.
    """
    if not isinstance(path, dict):
        return False
    if path.get("degraded"):
        return False
    if path.get("confidence") == "heuristic":
        return False
    return path.get("oracle_swallow_suspect") is True


def gen_oracle_swallow_questions(suspect_paths: list) -> list[dict]:
    """Emit ONE oracle-try/catch-swallow hacker-question per ORACLE-SWALLOW
    DefUsePath.

    The question is anchored at the catch clause's `file:line`, names the oracle
    callee, and carries oracle_swallow_suspect=True + dataflow_path_id so the
    ranker can boost it and the hunter brief can attach the path context. R76:
    anchors taken verbatim from the slice; the hunter is told to verify at source.
    This is a LEAD, never a finding.

    Default-off: an empty suspect_paths list yields [].
    """
    out: list[dict] = []
    for path in suspect_paths:
        src = path.get("source") or {}
        sink = path.get("sink") or {}
        osw = path.get("oracle_swallow") or {}
        sink_fn = (sink.get("fn") or "").strip()
        src_fn = (src.get("fn") or "").strip()
        contract = osw.get("contract") or "?"
        function = osw.get("function") or sink_fn or src_fn or "?"
        oracle_callee = osw.get("oracle_callee") or "an oracle read"
        at_file = osw.get("at_file") or "?"
        catch_line = osw.get("catch_line")
        try_line = osw.get("try_line")
        swallow_anchor = (f"{at_file}:{catch_line}" if catch_line is not None else at_file)
        sink_kind = sink.get("kind") or "value-mover"
        sink_callee = sink.get("callee") or sink.get("var") or sink_kind
        path_id = path.get("path_id") or "dfp-?"
        q = (
            f"Data-flow slice {path_id}: `{contract}.{function}` wraps the oracle "
            f"read `{oracle_callee}()` (try @ line {try_line}) in a try whose CATCH "
            f"@ {swallow_anchor} SWALLOWS the failure (no revert / no re-throw / no "
            f"subsequent validating require) - on an oracle revert the function "
            f"proceeds with a STALE, zero, or default price/value. Can an attacker "
            f"force the oracle call to revert (or otherwise induce the catch path) "
            f"so the downstream value-moving logic transacts on a stale/zero price "
            f"(an oracle-failure-ignored / stale-price bug)? Confirm at source per "
            f"R76 first (read the catch body and what the post-try code does with "
            f"the value; verify the catch sets no fallback that a later require "
            f"validates)."
        )
        rec = {
            "schema_version": SCHEMA,
            "function": function,
            "file": swallow_anchor,
            "language": path.get("language", "?"),
            "anchor_invariant": f"oracle-trycatch-swallow:{path_id}",
            "question": q,
            "question_class": "oracle-trycatch-swallow",
            "question_source": "flow-seeded-oracle-swallow",
            "flow_seeded": True,
            "oracle_swallow_suspect": True,
            "dataflow_path_id": path_id,
            "flow_source_fn": src_fn,
            "flow_sink_fn": sink_fn,
            "flow_sink_kind": sink_kind,
            "oracle_swallow_contract": contract,
            "oracle_swallow_callee": oracle_callee,
            "oracle_swallow_anchor": swallow_anchor,
            "flow_confidence": path.get("confidence", ""),
        }
        # Additive canonical stale-oracle class (verbatim-matched; omitted when no
        # canonical class exists - never invented). `stale-or-manipulated-oracle`
        # is live in the corpus today.
        ac = _suggest_oracle_swallow_attack_class(sink_kind, sink_callee)
        if ac:
            rec["attack_class"] = ac
            rec["attack_class_provenance"] = "dataflow_oracle_swallow_suspect"
        out.append(rec)
    return out


def _suggest_memory_copy_no_writeback_attack_class(sink_kind: str, callee: str | None):
    """Map a MEMORY-COPY-NO-WRITEBACK path (Glider gap W6 P8) -> a CANONICAL
    lost-state-update / incorrect-state-tracking attack class (verbatim-matched
    against the taxonomy, omitted when none exists - R38). ADDITIVE: callers tag
    provenance="dataflow_memory_copy_no_writeback_suspect". NOTE: the candidate
    classes are checked against the corpus; if none are present today, this returns
    None (honest - no fabrication); the I1 question + annotation still fire, so this
    is NOT an orphan. It auto-lights-up if the corpus later adds one of the
    candidates."""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "dataflow_attack_class",
            str(AUDITOOOR_ROOT / "tools" / "lib" / "dataflow_attack_class.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
    except Exception:
        return None
    try:
        return mod.suggest_memory_copy_no_writeback_attack_class(sink_kind, callee=callee)
    except Exception:
        return None


def _flow_path_is_memory_copy_no_writeback_suspect(path: dict) -> bool:
    """A DefUsePath is memory-copy-no-writeback-suspect-seedable iff the closure
    pass stamped it `memory_copy_no_writeback_suspect == True` (the value-flow's
    source/sink fn reads a storage state-var into a MEMORY local, mutates the local,
    but NEVER writes the mutation back to the state var - the state update is
    silently lost).

    Honest filter (R80): degraded records and heuristic-confidence records never
    seed. Functional-correctness lead (lost state update is a bug regardless of
    access-control guards), so `unguarded` is not consulted.
    """
    if not isinstance(path, dict):
        return False
    if path.get("degraded"):
        return False
    if path.get("confidence") == "heuristic":
        return False
    return path.get("memory_copy_no_writeback_suspect") is True


def gen_memory_copy_no_writeback_questions(suspect_paths: list) -> list[dict]:
    """Emit ONE memory-copy-no-writeback hacker-question per
    MEMORY-COPY-NO-WRITEBACK DefUsePath.

    The question is anchored at the mutation `file:line` (the load-bearing site
    where the developer intended a state update but the memory copy means it is
    lost), names the state variable + local copy, and carries
    memory_copy_no_writeback_suspect=True + dataflow_path_id so the ranker can
    boost it and the hunter brief can attach the path context. R76: anchors taken
    verbatim from the slice; the hunter is told to verify at source. This is a
    LEAD, never a finding.

    Default-off: an empty suspect_paths list yields [].
    "no question when slice absent" contract: this function is only called when
    the slice contains at least one memory_copy_no_writeback_suspect path; an
    empty list produces no output (loop simply does not iterate).
    """
    out: list[dict] = []
    for path in suspect_paths:
        src = path.get("source") or {}
        sink = path.get("sink") or {}
        mc = path.get("memory_copy_no_writeback") or {}
        sink_fn = (sink.get("fn") or "").strip()
        src_fn = (src.get("fn") or "").strip()
        state_var = mc.get("state_var") or "storageVar"
        local_var = mc.get("local") or "localCopy"
        copy_line = mc.get("copy_line")
        mutate_line = mc.get("mutate_line")
        at_fn = mc.get("at_fn") or "?"
        at_end_label = mc.get("at_end") or "source"
        mc_end = src if at_end_label == "source" else sink
        mc_file = mc_end.get("file") or "?"
        anchor_fn = (sink_fn or src_fn or "?")
        # Anchor at the mutation site (the load-bearing lost-write site).
        mutate_anchor = (f"{mc_file}:{mutate_line}"
                         if mutate_line is not None else mc_file)
        copy_anchor = (f"{mc_file}:{copy_line}"
                       if copy_line is not None else mc_file)
        sink_kind = sink.get("kind") or "state-mutator"
        sink_callee = sink.get("callee") or sink.get("var") or sink_kind
        path_id = path.get("path_id") or "dfp-?"
        q = (
            f"Data-flow slice {path_id}: function `{at_fn}` copies storage "
            f"variable `{state_var}` into a MEMORY local `{local_var}` @ "
            f"{copy_anchor}, then MUTATES `{local_var}` @ {mutate_anchor}, "
            f"but the function NEVER writes `{local_var}` back to `{state_var}`. "
            f"Because `{local_var}` is a memory copy (not a storage pointer), the "
            f"mutation is SILENTLY DISCARDED when the function returns - the "
            f"intended state update is lost (lost-state-update). "
            f"Verify at source per R76: confirm `{local_var}` is declared "
            f"`memory` (not `storage`), that the mutation is non-trivial, and that "
            f"no later assignment `{state_var} = {local_var}` (or direct field "
            f"write to `{state_var}`) appears in this function. A `storage` "
            f"pointer writes through automatically and is NOT a bug."
        )
        rec = {
            "schema_version": SCHEMA,
            "function": anchor_fn,
            "file": mutate_anchor,
            "language": path.get("language", "?"),
            "anchor_invariant": f"memory-copy-no-writeback:{path_id}",
            "question": q,
            "question_class": "lost-state-update",
            "question_source": "flow-seeded-memory-copy-no-writeback",
            "flow_seeded": True,
            "memory_copy_no_writeback_suspect": True,
            "dataflow_path_id": path_id,
            "flow_source_fn": src_fn,
            "flow_sink_fn": sink_fn,
            "flow_sink_kind": sink_kind,
            "mem_copy_state_var": state_var,
            "mem_copy_local": local_var,
            "mem_copy_copy_anchor": copy_anchor,
            "mem_copy_mutate_anchor": mutate_anchor,
            "flow_confidence": path.get("confidence", ""),
        }
        # Edge (R38): additive canonical lost-state-update class (verbatim-matched;
        # omitted when no canonical class exists - never invented).
        ac = _suggest_memory_copy_no_writeback_attack_class(sink_kind, sink_callee)
        if ac:
            rec["attack_class"] = ac
            rec["attack_class_provenance"] = "dataflow_memory_copy_no_writeback_suspect"
        out.append(rec)
    return out


def _suggest_two_step_accept_wrong_guard_attack_class(
        sink_kind: str, callee: str | None):
    """Map a TWO-STEP-ACCEPT-WRONG-GUARD path -> a CANONICAL access-control class
    (verbatim-matched against the taxonomy, omitted when none exists - R38).
    provenance="dataflow_two_step_accept_wrong_guard_suspect"."""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "dataflow_attack_class",
            str(AUDITOOOR_ROOT / "tools" / "lib" / "dataflow_attack_class.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
    except Exception:
        return None
    try:
        return mod.suggest_two_step_accept_wrong_guard_attack_class(
            sink_kind, callee=callee)
    except Exception:
        return None


def _suggest_signature_replay_attack_class(sink_kind: str, callee: str | None):
    """Map a SIGNATURE-REPLAY path (Glider gap W6 P3) -> a CANONICAL replay
    attack class (verbatim-matched against the taxonomy, omitted when none exists
    - R38). ADDITIVE: callers tag
    provenance="dataflow_signature_replay_suspect"."""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "dataflow_attack_class",
            str(AUDITOOOR_ROOT / "tools" / "lib" / "dataflow_attack_class.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
    except Exception:
        return None
    try:
        return mod.suggest_signature_replay_attack_class(sink_kind, callee=callee)
    except Exception:
        return None


def _flow_path_is_two_step_accept_wrong_guard_suspect(path: dict) -> bool:
    """True when the dataflow closure-unguarded pass (apply_closure_unguarded)
    stamped it `two_step_accept_wrong_guard_suspect == True` (the value-flow's
    source or sink function is an accept/claim-ownership function gated by
    onlyOwner-family instead of checking the PENDING owner).

    This is the same gating predicate used by the unchecked-return, override-dropped-
    guard, and memory-copy-no-writeback consumers: filter first, then gen_*.
    Default-off: when the slice annotation is absent the filter returns False
    for all paths -> gen returns [] (no false positive question).
    """
    return path.get("two_step_accept_wrong_guard_suspect") is True


def gen_two_step_accept_wrong_guard_questions(suspect_paths: list) -> list[dict]:
    """Emit ONE two-step-accept-wrong-guard hacker-question per
    TWO-STEP-ACCEPT-WRONG-GUARD DefUsePath.

    The question is anchored at the `function` file:line, names the guard modifier,
    the pending var, and the ownership var, and carries
    two_step_accept_wrong_guard_suspect=True + dataflow_path_id so the ranker can
    boost it and the hunter brief can attach the path context. R76: anchors taken
    verbatim from the slice; the hunter is told to verify at source. This is a
    LEAD, never a finding.

    Default-off: an empty suspect_paths list yields [].
    "no question when slice absent" contract: this function is only called when
    the slice contains at least one two_step_accept_wrong_guard_suspect path; an
    empty list produces no output.
    """
    out: list[dict] = []
    for path in suspect_paths:
        src = path.get("source") or {}
        sink = path.get("sink") or {}
        tsawg = path.get("two_step_accept_wrong_guard") or {}
        sink_fn = (sink.get("fn") or "").strip()
        src_fn = (src.get("fn") or "").strip()
        fn_name = tsawg.get("function") or "?"
        contract_name = tsawg.get("contract") or "?"
        guard_mod = tsawg.get("guard_modifier") or "onlyOwner"
        pending_var = tsawg.get("pending_var") or "pendingOwner"
        ownership_var = tsawg.get("ownership_var") or "owner"
        at_line = tsawg.get("at_line")
        at_end_label = path.get("closure_note", "")
        # Determine which path-end the annotation came from.
        if "source" in at_end_label.lower() and src.get("file"):
            anchor_file = src.get("file") or "?"
        else:
            anchor_file = sink.get("file") or src.get("file") or "?"
        anchor_fn = (sink_fn or src_fn or fn_name or "?")
        anchor = (f"{anchor_file}:{at_line}" if at_line is not None else anchor_file)
        sink_kind = sink.get("kind") or "authority"
        sink_callee = sink.get("callee") or sink.get("var") or sink_kind
        path_id = path.get("path_id") or "dfp-?"
        q = (
            f"Data-flow slice {path_id}: function `{fn_name}` on contract "
            f"`{contract_name}` ({anchor}) is a two-step ownership-accept function "
            f"(named accept/claim-ownership/admin) gated by modifier `{guard_mod}` "
            f"which checks the CURRENT `{ownership_var}` - the WRONG guard. The "
            f"CORRECT guard for an accept-ownership function is "
            f"`require(msg.sender == {pending_var})` (checking the PENDING owner). "
            f"With the current guard: (a) the pending owner `{pending_var}` can "
            f"NEVER call `{fn_name}` (the require reverts for any address that is "
            f"not the current `{ownership_var}`), OR (b) the current owner can "
            f"bypass the two-step and forcibly self-assign (privilege escalation). "
            f"Verify at source per R76: confirm `{fn_name}` is in scope, that "
            f"`{pending_var}` is the two-step pending-owner variable, that the "
            f"modifier `{guard_mod}` checks the CURRENT owner rather than "
            f"`{pending_var}`, and that NO separate `require(msg.sender == "
            f"{pending_var})` check exists anywhere in the function body."
        )
        rec = {
            "schema_version": SCHEMA,
            "function": anchor_fn,
            "file": anchor,
            "language": path.get("language", "?"),
            "anchor_invariant": f"two-step-accept-wrong-guard:{path_id}",
            "question": q,
            "question_class": "access-control",
            "question_source": "flow-seeded-two-step-accept-wrong-guard",
            "flow_seeded": True,
            "two_step_accept_wrong_guard_suspect": True,
            "dataflow_path_id": path_id,
            "flow_source_fn": src_fn,
            "flow_sink_fn": sink_fn,
            "flow_sink_kind": sink_kind,
            "tsawg_contract": contract_name,
            "tsawg_function": fn_name,
            "tsawg_guard_modifier": guard_mod,
            "tsawg_pending_var": pending_var,
            "tsawg_ownership_var": ownership_var,
            "tsawg_anchor": anchor,
            "flow_confidence": path.get("confidence", ""),
        }
        # Edge (R38): additive canonical access-control class (verbatim-matched;
        # omitted when no canonical class exists - never invented). `access-control`
        # IS in the corpus today and faithfully describes the wrong-guard gap.
        ac = _suggest_two_step_accept_wrong_guard_attack_class(sink_kind, sink_callee)
        if ac:
            rec["attack_class"] = ac
            rec["attack_class_provenance"] = "dataflow_two_step_accept_wrong_guard_suspect"
        out.append(rec)
    return out


def _flow_path_is_signature_replay_suspect(path: dict) -> bool:
    """A DefUsePath is signature-replay-suspect-seedable iff the closure pass
    stamped it `signature_replay_suspect == True` (the value-flow's source/sink
    fn - or an intermediate hop in its forward callee closure - calls ecrecover
    without a per-signer/per-message nonce write (missing-nonce) or without
    block.chainid in the digest (missing-chainid)).

    Honest filter (R80): degraded records and heuristic-confidence records never
    seed. Guard-INDEPENDENT lead (a replayable signature is a bug regardless of
    the path's access-control guard status), so `unguarded` is not consulted.
    """
    if not isinstance(path, dict):
        return False
    if path.get("degraded"):
        return False
    if path.get("confidence") == "heuristic":
        return False
    return path.get("signature_replay_suspect") is True


def gen_signature_replay_questions(suspect_paths: list) -> list[dict]:
    """Emit ONE signature-replay hacker-question per SIGNATURE-REPLAY-SUSPECT
    DefUsePath.

    The question is anchored at the ecrecover `file:line`, names the sub-rule
    kind (missing-nonce or missing-chainid), and carries
    signature_replay_suspect=True + dataflow_path_id so the ranker can boost it
    and the hunter brief can attach the path context. R76: anchors taken verbatim
    from the slice; the hunter is told to verify at source. This is a LEAD, never
    a finding.

    Default-off: an empty suspect_paths list yields [].
    "no question when slice absent" contract: this function is only called when the
    slice contains at least one signature_replay_suspect path; an empty list
    produces no output (loop simply does not iterate).
    """
    out: list[dict] = []
    for path in suspect_paths:
        src = path.get("source") or {}
        sink = path.get("sink") or {}
        sr = path.get("signature_replay") or {}
        sink_fn = (sink.get("fn") or "").strip()
        src_fn = (src.get("fn") or "").strip()
        kind = sr.get("kind") or "missing-nonce"
        ecrecover_line = sr.get("ecrecover_line")
        at_fn = sr.get("at_fn") or "?"
        at_end_label = sr.get("at_end") or "source"
        sr_end = src if at_end_label == "source" else sink
        sr_file = sr_end.get("file") or "?"
        anchor_fn = (sink_fn or src_fn or "?")
        # Anchor at the ecrecover call site (the load-bearing verification point).
        ecrecover_anchor = (f"{sr_file}:{ecrecover_line}"
                            if ecrecover_line is not None else sr_file)
        sink_kind = sink.get("kind") or "sig-verifier"
        sink_callee = sink.get("callee") or sink.get("var") or sink_kind
        path_id = path.get("path_id") or "dfp-?"
        if kind == "missing-nonce":
            q = (
                f"Data-flow slice {path_id}: function `{at_fn}` calls "
                f"`ecrecover(...)` @ {ecrecover_anchor} to verify a signature "
                f"but NEVER writes a per-signer or per-message nonce / used-hash "
                f"mapping (no `nonces[signer]++`, no `usedHashes[hash]=true`, no "
                f"similar replay-prevention storage write in the function or its "
                f"callee closure). A valid signature can therefore be submitted "
                f"MORE THAN ONCE on the same chain (same-chain signature replay). "
                f"Confirm at source per R76: read the actual function, verify that "
                f"no nonce-increment or used-hash marking is performed anywhere in "
                f"the call path (an EIP-712 domain separator alone does NOT prevent "
                f"replay - it must be paired with a per-message nonce or used-hash "
                f"flag that is SET after a successful verify)."
            )
        else:  # missing-chainid
            q = (
                f"Data-flow slice {path_id}: function `{at_fn}` calls "
                f"`ecrecover(...)` @ {ecrecover_anchor} to verify a signature "
                f"but the digest / hash argument is built WITHOUT reading "
                f"`block.chainid` anywhere in the function or its callee closure. "
                f"The same signed message is therefore valid on EVERY chain this "
                f"contract is deployed on (cross-chain signature replay / "
                f"permit-replay after a fork). "
                f"Confirm at source per R76: read the digest-construction path "
                f"(the keccak256 / abi.encode calls feeding the ecrecover hash "
                f"arg) and confirm that block.chainid (or a cached DOMAIN_SEPARATOR "
                f"that was computed WITH block.chainid) is genuinely absent; a "
                f"cached domain separator that INCLUDES chainid is NOT a bug."
            )
        rec = {
            "schema_version": SCHEMA,
            "function": anchor_fn,
            "file": ecrecover_anchor,
            "language": path.get("language", "?"),
            "anchor_invariant": f"signature-replay-{kind}:{path_id}",
            "question": q,
            "question_class": "signature-replay",
            "question_source": "flow-seeded-signature-replay",
            "flow_seeded": True,
            "signature_replay_suspect": True,
            "signature_replay_kind": kind,
            "dataflow_path_id": path_id,
            "flow_source_fn": src_fn,
            "flow_sink_fn": sink_fn,
            "flow_sink_kind": sink_kind,
            "sig_replay_ecrecover_anchor": ecrecover_anchor,
            "flow_confidence": path.get("confidence", ""),
        }
        # Edge (R38): additive canonical signature-replay class (verbatim-matched;
        # omitted when no canonical class exists - never invented).
        # `permit-signature-replay` IS in the corpus taxonomy today.
        ac = _suggest_signature_replay_attack_class(sink_kind, sink_callee)
        if ac:
            rec["attack_class"] = ac
            rec["attack_class_provenance"] = "dataflow_signature_replay_suspect"
        out.append(rec)
    return out


# Make tools/lib importable so the rubric parser (single source of truth) can be
# reused instead of re-implementing SEVERITY.md parsing here.
sys.path.insert(0, str(AUDITOOOR_ROOT / "tools"))
try:
    from lib.severity_rubric import (  # type: ignore
        TierRow,
        find_severity_md,
        parse_tier_rows,
    )
except Exception:  # pragma: no cover - lib should always be present in-tree
    TierRow = None  # type: ignore
    find_severity_md = None  # type: ignore
    parse_tier_rows = None  # type: ignore

# Tiers that pay out a bounty. A SEVERITY.md "Low" row is technically a row but
# the volume hunt should bias toward the classes the program actually pays for;
# all four canonical tiers are payable on most programs, so the default set is
# all-but-empty.  The mapping below converts a rubric sentence to the QUESTION
# TEMPLATE class keys used elsewhere in this file so a rubric-mapped question is
# tagged with the SAME question_class the ranker scores.
PAYABLE_TIERS = frozenset({"critical", "high", "medium", "low"})

# Keyword -> question_class map. Each rubric sentence is scanned for these
# substrings (lowercased) and the FIRST match wins; this lets a program's
# payable row ("incorrect withdrawal proven", "dispute game resolves wrong")
# pull the matching attack-template class so the per-fn hunt fires that class
# on relevant functions instead of staying generic on the rubric axis.
RUBRIC_SENTENCE_CLASS_MAP: list[tuple[str, str]] = [
    ("reentr", "reentrancy"),
    ("access control", "access-control-missing"),
    ("unauthor", "access-control-missing"),
    ("permission", "access-control-missing"),
    ("only owner", "access-control-missing"),
    ("onlyowner", "access-control-missing"),
    ("privileg", "access-control-missing"),
    ("conservation", "sum-preserved"),
    ("accounting", "sum-preserved"),
    ("insolven", "sum-preserved"),
    ("balance", "sum-preserved"),
    ("loss of funds", "sum-preserved"),
    ("loss of user", "sum-preserved"),
    ("drain", "sum-preserved"),
    ("steal", "sum-preserved"),
    ("theft", "sum-preserved"),
    ("withdraw", "sum-preserved"),
    ("deadline", "deadline-future"),
    ("stale", "deadline-future"),
    ("replay", "deadline-future"),
    ("origin", "origin-checked"),
    ("weight", "weight-bounded"),
    ("validatebasic", "msg-validatebasic"),
    ("validate basic", "msg-validatebasic"),
    ("ante", "ante-traversal"),
    ("nonce", "nonce-reuse"),
    ("constant time", "constant-time"),
    ("timing", "constant-time"),
    ("malleab", "malleability"),
    ("serializ", "serialization-roundtrip"),
    ("under-constrain", "under-constrained-signal"),
    ("under constrain", "under-constrained-signal"),
    ("soundness", "soundness"),
    ("proof", "soundness"),
    ("constrain", "under-constrained-signal"),
]


def map_rubric_sentence_to_class(sentence: str) -> str:
    """Map a payable rubric sentence to a question_class template key.

    Returns the matching template class key (e.g. 'sum-preserved') or
    'rubric-targeted' when no keyword matches - so EVERY payable row still
    yields a tagged, targeted question even when its phrasing is novel.
    """
    low = (sentence or "").lower()
    for kw, klass in RUBRIC_SENTENCE_CLASS_MAP:
        if kw in low:
            return klass
    return "rubric-targeted"


def load_payable_rubric_rows(severity_md: Path) -> list:
    """Parse SEVERITY.md and return the payable TierRow list (one per row).

    Returns [] (and the caller stays generic) if the parser is unavailable or
    the file is missing/empty. Each returned object is the lib TierRow.
    """
    if parse_tier_rows is None:
        return []
    try:
        text = Path(severity_md).read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    rows = parse_tier_rows(text)
    return [r for r in rows if r.tier in PAYABLE_TIERS]


def _rubric_row_id(row) -> str:
    """Stable identifier for a payable rubric row (explicit ID or tier+slug)."""
    if getattr(row, "rubric_id", ""):
        return row.rubric_id
    slug = re.sub(r"[^a-z0-9]+", "-", (row.sentence or "").lower()).strip("-")[:32]
    return f"{row.tier}-{slug}" if slug else row.tier

# LANGUAGE_ALLOWED_CLASSES: maps template-key -> frozenset of allowed language
# tags (lowercase). Templates absent from this mapping are language-agnostic and
# fire for ALL languages.  Templates listed here fire ONLY when the function's
# recorded language is in the allowed set.
LANGUAGE_ALLOWED_CLASSES: dict[str, frozenset[str]] = {
    # Solidity-only attack families
    "reentrancy": frozenset({"solidity", "vyper"}),
    "recipient-nonzero": frozenset({"solidity", "vyper"}),
    "deadline-future": frozenset({"solidity", "vyper"}),
    "access-control-missing": frozenset({"solidity", "vyper"}),
    # Substrate (Rust) families
    "signed-extension": frozenset({"rust"}),
    "hook-weight": frozenset({"rust"}),
    # Cosmos / Go families
    "ante-traversal": frozenset({"go"}),
    "msg-validatebasic": frozenset({"go"}),
    "module-account-conservation": frozenset({"go"}),
    # Solana (Rust) families
    "pda-owner-check": frozenset({"rust"}),
    "cpi-signer": frozenset({"rust"}),
    "account-realloc": frozenset({"rust"}),
    # Move families
    "resource-account-signer": frozenset({"move"}),
    "hot-potato-capability": frozenset({"move"}),
    # ZK families
    "under-constrained-signal": frozenset({"circom", "noir", "leo", "cairo", "gnark"}),
    "soundness": frozenset({"circom", "noir", "leo", "cairo", "gnark"}),
}


def _language_allows(template_key: str, lang: str) -> bool:
    """Return True if template_key is permitted for the given language tag.

    Language-agnostic templates (absent from LANGUAGE_ALLOWED_CLASSES) always
    return True.  Language-restricted templates return True only when lang
    (lowercased, stripped) is in the allowed set.
    """
    allowed = LANGUAGE_ALLOWED_CLASSES.get(template_key)
    if allowed is None:
        return True  # language-agnostic
    return lang.lower().strip() in allowed


QUESTION_TEMPLATES = {
    "access-control-missing": [
        "Can a non-owner address call {fn} directly and trigger a state change?",
        "Is there any modifier or onlyOwner-style check on {fn}? If not, what privileged operation can a non-admin invoke?",
    ],
    "reentrancy": [
        "Can {fn} be reentered before its state-write step completes?",
        "Does {fn} follow Checks-Effects-Interactions (CEI), or does the external call happen BEFORE the storage write?",
        "Could a malicious receiver contract reenter {fn} via the external call and drain funds before the balance update?",
    ],
    "amount-nonzero": [
        "What happens when {fn} is called with amount=0? Does the protocol get into an inconsistent state?",
        "Is there a non-trivial division by amount inside {fn} that could revert or wrap?",
    ],
    "recipient-nonzero": [
        "If {fn} is called with recipient = address(0), does the protocol burn funds or revert?",
    ],
    "sum-preserved": [
        "Does the aggregated `sum_over_keys({var})` invariant after {fn} executes match the pre-state plus the delta? If not, where does conservation break?",
    ],
    "deadline-future": [
        "Can {fn} be called with deadline in the past or close to block.timestamp; does this enable order-replay or stale-quote acceptance?",
    ],
    "origin-checked": [
        "What if {fn} is dispatched as Origin::None or as Origin::Root but should be Signed; does the extrinsic still proceed?",
        "Could a malicious caller forge the origin and reach a privileged code path?",
    ],
    "weight-bounded": [
        "Is the declared `#[weight]` on {fn} bounded by the worst-case computation? If params are attacker-controlled and weight scales linearly, can a low-fee high-cost DoS be triggered?",
    ],
    "ctx-validation": [
        "Does {fn} validate ctx.BlockHeight() or msg.ValidateBasic() before any state write? If not, what malformed msg bypasses guards?",
    ],
    "authz": [
        "Can a non-creator/non-owner address claim authority for {fn}? Where is the ownership check enforced?",
    ],
    # --- Cosmos-SDK (Go) additive families ---
    "ante-traversal": [
        "Does the Msg handled by {fn} traverse every ante decorator (ValidateBasicDecorator, ValidateNestedMsg, SetUpContextDecorator, SigVerificationDecorator, DeductFeeDecorator, project-specific decorators), or can a crafted Msg reach {fn}'s state write via a direct keeper call that bypasses the ante chain?",
        "If {fn} is reachable via MsgExec/nested-Msg, which ante decorator rejects the nested shape, and can an attacker wrap the Msg to skip it?",
    ],
    "msg-validatebasic": [
        "Does the Msg consumed by {fn} implement ValidateBasic(), and does {fn} rely on it for field bounds? What malformed field (negative coin, empty signer, oversized memo) passes ValidateBasic() yet corrupts state inside {fn}?",
    ],
    "module-account-conservation": [
        "Does {fn} preserve module-account balance conservation (sum of user sub-balances == module account holdings) across the bank send/mint/burn it performs? Where could a rounding or ordering bug let the module account drift from the sum of claims?",
    ],
    # --- Substrate (Rust) additive families ---
    "signed-extension": [
        "Is there a SignedExtension (pre_dispatch / validate) that {fn}'s extrinsic depends on for nonce, fee, or mortality checks? Can a transaction skip or underpay it and still dispatch {fn}?",
    ],
    "hook-weight": [
        "If {fn} is an on_initialize / on_finalize hook, is its weight bounded independent of attacker-controlled storage growth? Can an attacker inflate a StorageMap so the per-block hook exceeds the block weight budget and stalls finalization?",
    ],
    # --- Rust-crypto additive families ---
    "nonce-reuse": [
        "Does {fn} derive or accept a nonce/k-value that could repeat across two signatures over different messages? If a nonce is reused (deterministic-but-seeded-on-mutable-state, or RNG misuse), can the private key be recovered?",
    ],
    "constant-time": [
        "Does {fn} branch or early-return on secret-dependent data (key bytes, scalar, MAC compare)? Is the equality/comparison constant-time, or can timing leak the secret?",
    ],
    "malleability": [
        "Can a third party take a valid signature/proof accepted by {fn} and produce a second distinct-but-valid encoding (high-S ECDSA, point/scalar non-canonical form) for the same message, enabling replay or double-count?",
    ],
    "serialization-roundtrip": [
        "Does decode(encode(x)) == x hold for every input {fn} serializes/deserializes? What non-canonical or trailing-bytes encoding decodes successfully yet re-encodes differently, breaking a hash/commitment {fn} relies on?",
    ],
    # --- Solana additive families ---
    "pda-owner-check": [
        "Does {fn} verify the owner program AND the PDA seeds/bump of every account it reads or writes? Can an attacker pass a look-alike account it owns where {fn} expects a program-derived account, bypassing the authority check?",
    ],
    "cpi-signer": [
        "When {fn} performs a CPI, does it correctly scope invoke_signed PDA signer seeds so it cannot be tricked into signing for an account it should not control? Can a passed-in program account redirect the CPI to a malicious program?",
    ],
    "account-realloc": [
        "If {fn} reallocs or initializes an account, is the new space zero-initialized and the rent-exemption / discriminator re-checked? Can a realloc leave stale bytes an attacker reinterprets as authority or balance?",
    ],
    # --- Move additive families ---
    "resource-account-signer": [
        "Does {fn} require the correct &signer / resource-account capability to move or mutate a resource, or can a caller pass a signer for an address that does not own the resource being modified?",
    ],
    "hot-potato-capability": [
        "Does {fn} return a hot-potato (no store/drop/copy) value or a capability that MUST be consumed in the same transaction? Can the obligation be dropped, duplicated, or escape so an unpaid/unauthorized state persists?",
    ],
    # --- ZK additive families ---
    "under-constrained-signal": [
        "Is every output/intermediate signal {fn} computes fully constrained, or can a malicious prover assign a free (witness-only) value to a signal that is used downstream but never pinned by a constraint?",
    ],
    "soundness": [
        "Can a prover satisfy {fn}'s constraint system with a witness that does NOT correspond to a valid execution (missing range check, missing boolean constraint, unchecked selector), producing a proof the verifier accepts for a false statement?",
    ],
}


def derive_question_kind(inv: str) -> str:
    """Map invariant naming convention to question-template key."""
    inv_l = inv.lower()
    if "access-control-missing" in inv_l:
        return "access-control-missing"
    if "reentrancy" in inv_l:
        return "reentrancy"
    if "amount-nonzero" in inv_l:
        return "amount-nonzero"
    if "recipient-nonzero" in inv_l:
        return "recipient-nonzero"
    if "sum-" in inv_l:
        return "sum-preserved"
    if "deadline-future" in inv_l:
        return "deadline-future"
    if "origin-checked" in inv_l:
        return "origin-checked"
    if "weight-bounded" in inv_l:
        return "weight-bounded"
    if "ctx-validation" in inv_l:
        return "ctx-validation"
    if "authz" in inv_l:
        return "authz"
    if "ante-traversal" in inv_l:
        return "ante-traversal"
    if "msg-validatebasic" in inv_l:
        return "msg-validatebasic"
    if "module-account-conservation" in inv_l:
        return "module-account-conservation"
    if "signed-extension" in inv_l:
        return "signed-extension"
    if "hook-weight" in inv_l:
        return "hook-weight"
    if "nonce-reuse" in inv_l:
        return "nonce-reuse"
    if "constant-time" in inv_l:
        return "constant-time"
    if "malleability" in inv_l:
        return "malleability"
    if "serialization-roundtrip" in inv_l:
        return "serialization-roundtrip"
    if "pda-owner-check" in inv_l:
        return "pda-owner-check"
    if "cpi-signer" in inv_l:
        return "cpi-signer"
    if "account-realloc" in inv_l:
        return "account-realloc"
    if "resource-account-signer" in inv_l:
        return "resource-account-signer"
    if "hot-potato-capability" in inv_l:
        return "hot-potato-capability"
    if "under-constrained-signal" in inv_l:
        return "under-constrained-signal"
    if "soundness" in inv_l:
        return "soundness"
    return "generic"


def _build_class_to_rows(payable_rows: list) -> dict[str, list]:
    """Index payable rubric rows by the question_class their sentence maps to."""
    idx: dict[str, list] = collections.defaultdict(list)
    for row in payable_rows or []:
        klass = map_rubric_sentence_to_class(row.sentence)
        idx[klass].append(row)
    return idx


# ---------------------------------------------------------------------------
# Rubric-row SURFACE-APPLICABILITY gate. A payable rubric row whose impact class
# requires a specific structural surface is VACUOUS when the target's repo-tree has
# none of that surface - attaching it just burns hunt budget on guaranteed negatives
# (NUVA 2026-06-30: 120/434 = 28% of ranked questions were governance-voting-manipulation
# attached to EVM contracts with ZERO governance state; every one auto-NEGATIVE). The gate
# is PER REPO-TREE (a sibling tree that DOES have the surface - e.g. the cosmos gov vault -
# still gets the questions) and FAIL-OPEN (never drops when it cannot scan). Conservative:
# only impact classes with an UNAMBIGUOUS structural footprint.
# Each entry: (sentence-keyword regex, required-source-symbol regex, surface name).
SURFACE_REQUIREMENTS = [
    (
        re.compile(r"governance|voting|\bvote\b|proposal|ballot|quorum", re.IGNORECASE),
        re.compile(r"governance|voting|\bvote\b|proposal|ballot|quorum|tally|"
                   r"\bgov\b|govtypes|govkeeper|\bgov\.", re.IGNORECASE),
        "governance",
    ),
]
_SURFACE_SRC_EXT = (".sol", ".go", ".rs", ".move", ".vy", ".cairo")
_SURFACE_SKIP_SUFFIX = (".t.sol", "_test.go", ".pb.go", "_test.rs")
_SURFACE_VENDOR = {
    "node_modules", "lib", "vendor", "external", "third_party", "third-party",
    ".git", "target", "dist", "build", "out", "cache", "artifacts", "testdata", "deps",
}
_SURFACE_CACHE: dict = {}


def _repo_tree_for(file_path: str):
    """The in-scope repo-tree root that owns ``file_path`` (the dir directly under a
    ``src`` segment, else the nearest manifest-bearing ancestor, else the parent)."""
    from pathlib import Path as _P
    p = _P(file_path)
    if not p.is_absolute():
        return None
    parts = p.parts
    for i, seg in enumerate(parts):
        if seg == "src" and i + 1 < len(parts):
            return _P(*parts[: i + 2])
    for anc in p.parents:
        if any((anc / m).exists() for m in
               ("foundry.toml", "package.json", "go.mod", "Cargo.toml", "Move.toml")):
            return anc
    return p.parent


def _tree_has_surface(root, surface: str, sym_re) -> bool:
    """Does any non-vendored, non-test source file under ``root`` contain the surface
    symbol? Cached per (root, surface). Fail-OPEN: True on any scan error (never drop)."""
    import os
    key = (str(root), surface)
    if key in _SURFACE_CACHE:
        return _SURFACE_CACHE[key]
    from pathlib import Path as _P
    found = False
    try:
        for dp, dns, fns in os.walk(root):
            dns[:] = [d for d in dns if d not in _SURFACE_VENDOR and not d.startswith(".")]
            for fn in fns:
                if fn.endswith(_SURFACE_SRC_EXT) and not fn.endswith(_SURFACE_SKIP_SUFFIX):
                    try:
                        if sym_re.search(_P(dp, fn).read_text(encoding="utf-8", errors="ignore")):
                            found = True
                            break
                    except OSError:
                        continue
            if found:
                break
    except OSError:
        found = True  # fail-open
    _SURFACE_CACHE[key] = found
    if not found:
        sys.stderr.write(
            f"[per-fn-q] surface '{surface}' ABSENT in {root} - dropping "
            f"structurally-vacuous {surface}-class rubric questions for that tree\n"
        )
    return found


def _rubric_row_applicable(sentence: str, file_: str) -> bool:
    """False when the row's impact class needs a structural surface absent from the
    target's repo-tree (per-tree, fail-open). Generic via SURFACE_REQUIREMENTS."""
    for sent_re, sym_re, surface in SURFACE_REQUIREMENTS:
        if sent_re.search(sentence or ""):
            root = _repo_tree_for(file_)
            if root is not None and not _tree_has_surface(root, surface, sym_re):
                return False
    return True


def gen_questions(fn_record: dict, payable_rows: list | None = None) -> list[dict]:
    """Generate per-function hacker questions from one invariant record.

    When ``payable_rows`` (parsed SEVERITY.md rows) is supplied, every emitted
    question whose ``question_class`` maps to a payable rubric row is tagged
    ``payable_match=True`` + the matching ``rubric_row_id`` / ``rubric_tier`` /
    ``rubric_sentence`` so the ranker can boost it above a generic question.
    In addition, ONE targeted question is emitted per payable rubric row on this
    function so EVERY payable severity row gets a candidate question - the hunt
    attacks what the SPECIFIC program pays for, not a generic rubric axis.
    """
    out = []
    fn = fn_record.get("function", "?")
    file_ = fn_record.get("file", "?")
    lang = fn_record.get("language", "?")
    payable_rows = payable_rows or []
    class_to_rows = _build_class_to_rows(payable_rows)

    def _tag_payable(rec: dict) -> dict:
        """Stamp rubric provenance onto a record whose class maps to a payable
        row. Mutates and returns the record."""
        rows = class_to_rows.get(rec.get("question_class", ""))
        if rows:
            row = rows[0]
            rec["payable_match"] = True
            rec["rubric_row_id"] = _rubric_row_id(row)
            rec["rubric_tier"] = row.tier
            rec["rubric_sentence"] = row.sentence
        return rec

    for inv in fn_record.get("invariant_candidates", []):
        kind = derive_question_kind(inv)
        # Gate: skip language-restricted templates when the function's language
        # is not in the allowed set.
        if not _language_allows(kind, lang):
            continue
        templates = QUESTION_TEMPLATES.get(kind)
        if not templates:
            # generic fallback
            templates = [
                f"Stated invariant '{inv}': construct an attack scenario "
                "where this invariant is violated, citing the exact bytes that "
                "would cause the break."
            ]
        for t in templates:
            try:
                q = t.format(fn=fn, var=inv.split("-")[-2] if "-" in inv else "x")
            except (IndexError, KeyError):
                q = t.format(fn=fn, var="x") if "{var}" in t else t.format(fn=fn) if "{fn}" in t else t
            out.append(_tag_payable({
                "schema_version": SCHEMA,
                "function": fn,
                "file": file_,
                "language": lang,
                "anchor_invariant": inv,
                "question": q,
                "question_class": kind,
                "question_source": "synth-template",
            }))
    # Incident-grounded questions. invariant-auto-synth.py attaches
    # `incident_invariants` (real invariants extracted from the 994-incident
    # library, each carrying invariant_id + statement + source_finding_ids +
    # verification_tier). The prior implementation iterated ONLY
    # `invariant_candidates` and silently DROPPED this field, so 0% of emitted
    # questions were grounded in a real finding. Interpolate the real statement
    # and cite the source findings so the hunter LLM is anchored to an actual
    # incident rather than a pure regex-shape template.
    for inc in fn_record.get("incident_invariants", []):
        if not isinstance(inc, dict):
            continue
        statement = (inc.get("statement") or "").strip()
        if not statement:
            continue
        inv_id = inc.get("invariant_id") or "UNKNOWN-INV"
        src_ids = inc.get("source_finding_ids") or []
        tier = inc.get("verification_tier") or ""
        category = (inc.get("category") or "").strip()
        # Cap the in-prompt citation list (some invariants carry dozens of source
        # findings); the full list stays on the record's source_finding_ids field.
        if src_ids:
            shown = [str(s) for s in src_ids[:5]]
            cite = ", ".join(shown)
            if len(src_ids) > 5:
                cite += f", +{len(src_ids) - 5} more"
        else:
            cite = "no source ids on record"
        q = (
            f"Real-incident invariant {inv_id}"
            + (f" [{category}]" if category else "")
            + f": \"{statement}\". This invariant was violated in prior audited "
            f"findings ({cite}). Construct a concrete attack on {fn} that breaks "
            "this same invariant, citing the exact lines/bytes that cause the break."
        )
        out.append(_tag_payable({
            "schema_version": SCHEMA,
            "function": fn,
            "file": file_,
            "language": lang,
            "anchor_invariant": inv_id,
            "question": q,
            "question_class": category or "incident-grounded",
            "question_source": "incident-invariant",
            "incident_anchor": inv_id,
            "incident_statement": statement,
            "source_finding_ids": src_ids,
            "verification_tier": tier,
        }))

    # Per-rubric-row targeted questions. EVERY payable severity row gets a
    # dedicated candidate question on this function, so the volume hunt cannot
    # stay generic on the rubric axis - it attacks the program's PAYABLE classes
    # (e.g. optimism "incorrectly-proven withdrawal", "dispute game resolves to
    # wrong outcome") by name. These are tagged payable_match=True with the
    # row's own class so the ranker boosts them above generic questions.
    for row in payable_rows:
        sentence = (row.sentence or "").strip()
        klass = map_rubric_sentence_to_class(sentence)
        # Gate language-restricted template classes the same way as templates.
        if not _language_allows(klass, lang):
            continue
        # Surface-applicability gate: skip a structurally-vacuous impact class
        # (e.g. governance-voting-manipulation on a repo-tree with no governance
        # state) so the hunt is not flooded with guaranteed-negative questions.
        if not _rubric_row_applicable(sentence, file_):
            continue
        row_id = _rubric_row_id(row)
        if sentence:
            q = (
                f"Payable rubric row {row_id} (tier {row.tier}): "
                f"\"{sentence}\". Construct a concrete attack on {fn} that "
                "realizes THIS rubric impact, citing the exact lines/bytes that "
                "cause the break. If this function cannot reach the impact, say "
                "why (which guard / which caller / which invariant blocks it)."
            )
        else:
            q = (
                f"Payable rubric row {row_id} (tier {row.tier}): can {fn} reach "
                "any impact that satisfies this severity tier? Cite the exact "
                "lines/bytes, or say which guard blocks it."
            )
        out.append({
            "schema_version": SCHEMA,
            "function": fn,
            "file": file_,
            "language": lang,
            "anchor_invariant": row_id,
            "question": q,
            "question_class": klass,
            "question_source": "rubric-row-targeted",
            "payable_match": True,
            "rubric_row_id": row_id,
            "rubric_tier": row.tier,
            "rubric_sentence": sentence,
        })
    return out


def _cap_questions(questions: list[dict], cap: int) -> list[dict]:
    """Apply the per-fn cap WITHOUT starving the high-signal anchors.

    gen_questions appends incident-grounded AND rubric-row-targeted questions
    LAST, so a naive ``[:cap]`` slice (when the synth-template questions already
    fill the budget) would drop every anchor and defeat the whole uplift.

    Priority is anchor-first: ALL rubric-row-targeted questions survive (every
    payable severity row MUST keep its candidate question - that is the contract
    of this uplift), then incident-grounded questions fill up to half the cap,
    then templates backfill the remainder. Template-first ordering is preserved
    for downstream stability.
    """
    if cap is None or cap <= 0:
        return list(questions)
    rubric = [q for q in questions
              if q.get("question_source") == "rubric-row-targeted"]
    grounded = [q for q in questions
                if q.get("question_source") == "incident-invariant"]
    templated = [q for q in questions
                 if q.get("question_source") not in
                 ("incident-invariant", "rubric-row-targeted")]
    if not grounded and not rubric:
        return questions[:cap]
    # Rubric-row questions are never dropped: every payable row keeps a question.
    keep_rubric = list(rubric)
    remaining = max(0, cap - len(keep_rubric))
    reserve = max(0, min(len(grounded), remaining // 2 if remaining else 0))
    if grounded and remaining and reserve == 0:
        reserve = min(len(grounded), 1)
    keep_grounded = grounded[:reserve]
    keep_templated = templated[: max(0, remaining - len(keep_grounded))]
    return keep_templated + keep_grounded + keep_rubric


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--invariants", required=True,
                   help="Path to invariants.jsonl (from invariant-auto-synth.py)")
    p.add_argument("--output", required=True,
                   help="Output JSONL path")
    p.add_argument("--max-questions-per-fn", type=int, default=5)
    p.add_argument("--severity-md", default="",
                   help="Path to the program SEVERITY.md. Payable rubric rows "
                        "are fed into question generation so the hunt attacks "
                        "the SPECIFIC program's payable classes.")
    p.add_argument("--workspace", default="",
                   help="Workspace root; SEVERITY.md is auto-discovered under it "
                        "when --severity-md is not given. ALSO the source of the "
                        "data-flow slice (<ws>/.auditooor/dataflow_paths.jsonl) "
                        "used to seed flow-grounded questions.")
    p.add_argument("--dataflow-paths", default="",
                   help="Explicit path to a dataflow_paths.jsonl slice. When set, "
                        "overrides the workspace auto-discovery for flow-seeding. "
                        "When neither this nor --workspace yields a slice, zero "
                        "flow-seeded questions are emitted (default-off).")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    inv_path = Path(args.invariants)
    if not inv_path.is_file():
        sys.stderr.write(f"[per-fn-q] no invariants file: {inv_path}\n")
        return 2

    # Resolve the program SEVERITY.md (explicit > workspace auto-discover) and
    # parse its payable rows once. Empty list => generic behaviour (back-compat).
    payable_rows: list = []
    sev_path = None
    if args.severity_md:
        sev_path = Path(args.severity_md)
    elif args.workspace and find_severity_md is not None:
        sev_path = find_severity_md(Path(args.workspace))
    if sev_path is not None and Path(sev_path).is_file():
        payable_rows = load_payable_rubric_rows(Path(sev_path))
        sys.stderr.write(
            f"[per-fn-q] payable rubric rows from {sev_path}: "
            f"{len(payable_rows)}\n"
        )
    elif args.severity_md or args.workspace:
        sys.stderr.write(
            "[per-fn-q] no SEVERITY.md resolved; staying generic on rubric axis\n"
        )

    # --- Flow-seeded question source (Bidirectional wiring 49a). ---------------
    # Read the data-flow slice ONCE (workspace auto-discovery, or an explicit
    # --dataflow-paths override), filter to genuine UNGUARDED value-mover flows,
    # and emit one targeted question per path anchored at the real sink file:line.
    # Default-off: no slice -> seedable=[] -> seeded=[] -> output byte-identical.
    seeded_questions: list[dict] = []
    if args.dataflow_paths:
        df_file = Path(args.dataflow_paths)
        all_paths: list = []
        if df_file.is_file():
            try:
                import importlib.util
                _spec = importlib.util.spec_from_file_location(
                    "dataflow_schema",
                    str(AUDITOOOR_ROOT / "tools" / "dataflow_schema.py"))
                _mod = importlib.util.module_from_spec(_spec)
                _spec.loader.exec_module(_mod)  # type: ignore
                for rec in _mod.read_jsonl(str(df_file)):
                    ok, _errs = _mod.validate(rec)
                    if ok and not (rec.get("degraded") is True):
                        all_paths.append(rec)
            except Exception:
                all_paths = []
    else:
        all_paths = _read_dataflow_paths(args.workspace)
    seedable = [p for p in all_paths if _flow_path_is_seedable(p)]
    seeded_questions = gen_flow_seeded_questions(seedable)
    # Guard-correctness consumer (additive, default-off): a path the closure pass
    # stamped boundary_suspect gets an off-by-one/boundary hunt question. These
    # are GUARDED paths (not in `seedable`) that may still be exploitable via a
    # boundary bug. Absent the boundary_suspect annotation, this yields [].
    boundary_suspect_paths = [p for p in all_paths
                              if _flow_path_is_boundary_suspect(p)]
    boundary_questions = gen_boundary_suspect_questions(boundary_suspect_paths)
    # Type-convertibility / UNSAFE-DOWNCAST consumer (additive, default-off): a
    # path the closure pass stamped downcast_suspect gets a truncation/sign-flip
    # hunt question anchored at the cast file:line. Absent the annotation -> [].
    downcast_suspect_paths = [p for p in all_paths
                              if _flow_path_is_downcast_suspect(p)]
    downcast_questions = gen_downcast_suspect_questions(downcast_suspect_paths)
    # Divide-before-multiply precision consumer (additive, default-off, Glider gap
    # W3): a path the closure pass stamped div_before_mul_suspect gets a precision-
    # loss hunt question anchored at the DIVISION file:line. Absent the annotation
    # -> []. Guard-independent (a precision bug is exploitable either way).
    div_before_mul_paths = [p for p in all_paths
                            if _flow_path_is_div_before_mul_suspect(p)]
    div_before_mul_questions = gen_div_before_mul_questions(div_before_mul_paths)
    # Inline-assembly / Yul consumer (additive, default-off): a path the closure
    # pass stamped asm_suspect gets an asm-delegatecall / storage-collision hunt
    # question anchored at the Yul block file:line. Absent the annotation -> [].
    asm_suspect_paths = [p for p in all_paths
                         if _flow_path_is_asm_suspect(p)]
    asm_questions = gen_asm_suspect_questions(asm_suspect_paths)
    # Same-fn CEI / intra-proc reentrancy consumer (additive, default-off): a path
    # the closure pass stamped intra_cei_suspect gets a same-fn-reentrancy hunt
    # question anchored at the post-call state-write file:line. Complements (does
    # not duplicate) the cross-fn closure reentrancy. Absent the annotation -> [].
    intra_cei_paths = [p for p in all_paths
                       if _flow_path_is_intra_cei_suspect(p)]
    intra_cei_questions = gen_intra_cei_questions(intra_cei_paths)
    # Unbounded-loop gas-griefing consumer (additive, default-off): a path the
    # closure pass stamped unbounded_loop_suspect gets an unbounded-loop-gas hunt
    # question anchored at the loop file:line. Absent the annotation -> [].
    unbounded_loop_paths = [p for p in all_paths
                            if _flow_path_is_unbounded_loop_suspect(p)]
    unbounded_loop_questions = gen_unbounded_loop_questions(unbounded_loop_paths)
    # Override-dropped-guard consumer (additive, default-off, Glider gap W1): a
    # path the closure pass stamped override_dropped_guard_suspect gets an
    # access-control bypass hunt question anchored at the override's declaration
    # file:line. Distinct from has_guard_in_closure (which only sees the post-drop
    # state). Absent the annotation -> [].
    override_dropped_guard_paths = [p for p in all_paths
                                    if _flow_path_is_override_dropped_guard_suspect(p)]
    override_dropped_guard_questions = gen_override_dropped_guard_questions(
        override_dropped_guard_paths)
    # Oracle try/catch-swallow consumer (additive, default-off, Glider gap W2): a
    # path the closure pass stamped oracle_swallow_suspect gets an oracle-failure-
    # ignored / stale-price hunt question anchored at the catch clause's file:line.
    # Distinct from has_guard_in_closure (access-control) and the boundary/downcast
    # oracles. Absent the annotation -> [].
    oracle_swallow_paths = [p for p in all_paths
                            if _flow_path_is_oracle_swallow_suspect(p)]
    oracle_swallow_questions = gen_oracle_swallow_questions(oracle_swallow_paths)
    # EnumerableSet remove-in-loop iteration-skip consumer (additive, default-off,
    # Glider gap W5): a path the closure pass stamped enumset_remove_in_loop_suspect
    # gets an iteration-skip hunt question anchored at the `remove` file:line.
    # Distinct from the unbounded-loop oracle (gas-exhaustion) - this is a functional
    # correctness break (silently-skipped elements). Absent the annotation -> [].
    enumset_remove_in_loop_paths = [p for p in all_paths
                                    if _flow_path_is_enumset_remove_in_loop_suspect(p)]
    enumset_remove_in_loop_questions = gen_enumset_remove_in_loop_questions(
        enumset_remove_in_loop_paths)
    # Unchecked-return-value consumer (additive, default-off, Glider gap W6 P1): a
    # path the closure pass stamped unchecked_return_value_suspect gets a silent-
    # failure hunt question anchored at the call file:line. Distinct from cap-3
    # (taint of INPUTS to sinks) and cap-8/W4 (external-call-then-write ORDERING) -
    # this keys on RETURN-value CONSUMPTION. Absent the annotation -> [].
    unchecked_return_paths = [p for p in all_paths
                              if _flow_path_is_unchecked_return_value_suspect(p)]
    unchecked_return_questions = gen_unchecked_return_questions(
        unchecked_return_paths)
    # Logic-tautology / dead-comparison consumer (additive, default-off, Glider
    # gap W6 P2): a path the closure pass stamped logic_tautology_suspect gets a
    # broken-access-control-logic hunt question anchored at the broken guard's
    # file:line. Distinct from has_guard_in_closure (which answers "is a guard
    # present", not "is the guard logically correct"). Absent the annotation -> [].
    logic_tautology_paths = [p for p in all_paths
                             if _flow_path_is_logic_tautology_suspect(p)]
    logic_tautology_questions = gen_logic_tautology_questions(logic_tautology_paths)
    # Memory-copy-no-writeback consumer (additive, default-off, Glider gap W6 P8):
    # a path the closure pass stamped memory_copy_no_writeback_suspect gets a
    # lost-state-update hunt question anchored at the mutation file:line. Distinct
    # from intra-CEI (state-write ORDER), unchecked-return (return CONSUMPTION), and
    # enumset-remove (ITERATION correctness) - this keys on WRITEBACK presence after
    # a memory copy of a storage var. Absent the annotation -> [].
    mem_copy_no_wb_paths = [p for p in all_paths
                            if _flow_path_is_memory_copy_no_writeback_suspect(p)]
    mem_copy_no_wb_questions = gen_memory_copy_no_writeback_questions(
        mem_copy_no_wb_paths)
    # Two-step-accept-wrong-guard consumer (additive, default-off, Glider gap W6 P5):
    # a path the closure pass stamped two_step_accept_wrong_guard_suspect gets an
    # access-control wrong-guard hunt question anchored at the function file:line.
    # Distinct from missing-guard (cap-1, no guard at all), override-dropped-guard
    # (W1, base-has-guard dropped in override), and logic-tautology (W6 P2, guard
    # logic broken). Absent the annotation -> [].
    two_step_accept_paths = [p for p in all_paths
                             if _flow_path_is_two_step_accept_wrong_guard_suspect(p)]
    two_step_accept_questions = gen_two_step_accept_wrong_guard_questions(
        two_step_accept_paths)
    # Signature-replay consumer (additive, default-off, Glider gap W6 P3): a
    # path the closure pass stamped signature_replay_suspect gets a
    # same-chain-or-cross-chain replay hunt question anchored at the ecrecover
    # file:line. Sub-rules: missing-nonce (same-chain replay) and missing-chainid
    # (cross-chain replay). Distinct from access-control (replay does not require
    # a missing guard), CEI (replay is about VERIFICATION preconditions, not
    # state-write order), and unchecked-return (ecrecover always returns a value).
    # Absent the annotation -> [].
    signature_replay_paths = [p for p in all_paths
                              if _flow_path_is_signature_replay_suspect(p)]
    signature_replay_questions = gen_signature_replay_questions(
        signature_replay_paths)
    # --- P3 sibling flow-fed seed sources (default-on when the sidecar is present).
    # Coupled-state co-write violators (state_coupling_edges.jsonl) -> one
    # 'coupled-seeded' question per |G|>=2 writer that omits a coupled sibling; and
    # attacker-movable oracle reads (oracle_reachability_hypotheses.jsonl) -> one
    # 'oracle-seeded' question per reachable read. Both key off --workspace only
    # (the sidecars live under <ws>/.auditooor/). Absent the sidecar -> [] (no-op).
    coupling_edges = _read_state_coupling_edges(args.workspace)
    coupled_seeded_edges = [e for e in coupling_edges
                            if _coupling_violators_omitting_sibling(e)]
    coupled_questions = gen_coupled_seeded_questions(coupled_seeded_edges)
    oracle_hypotheses = _read_oracle_hypotheses(args.workspace)
    oracle_seedable = [h for h in oracle_hypotheses if _oracle_hyp_is_seedable(h)]
    oracle_questions = gen_oracle_seeded_questions(oracle_seedable)
    if coupling_edges or oracle_hypotheses:
        sys.stderr.write(
            f"[per-fn-q] coupled-state seed: {len(coupling_edges)} edge(s), "
            f"{len(coupled_questions)} coupled-seeded question(s); "
            f"oracle-reachability seed: {len(oracle_hypotheses)} hypothesis(es), "
            f"{len(oracle_questions)} oracle-seeded question(s)\n"
        )
    if all_paths:
        sys.stderr.write(
            f"[per-fn-q] dataflow slice: {len(all_paths)} path(s), "
            f"{len(seedable)} unguarded value-mover flow(s) seeded, "
            f"{len(boundary_suspect_paths)} boundary-suspect guard(s) seeded, "
            f"{len(downcast_suspect_paths)} unsafe-downcast(s) seeded, "
            f"{len(div_before_mul_paths)} divide-before-multiply(s) seeded, "
            f"{len(asm_suspect_paths)} inline-asm/yul sink(s) seeded, "
            f"{len(intra_cei_paths)} same-fn-CEI/reentrancy seeded, "
            f"{len(unbounded_loop_paths)} unbounded-loop(s) seeded, "
            f"{len(override_dropped_guard_paths)} override-dropped-guard(s) seeded, "
            f"{len(oracle_swallow_paths)} oracle-try/catch-swallow(s) seeded, "
            f"{len(enumset_remove_in_loop_paths)} enumset-remove-in-loop(s) seeded, "
            f"{len(unchecked_return_paths)} unchecked-return-value(s) seeded, "
            f"{len(logic_tautology_paths)} logic-tautology(s) seeded, "
            f"{len(mem_copy_no_wb_paths)} memory-copy-no-writeback(s) seeded, "
            f"{len(two_step_accept_paths)} two-step-accept-wrong-guard(s) seeded, "
            f"{len(signature_replay_paths)} signature-replay(s) seeded\n"
        )

    records_out = (list(seeded_questions) + list(boundary_questions)
                   + list(downcast_questions) + list(div_before_mul_questions)
                   + list(asm_questions)
                   + list(intra_cei_questions) + list(unbounded_loop_questions)
                   + list(override_dropped_guard_questions)
                   + list(oracle_swallow_questions)
                   + list(enumset_remove_in_loop_questions)
                   + list(unchecked_return_questions)
                   + list(logic_tautology_questions)
                   + list(mem_copy_no_wb_questions)
                   + list(two_step_accept_questions)
                   + list(signature_replay_questions)
                   + list(coupled_questions)
                   + list(oracle_questions))
    # --- FAIL-CLOSED (P3): a PRESENT-but-EMPTY dataflow slice must NOT silently
    # degrade to symbol-only. The whole point of this arm is flow-FED questions;
    # if a slice FILE is on disk but produced zero flow-fed seeds of ANY kind
    # (DefUsePath value-mover/suspect + coupled-state + oracle), that is almost
    # always a broken/empty slice producer, not a genuinely clean target. Surface
    # it loudly on stderr instead of quietly leaving the flow arm dark. This is a
    # WARNING (stderr only) - it does not change the output file, so the symbol
    # fallback still runs and the no-slice byte-identical contract is preserved.
    _df_slice_present = False
    if args.dataflow_paths:
        _df_slice_present = Path(args.dataflow_paths).is_file()
    elif args.workspace:
        _df_slice_present = (
            Path(args.workspace) / ".auditooor" / "dataflow_paths.jsonl"
        ).is_file()
    _total_flow_fed = len(records_out)  # every record so far is flow-fed
    if _df_slice_present and _total_flow_fed == 0:
        sys.stderr.write(
            "[per-fn-q] FAIL-CLOSED WARNING: a dataflow slice file is PRESENT but "
            "produced ZERO flow-fed questions (no unguarded value-mover / suspect "
            "path, no coupled-state violator, no oracle read). The per-fn hunt is "
            "degrading to SYMBOL-ONLY for the flow arm - inspect the slice producer "
            "(dataflow-slice.py / state-coupling-graph.py / oracle-reachability-lane.py); "
            "do NOT treat this as a clean flow result.\n"
        )
    skipped_nonprod = 0
    # Scope text for impact-methodology contract-kind inference (SEVERITY.md, else
    # SCOPE.md, else empty). Read once; used by the per-fn impact renderer below.
    scope_text = ""
    try:
        if sev_path is not None and Path(sev_path).is_file():
            scope_text = Path(sev_path).read_text(encoding="utf-8", errors="replace")
        elif args.workspace:
            _scope_md = Path(args.workspace) / "SCOPE.md"
            if _scope_md.is_file():
                scope_text = _scope_md.read_text(encoding="utf-8", errors="replace")
    except OSError:
        scope_text = ""
    _impact_cap = min(3, args.max_questions_per_fn) if args.max_questions_per_fn else 3
    impact_emitted = 0
    # Track every (file, function) the invariant-derived path already covered so
    # the in-scope supplemental pass below does NOT double-emit for them.
    invariant_covered: set[tuple[str, str]] = set()
    with inv_path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                fn_rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            # Final emit-time scope guard: never seed questions for the audit's
            # own *Mutant*.sol mutation artifacts / test / generated trees, even
            # if the upstream invariant enumerator absorbed them (the SSV n40
            # leak). Fail-open; disable with AUDITOOOR_PERFN_Q_NO_SCOPE_FILTER=1.
            if _scope_exclusion_skip(fn_rec.get("file", "")):
                skipped_nonprod += 1
                continue
            invariant_covered.add(
                (fn_rec.get("file", "") or "", fn_rec.get("function", "") or "")
            )
            qs = _cap_questions(
                gen_questions(fn_rec, payable_rows), args.max_questions_per_fn
            )
            records_out.extend(qs)
            # Impact-methodology rows (function-specialized fund-theft / liquidation
            # / freeze / yield-theft lens) so the persisted corpus - not just the
            # dispatch brief - carries the capability. Default-on; the corpus-
            # provenance gate fails closed if these are absent on a value surface.
            imp = _render_impact_for_fn(fn_rec, scope_text, _impact_cap)
            if imp:
                records_out.extend(imp)
                impact_emitted += len(imp)

    # --- In-scope supplemental pass (L3 fix) -----------------------------------
    # per-fn questions were STRICTLY invariant-driven: a (file, function) with no
    # invariant row got ZERO hacker questions. invariant-auto-synth only covers a
    # subset of in-scope files, so genuine value-movers (e.g. AccountingLib NAV-
    # split math, RoundingGuard precision) were silently skipped. For every in-
    # scope unit the invariant path did NOT cover, emit at least the generic
    # impact-methodology question set (same impact_id / kill_condition rows the
    # tool already builds for the invariant-driven impact path). Scoped to in-scope
    # units only (OOS / mutation-artifact / test units are skipped). ADDITIVE -
    # invariant-derived rows above are unchanged; absent the sidecar this is a
    # no-op (byte-identical output).
    inscope_supplemental_emitted = 0
    inscope_supplemental_units = 0
    for unit in _read_inscope_units(args.workspace):
        u_file = unit.get("file", "") or ""
        u_fn = unit.get("function", "") or ""
        if not u_file or not u_fn:
            continue
        if (u_file, u_fn) in invariant_covered:
            continue
        if _scope_exclusion_skip(u_file):
            skipped_nonprod += 1
            continue
        fn_rec_unit = _inscope_unit_to_fn_rec(unit)
        imp = _render_impact_for_fn(fn_rec_unit, scope_text, _impact_cap)
        if not imp:
            # _render_impact_for_fn attaches nothing for unclassified internal-pure
            # leaf helpers (e.g. AccountingLib NAV-split math, RoundingGuard
            # precision). The unit is in-scope (passed the scope-exclusion guard
            # above), so it must not reach the hunt with ZERO questions: emit one
            # generic impact-methodology fallback keyed to the unit. ADDITIVE -
            # invariant-driven and already-rendered impact rows are unaffected.
            imp = _impact_methodology_fallback_for_unit(fn_rec_unit)
        if imp:
            records_out.extend(imp)
            impact_emitted += len(imp)
            inscope_supplemental_emitted += len(imp)
            inscope_supplemental_units += 1
    if inscope_supplemental_emitted:
        sys.stderr.write(
            f"[per-fn-q] in-scope supplemental: emitted "
            f"{inscope_supplemental_emitted} impact-methodology question(s) for "
            f"{inscope_supplemental_units} non-invariant in-scope unit(s)\n"
        )

    if impact_emitted:
        sys.stderr.write(
            f"[per-fn-q] impact-methodology: emitted {impact_emitted} "
            "function-specialized impact question(s)\n"
        )
    if skipped_nonprod:
        sys.stderr.write(
            f"[per-fn-q] scope-guard skipped {skipped_nonprod} non-production "
            "unit(s) (mutation-artifact/test/generated) from the invariants "
            "input\n"
        )

    # Normalize every record's `file` to a WORKSPACE-RELATIVE path. The two emit
    # passes disagree on path form: the invariant/main pass carries ABSOLUTE file
    # paths (from the function records) while the in-scope supplemental pass carries
    # ws-RELATIVE paths (from inscope_units.jsonl). Left unnormalized, the SAME unit
    # appears twice under two spellings, so every distinct-unit consumer (ranker
    # dedup, hunt-obligation _expected_units, coverage) double-counts it (strata
    # 2026-06-30: 224 phantom-inflated vs 135 true units). Strip the workspace prefix
    # at this single chokepoint so `file` is consistently relative downstream.
    _ws_abs = ""
    if getattr(args, "workspace", ""):
        try:
            _ws_abs = str(Path(args.workspace).resolve())
        except Exception:
            _ws_abs = str(args.workspace).rstrip("/")
    for r in records_out:
        f = str(r.get("file") or "")
        if f and _ws_abs and f.startswith(_ws_abs):
            r["file"] = f[len(_ws_abs):].lstrip("/")

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as fh:
        for r in records_out:
            fh.write(json.dumps(r) + "\n")
    sys.stderr.write(f"[per-fn-q] wrote {len(records_out)} questions to "
                     f"{out_path}\n")

    by_class = collections.Counter(r["question_class"] for r in records_out)
    if args.json:
        print(json.dumps({
            "total_questions": len(records_out),
            "by_class": dict(by_class),
            "out": str(out_path),
        }, indent=2))
    else:
        print(f"total questions emitted: {len(records_out)} | "
              f"by class: {dict(by_class)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
