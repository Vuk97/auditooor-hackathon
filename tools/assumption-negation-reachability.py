#!/usr/bin/env python3
"""assumption-negation-reachability.py - NOVELTY-GENERATION LAYER item 3.

ASSUMPTION-NEGATION REACHABILITY - the 3rd NOVELTY engine (class-agnostic; finds
never-covered 0-days). It does NOT read the corpus / attack-class taxonomy. For
each implicit assumption A the code makes (enumerated by the sibling engine
tools/assumption-enumeration-falsification.py - REUSED, not rebuilt), it NEGATES
A (not-A) and asks the OWNED dataflow/callgraph backend a single REACHABILITY
JOIN question:

  Is there an ENTRYPOINT-REACHABLE path on which not-A holds AND that path
  reaches an IMPACT SINK (value-move / state-corrupt / halt), with NO guard on
  that path enforcing A?

A reachable negation with impact = a candidate 0-day, class-agnostic (needs no
corpus class). That unnamed-ness is precisely the point (guard-rail: derive from
code + reachability, not a class list, not a token grep).

REASONING QUERY (reachable-negation, NOT a shape):

  SURVIVOR(A) := { paths establishing not-A } INTERSECT { paths reaching an
                 impact sink } is non-empty on an entrypoint-reachable path, and
                 NO guard enforces A on that path.

  - The A set (per unit) comes from assumption-enumeration-falsification.run().
    An assumption is a NEGATION CANDIDATE iff it is PRESENT (a code signal shows
    the fn makes it). We only pursue PRESENT assumptions (enforced or not) - the
    reachability join is what decides survivorship, not the sibling's falsifiable
    flag (which is a per-unit fold; here we need CONCRETE per-path evidence).
  - { paths reaching an impact sink } and { guard enforces A on this path } come
    from dataflow_paths.jsonl (source.kind=="param-entrypoint" => reachable;
    sink.kind in IMPACT sinks; guard_nodes are the persisted output of
    slither_predicates.has_guard_in_closure - consuming them IS reusing the
    closure-guard primitive to answer "is A enforced on THIS path").
  - not-A "holds on the path" := the path reaches the impact sink and NO
    guard_node on that path structurally enforces A (the enforcement regexes are
    the sibling engine's own AUTHORITY/BOUND/NONZERO/... signatures, REUSED).

HONESTY (never silent):
  * substrate_vacuous : dataflow_paths.jsonl missing/empty OR zero
    param-entrypoint paths -> we CANNOT run the join; emit nothing, status
    "substrate_vacuous" (fail-closed under --fail-closed).
  * cited-empty       : substrate present + entrypoint paths exist, join ran,
    zero survivors -> honest 0 (status "cited_empty").
  * needs_source (advisory): assumption PRESENT for a unit but that unit has NO
    entrypoint-reachable impact path in the substrate -> we cannot confirm OR
    refute reachability; emit an ADVISORY needs_source obligation (never a
    survivor, never terminal) so it is not silently dropped.

Every emitted row cites a file:line anchor from a real backend record (the
entrypoint source and the impact sink) - never an ungrounded claim.

Usage:
  python3 tools/assumption-negation-reachability.py --workspace <ws>
        [--src-root DIR] [--emit PATH] [--json] [--fail-closed]

Output: <ws>/.auditooor/assumption_negation_obligations.jsonl
        (schema auditooor.assumption_negation.v1) + a summary on stderr.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
from collections import defaultdict

SCHEMA = "auditooor.assumption_negation.v1"
AUDITOOOR = ".auditooor"
_TOOLS_DIR = pathlib.Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# REUSE the sibling assumption-enumeration engine (import, do not rebuild).
# ---------------------------------------------------------------------------

def _load_sibling():
    """Import tools/assumption-enumeration-falsification.py (hyphenated name)."""
    path = _TOOLS_DIR / "assumption-enumeration-falsification.py"
    spec = importlib.util.spec_from_file_location("assumption_enum_falsify", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load sibling engine at {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_SIB = _load_sibling()
_unit_key = _SIB._unit_key
_basename = _SIB._basename
_norm_fn = _SIB._norm_fn

# The sibling's own enforcement signatures - REUSED verbatim so "is A enforced on
# this path" is answered by the SAME primitive the enumeration engine uses.
_ENFORCE_RX = {
    "caller-trusted": _SIB.AUTHORITY_RX,
    "value-bounded": _SIB.BOUND_RX,
    "non-zero": _SIB.NONZERO_RX,
    "external-succeeds": _SIB.RETURN_CHECK_RX,
    "no-reentry": _SIB.REENTRY_RX,
    "init-once": _SIB.INIT_RX,
    "order-holds": _SIB.ORDER_RX,
}

# The negation text per axis (what not-A means as a reachable condition).
_NEGATION = {
    "caller-trusted": "an UNTRUSTED caller reaches the state mutator (no caller-identity/access guard on the path)",
    "value-bounded": "an UNBOUNDED value reaches the value-move sink (no bound/balance comparison on the path)",
    "non-zero": "a ZERO amount/denominator reaches the sink (no non-zero assertion on the path)",
    "external-succeeds": "a FAILED external call's result is consumed (no return/success check on the path)",
    "no-reentry": "a REENTRANT re-entry occurs between the external call and the state write (no reentrancy lock on the path)",
    "init-once": "the initializer runs MORE THAN ONCE (no run-once guard on the path)",
    "order-holds": "an OUT-OF-ORDER / replayed nonce-sequence reaches the mutator (no ordering assertion on the path)",
}

# Which impact-sink CLASS each negated assumption's survivor lands in.
_IMPACT_CLASS = {
    "caller-trusted": "state-corrupt",
    "value-bounded": "value-move",
    "non-zero": "value-move",
    "external-succeeds": "state-corrupt",
    "no-reentry": "value-move",
    "init-once": "state-corrupt",
    "order-holds": "state-corrupt",
}

# Impact-sink kinds by class. `source.kind=="param-entrypoint"` gates reachability;
# `sink.kind in IMPACT_SINKS` gates impact.
_VALUE_MOVE_SINKS = {"transfer", "safetransfer", "safetransferfrom", "burn", "mint",
                     "send", "call", "delegatecall", "transferfrom"}
_STATE_CORRUPT_SINKS = {"sstore", "storage-write", "storage_write", "accounting",
                        "ledger-write", "ledger_write", "state-write", "state_write",
                        "delegatecall", "call"}
_HALT_SINKS = {"revert", "revert-dos", "panic", "halt", "require-dos", "assert"}
_ALL_IMPACT_SINKS = _VALUE_MOVE_SINKS | _STATE_CORRUPT_SINKS | _HALT_SINKS


def _sink_classes(kind: str) -> set:
    k = (kind or "").strip().lower()
    out = set()
    if k in _VALUE_MOVE_SINKS:
        out.add("value-move")
    if k in _STATE_CORRUPT_SINKS:
        out.add("state-corrupt")
    if k in _HALT_SINKS:
        out.add("halt")
    return out


# ---------------------------------------------------------------------------
# Load CONCRETE per-path records (the sibling's fold loses per-path granularity;
# the reachability JOIN needs individual paths).
# ---------------------------------------------------------------------------

def load_paths(ws: pathlib.Path) -> tuple[dict, dict]:
    """Return (paths_by_unit, stats).

    paths_by_unit[unit_key] = list of {path_id, source{file,line,fn,kind},
      sink{kind,file,line}, guard_exprs:[str], reachable:bool, sink_classes:set}.
    Only records with a resolvable source.fn are kept (degrade rows skipped).
    """
    p = _adir(ws) / "dataflow_paths.jsonl"
    stats = {"records": 0, "kept": 0, "entrypoint_paths": 0, "impact_paths": 0,
             "file_present": p.exists()}
    by_unit: dict = defaultdict(list)
    if not p.exists():
        return dict(by_unit), stats
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        if r.get("schema") and not str(r.get("schema", "")).startswith("dataflow_path"):
            continue
        stats["records"] += 1
        src = r.get("source") or {}
        fn = src.get("fn")
        if not fn:
            continue  # degrade / no-source record
        stats["kept"] += 1
        reachable = src.get("kind") == "param-entrypoint"
        if reachable:
            stats["entrypoint_paths"] += 1
        sink = r.get("sink") or {}
        sink_kind = sink.get("kind") or ""
        sc = _sink_classes(sink_kind)
        if reachable and sc:
            stats["impact_paths"] += 1
        guard_exprs = []
        for g in r.get("guard_nodes", []) or []:
            e = g.get("expr", "")
            if e:
                guard_exprs.append(e)
        k = _unit_key(src.get("file", ""), fn)
        by_unit[k].append({
            "path_id": r.get("path_id", ""),
            "source": {"file": src.get("file", ""), "line": src.get("line", 0),
                       "fn": fn, "kind": src.get("kind", "")},
            "sink": {"kind": sink_kind, "file": sink.get("file", ""),
                     "line": sink.get("line", 0)},
            "guard_exprs": guard_exprs,
            "reachable": reachable,
            "sink_classes": sc,
            # authoritative closure verdict: a compensating guard DOMINATES this
            # path's sink in the closure even when no guard token is inline. The
            # engine previously read only guard_nodes[].expr and counted a
            # closure-guarded path as an unrefuted survivor (root-caused
            # 2026-07-14 guard-feed audit: nuva EVM anchors carry 290
            # closure_guarded paths vs 30 genuinely-unguarded).
            "closure_guarded": r.get("closure_guarded") is True,
        })
    return dict(by_unit), stats


def _adir(ws: pathlib.Path) -> pathlib.Path:
    return ws / AUDITOOOR


# ---------------------------------------------------------------------------
# --autorun-producers: materialize the substrate (dataflow_paths.jsonl) BEFORE
# the reachability join. The build agent's proof-run FABRICATED a nuva firing:
# on disk the join is substrate_vacuous because dataflow_paths.jsonl is absent
# unless the dataflow backend was run first. This flag runs the OWNED dataflow
# backend + the sibling assumption-enumeration engine so the join has a real
# substrate; if nothing materializes, the honest substrate_vacuous verdict still
# fires (we NEVER fabricate a survivor). Failures are tolerated per-producer.
# ---------------------------------------------------------------------------

def _producer_commands(ws: pathlib.Path) -> list[tuple[str, list[str]]]:
    wss = str(ws)
    cmds: list[tuple[str, list[str]]] = []
    # The dataflow backend that emits <ws>/.auditooor/dataflow_paths.jsonl (the
    # entrypoint->impact-sink substrate the join reads). Prefer the router.
    if (_TOOLS_DIR / "dataflow.py").is_file():
        cmds.append(("dataflow.py", ["--workspace", wss, "--mode", "both"]))
    elif (_TOOLS_DIR / "dataflow-slice.py").is_file():
        cmds.append(("dataflow-slice.py", ["--workspace", wss, "--mode", "both"]))
    # The sibling implicit-assumption A-set engine (reused in-process; also run as
    # a producer so any sidecar it emits is fresh).
    # This sibling tool intentionally keeps a positional workspace CLI. Keep the
    # producer invocation aligned with its public parser instead of masking rc=2.
    cmds.append(("assumption-enumeration-falsification.py", [wss]))
    return cmds


def _newest_declared_source_mtime(ws: pathlib.Path) -> float:
    """Return the newest mtime among declared source units, when available.

    Reasoner autorun is often invoked once per obligation family. Re-running the
    full dataflow backend for every family is wasteful and can starve the ordered
    pipeline. The in-scope manifest is already the canonical source denominator;
    use it for freshness instead of scanning generated or vendored trees.
    """
    manifest = _adir(ws) / "inscope_units.jsonl"
    newest = 0.0
    if manifest.is_file():
        for line in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                row = json.loads(line)
            except (TypeError, ValueError):
                continue
            if not isinstance(row, dict):
                continue
            raw = row.get("file") or row.get("path") or row.get("source_file")
            if not raw:
                continue
            path = pathlib.Path(str(raw))
            if not path.is_absolute():
                path = ws / path
            try:
                newest = max(newest, path.stat().st_mtime)
            except OSError:
                continue
    return newest


def _producer_artifact_and_inputs(
    ws: pathlib.Path, script: str
) -> tuple[pathlib.Path | None, list[pathlib.Path], float]:
    """Map an autorun producer to its durable output and freshness inputs."""
    aud = _adir(ws)
    if script in {"dataflow.py", "dataflow-slice.py"}:
        artifact = aud / "dataflow_paths.jsonl"
        inputs = [aud / "inscope_units.jsonl", aud / "value_moving_functions.json"]
        source_mtime = _newest_declared_source_mtime(ws)
        return artifact, inputs, source_mtime
    if script == "assumption-enumeration-falsification.py":
        return aud / "assumption_falsification_obligations.jsonl", [
            aud / "dataflow_paths.jsonl",
            aud / "value_moving_functions.json",
            aud / "guard_completeness.jsonl",
        ], 0.0
    return None, [], 0.0


def _artifact_is_fresh(
    artifact: pathlib.Path, inputs: list[pathlib.Path], extra_mtime: float = 0.0
) -> bool:
    if not artifact.is_file():
        return False
    try:
        artifact_mtime = artifact.stat().st_mtime
    except OSError:
        return False
    input_mtimes = []
    for path in inputs:
        try:
            input_mtimes.append(path.stat().st_mtime)
        except OSError:
            continue
    return artifact_mtime >= max([*input_mtimes, extra_mtime], default=0.0)


def _autorun_producers(ws: pathlib.Path) -> list[dict]:
    """Run the substrates and return a per-producer log with honest exit status."""
    log: list[dict] = []
    for script, tail in _producer_commands(ws):
        path = _TOOLS_DIR / script
        if not path.is_file():
            log.append({"producer": script, "ok": False,
                        "reason": "producer-script-not-found"})
            continue
        artifact, inputs, extra_mtime = _producer_artifact_and_inputs(ws, script)
        if artifact is not None and _artifact_is_fresh(artifact, inputs, extra_mtime):
            log.append({"producer": script, "ok": True, "ran": False,
                        "status": "skipped-fresh", "artifact": str(artifact),
                        "reason": "durable substrate is newer than declared inputs"})
            continue
        try:
            cp = subprocess.run(
                [sys.executable, str(path), *tail],
                capture_output=True, text=True, timeout=4200)
            log.append({"producer": script, "ok": cp.returncode == 0,
                        "returncode": cp.returncode,
                        "stderr_tail": (cp.stderr or "")[-400:]})
        except Exception as exc:  # noqa: BLE001 - report, never crash the join
            log.append({"producer": script, "ok": False,
                        "reason": f"{type(exc).__name__}: {exc}"})
    return log


def _guard_enforces(assumption: str, guard_exprs: list) -> str | None:
    """Return the enforcing guard expr if any guard on the path enforces A, else
    None. This is the closure-guard primitive REUSED - a guard whose expr matches
    A's enforcement signature means A IS enforced on this path (so not-A does NOT
    hold and the path is not a survivor)."""
    rx = _ENFORCE_RX.get(assumption)
    if rx is None:
        return None
    for e in guard_exprs:
        if rx.search(e or ""):
            return e
    return None


# ---------------------------------------------------------------------------
# Core reachability join.
# ---------------------------------------------------------------------------

def run(ws: pathlib.Path, src_root: str | None = None) -> dict:
    # 1. A set (present assumptions per unit) from the sibling engine - REUSED.
    sib_rep = _SIB.run(ws)
    present_by_unit: dict = defaultdict(list)
    for u in sib_rep.get("units", []):
        for o in u.get("assumptions", []):
            if o.get("advisory"):
                continue  # advisory-only axes (no-overflow) carry no enforce sig
            if o.get("assumption") not in _ENFORCE_RX:
                continue
            if not o.get("present_signal"):
                continue
            present_by_unit[u["unit"]].append({
                "assumption": o["assumption"],
                "present_signal": o["present_signal"],
                "file": u.get("file", ""),
                "function": u.get("function", ""),
            })

    # 2. Concrete per-path substrate.
    paths_by_unit, stats = load_paths(ws)

    substrate_vacuous = (not stats["file_present"]) or stats["kept"] == 0 \
        or stats["entrypoint_paths"] == 0

    survivors: list = []
    needs_source: list = []

    if not substrate_vacuous:
        for unit, assumps in sorted(present_by_unit.items()):
            unit_paths = paths_by_unit.get(unit, [])
            # entrypoint-reachable impact paths for this unit
            impact_paths = [p for p in unit_paths if p["reachable"] and p["sink_classes"]]
            for a in assumps:
                axis = a["assumption"]
                want_class = _IMPACT_CLASS.get(axis)
                # candidate impact paths whose sink class matches the negation's
                # impact class (fallback: any impact sink if class unknown).
                cand = [p for p in impact_paths
                        if (want_class in p["sink_classes"]) or (want_class is None)]
                if not cand:
                    # assumption present but no entrypoint-reachable impact path
                    # in the substrate for it -> advisory needs_source (never dropped).
                    needs_source.append({
                        "unit": unit, "assumption": axis, "file": a["file"],
                        "function": a["function"],
                        "reason": ("assumption present but no entrypoint-reachable "
                                   f"{want_class or 'impact'} path in substrate for this unit"),
                    })
                    continue
                # SURVIVOR: >=1 candidate path with NO inline guard enforcing A
                # AND NOT closure-guarded (a guard dominating the sink in the
                # closure refutes the negation just as an inline guard does).
                surviving_paths = []
                closure_pruned = 0
                for p in cand:
                    enf = _guard_enforces(axis, p["guard_exprs"])
                    if enf is not None:
                        continue
                    if p.get("closure_guarded"):
                        closure_pruned += 1
                        continue
                    surviving_paths.append(p)
                if not surviving_paths:
                    # every impact path is inline- or closure-guarded -> not a
                    # survivor. When closure-guarding is what pruned it, record an
                    # advisory needs_source so the drop is auditable (never silent).
                    if closure_pruned:
                        needs_source.append({
                            "unit": unit, "assumption": axis, "file": a["file"],
                            "function": a["function"],
                            "reason": (f"all {closure_pruned} reachable {want_class or 'impact'} "
                                       "path(s) are closure-guarded (compensating guard "
                                       "dominates the sink) - negation refuted pre-emit"),
                            "guard_closure_dominated": True,
                        })
                    continue
                # cite the shortest / first surviving path.
                sp = surviving_paths[0]
                survivors.append({
                    "unit": unit,
                    "assumption": axis,
                    "assumption_present": a["present_signal"],
                    "negation": _NEGATION.get(axis, f"not({axis})"),
                    "impact_class": want_class,
                    "impact_sink": sp["sink"],
                    "reachable_path": {
                        "path_id": sp["path_id"],
                        "entrypoint": sp["source"],
                        "sink": sp["sink"],
                        "guard_exprs_on_path": sp["guard_exprs"],
                    },
                    "file": a["file"],
                    "function": a["function"],
                    "line": sp["source"].get("line", 0),
                    "n_surviving_paths": len(surviving_paths),
                })

    status = "substrate_vacuous" if substrate_vacuous else (
        "survivors" if survivors else "cited_empty")

    return {
        "schema": SCHEMA,
        "workspace": str(ws),
        "src_root": src_root or "",
        "status": status,
        "substrate": {
            "dataflow_paths_present": stats["file_present"],
            "records": stats["records"],
            "kept_paths": stats["kept"],
            "entrypoint_paths": stats["entrypoint_paths"],
            "entrypoint_impact_paths": stats["impact_paths"],
            "vacuous": substrate_vacuous,
        },
        "assumption_units": len(present_by_unit),
        "assumption_present_total": sum(len(v) for v in present_by_unit.values()),
        "survivor_count": len(survivors),
        "needs_source_count": len(needs_source),
        "survivors": survivors,
        "needs_source": needs_source,
        "by_axis": _by_axis(survivors),
    }


def _by_axis(survivors: list) -> dict:
    d: dict = defaultdict(int)
    for s in survivors:
        d[s["assumption"]] += 1
    return dict(sorted(d.items()))


def _emit_rows(rep: dict, outp: pathlib.Path) -> int:
    outp.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with outp.open("w") as fh:
        for s in rep["survivors"]:
            row = {
                "schema": SCHEMA,
                "novelty": "ASSUMPTION-NEGATION",
                "verdict": "survivor",
                "proof_status": "open",
                "corpus_class": None,
                "attack_class": "novel-assumption-negation",
                **s,
            }
            fh.write(json.dumps(row) + "\n")
            n += 1
        for ns in rep["needs_source"]:
            row = {
                "schema": SCHEMA,
                "novelty": "ASSUMPTION-NEGATION",
                "verdict": "needs_source",
                "proof_status": "open",
                "advisory": True,
                "corpus_class": None,
                "attack_class": "novel-assumption-negation",
                **ns,
            }
            fh.write(json.dumps(row) + "\n")
            n += 1
        # Capability-vacuity-telltale: the reachability join RAN over materialized
        # param-entrypoint paths and produced 0 survivors (status "cited_empty").
        # PERSIST an explicit cited-empty examined-record so the reasoner-firing gate
        # scores this FIRED_CLEAN (ran, examined, recorded 0) not silently VACUOUS.
        # substrate_vacuous (no materialized paths) is NOT greened here.
        if n == 0 and rep.get("status") == "cited_empty":
            sub = rep.get("substrate", {}) if isinstance(rep.get("substrate"), dict) else {}
            fh.write(json.dumps({
                "schema": SCHEMA,
                "novelty": "ASSUMPTION-NEGATION",
                "verdict": "cited_empty",
                "advisory": True,
                "note": ("cited-empty: assumption-negation reachability join ran over "
                         "materialized entrypoint paths, 0 negated-assumption survivors"),
                "survivors": [],
                "report": {"reasoner": "assumption-negation-reachability",
                           "status": rep.get("status"),
                           "totals": {"examined": int(
                               rep.get("assumption_present_total", 0)
                               or sub.get("kept", 0) or 0)}},
            }) + "\n")
            n += 1
    return n


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--src-root", default=None,
                    help="source root (advisory; anchors are cited from backends)")
    ap.add_argument("--emit", default=None,
                    help="output jsonl path (default <ws>/.auditooor/assumption_negation_obligations.jsonl)")
    ap.add_argument("--json", action="store_true", help="emit full report JSON to stdout")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit non-zero on substrate_vacuous (cannot run the join)")
    ap.add_argument("--autorun-producers", action="store_true",
                    help="run the dataflow backend + assumption-enumeration engine "
                         "first so dataflow_paths.jsonl materializes before the join "
                         "(never fabricates a survivor; substrate_vacuous still fires "
                         "if nothing materializes)")
    args = ap.parse_args(argv)

    ws = pathlib.Path(args.workspace).resolve()
    if not ws.exists():
        print(f"[err] workspace not found: {ws}", file=sys.stderr)
        return 2

    producer_log = None
    if args.autorun_producers:
        producer_log = _autorun_producers(ws)
        for r in producer_log:
            status = "ok" if r.get("ok") else f"FAIL ({r.get('reason') or r.get('returncode')})"
            print(f"[assumption-negation autorun] {r['producer']}: {status}",
                  file=sys.stderr)
        failed = [r for r in producer_log if not r.get("ok")]
        if failed:
            print("[assumption-negation] FAIL-CLOSED: required producer failed",
                  file=sys.stderr)
            return 2

    rep = run(ws, src_root=args.src_root)
    if producer_log is not None:
        rep["autorun_producers"] = producer_log

    outp = pathlib.Path(args.emit) if args.emit else (
        _adir(ws) / "assumption_negation_obligations.jsonl")
    n = _emit_rows(rep, outp)

    if args.json:
        print(json.dumps(rep, indent=2, default=list))
    else:
        print(f"[assumption-negation] ws={ws.name} status={rep['status']} "
              f"assumptions_present={rep['assumption_present_total']} "
              f"survivors={rep['survivor_count']} needs_source={rep['needs_source_count']} "
              f"-> {outp} ({n} rows)", file=sys.stderr)
        sub = rep["substrate"]
        print(f"    substrate: paths_present={sub['dataflow_paths_present']} "
              f"kept={sub['kept_paths']} entrypoint={sub['entrypoint_paths']} "
              f"entrypoint_impact={sub['entrypoint_impact_paths']} vacuous={sub['vacuous']}",
              file=sys.stderr)
        for a, c in rep["by_axis"].items():
            print(f"    {a:18s} survivors={c}", file=sys.stderr)

    if args.fail_closed and rep["status"] == "substrate_vacuous":
        print("[assumption-negation] FAIL-CLOSED: substrate vacuous (join could not run)",
              file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
