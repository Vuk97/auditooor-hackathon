"""DefUsePath schema (v1) - frozen record + validator shared by producers/consumers.

A DefUsePath is one def-use slice from a tainted SOURCE (function param / msg.*)
to a value-moving SINK (transfer/transferFrom/call/mint/burn/state-write), with the
inter-procedural call hops it crossed and whether a guard (require/assert/compare)
dominates the slice.

Producer (Phase 1 Solidity arm): tools/dataflow-slice.py
  - writes one record per line to <ws>/.auditooor/dataflow_paths.jsonl

Consumers: detectors/_predicate_engine.py (function.value_flow_path /
function.unguarded_value_flow_to), and any future cross-language arm.

The schema is intentionally engine-agnostic: a Go/Rust arm can emit the same record
with its own `engine`/`confidence` so downstream tooling stays uniform.

R80 honesty contract: a record with confidence="semantic-ssa" is IR-backed. A record
with confidence="heuristic" (name-substring fallback) or degraded=True is advisory and
MUST NOT be cited as a proven flow. A degrade record carries
engine="unsupported-or-compile-fail-degrade".
"""
from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Tuple

SCHEMA_VERSION = "dataflow_path.v1"

# canonical enums
DIRECTIONS = {"forward", "backward"}
CONFIDENCES = {"semantic-ssa", "syntactic", "heuristic"}
HOP_VIA = {"internal_call", "high_level", "return", "boundary", "intra", "storage"}

# top-level required keys (frozen v1)
_TOP_KEYS = (
    "schema",
    "path_id",
    "language",
    "direction",
    "engine",
    "source",
    "sink",
    "hops",
    "call_depth",
    "unguarded",
    "guard_nodes",
    "source_unit_ids",
    "sink_unit_ids",
    "confidence",
    "degraded",
)

_SOURCE_KEYS = ("kind", "fn", "var", "file", "line")
_SINK_KEYS = ("kind", "callee", "arg_pos", "fn", "file", "line")
_HOP_KEYS = ("from_var", "to_var", "fn", "via", "file", "line", "ir", "guarded")
_GUARD_KEYS = ("file", "line", "expr")


def new_path(
    path_id: str,
    language: str,
    direction: str,
    engine: str,
    source: Dict[str, Any],
    sink: Dict[str, Any],
    hops: List[Dict[str, Any]],
    guard_nodes: List[Dict[str, Any]] | None = None,
    source_unit_ids: List[Any] | None = None,
    sink_unit_ids: List[Any] | None = None,
    confidence: str = "semantic-ssa",
    degraded: bool = False,
) -> Dict[str, Any]:
    """Build a v1 DefUsePath record. call_depth + unguarded are derived from hops/guards."""
    guard_nodes = guard_nodes or []
    hops = hops or []
    # call_depth = number of inter-procedural hops crossed
    #   (via in {internal_call,high_level,return,storage} - a storage-mediated def->use
    #    write@fnA -> read@fnB is a genuine cross-function hop too).
    call_depth = sum(1 for h in hops
                     if h.get("via") in ("internal_call", "high_level", "return", "storage"))
    any_hop_guarded = any(h.get("guarded") for h in hops)
    unguarded = not (bool(guard_nodes) or any_hop_guarded)
    return {
        "schema": SCHEMA_VERSION,
        "path_id": path_id,
        "language": language,
        "direction": direction,
        "engine": engine,
        "source": source,
        "sink": sink,
        "hops": hops,
        "call_depth": call_depth,
        "unguarded": unguarded,
        "guard_nodes": guard_nodes,
        "source_unit_ids": source_unit_ids or [],
        "sink_unit_ids": sink_unit_ids or [],
        "confidence": confidence,
        "degraded": bool(degraded),
    }


def degrade_record(language: str, reason: str) -> Dict[str, Any]:
    """R80 degrade contract: an advisory empty record on compile/engine failure."""
    return {
        "schema": SCHEMA_VERSION,
        "path_id": "degrade-0",
        "language": language,
        "direction": "backward",
        "engine": "unsupported-or-compile-fail-degrade",
        "source": {"kind": "none", "fn": None, "var": None, "file": None, "line": None},
        "sink": {"kind": "none", "callee": None, "arg_pos": None, "fn": None, "file": None, "line": None},
        "hops": [],
        "call_depth": 0,
        "unguarded": False,
        "guard_nodes": [],
        "source_unit_ids": [],
        "sink_unit_ids": [],
        "confidence": "heuristic",
        "degraded": True,
        "degrade_reason": reason,
    }


def validate(rec: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Return (ok, errors). Strict enough to keep producers honest, loose on payload values."""
    errs: List[str] = []
    if not isinstance(rec, dict):
        return False, ["record is not a dict"]
    for k in _TOP_KEYS:
        if k not in rec:
            errs.append(f"missing top key: {k}")
    if rec.get("schema") != SCHEMA_VERSION:
        errs.append(f"schema mismatch: {rec.get('schema')!r} != {SCHEMA_VERSION!r}")
    if rec.get("direction") not in DIRECTIONS:
        errs.append(f"bad direction: {rec.get('direction')!r}")
    if rec.get("confidence") not in CONFIDENCES:
        errs.append(f"bad confidence: {rec.get('confidence')!r}")
    if not isinstance(rec.get("degraded"), bool):
        errs.append("degraded must be bool")
    if not isinstance(rec.get("unguarded"), bool):
        errs.append("unguarded must be bool")
    if not isinstance(rec.get("call_depth"), int):
        errs.append("call_depth must be int")
    src = rec.get("source")
    if isinstance(src, dict):
        for k in _SOURCE_KEYS:
            if k not in src:
                errs.append(f"source missing key: {k}")
    else:
        errs.append("source must be a dict")
    snk = rec.get("sink")
    if isinstance(snk, dict):
        for k in _SINK_KEYS:
            if k not in snk:
                errs.append(f"sink missing key: {k}")
    else:
        errs.append("sink must be a dict")
    hops = rec.get("hops")
    if isinstance(hops, list):
        for i, h in enumerate(hops):
            if not isinstance(h, dict):
                errs.append(f"hop[{i}] not a dict")
                continue
            for k in _HOP_KEYS:
                if k not in h:
                    errs.append(f"hop[{i}] missing key: {k}")
            if h.get("via") not in HOP_VIA:
                errs.append(f"hop[{i}] bad via: {h.get('via')!r}")
    else:
        errs.append("hops must be a list")
    gn = rec.get("guard_nodes")
    if isinstance(gn, list):
        for i, g in enumerate(gn):
            if not isinstance(g, dict):
                errs.append(f"guard_nodes[{i}] not a dict")
                continue
            for k in _GUARD_KEYS:
                if k not in g:
                    errs.append(f"guard_nodes[{i}] missing key: {k}")
    else:
        errs.append("guard_nodes must be a list")
    return (len(errs) == 0), errs


def write_jsonl(path: str, records: Iterable[Dict[str, Any]]) -> int:
    """TRUNCATING single-language write (legacy).

    Opens the file in 'w' mode, so it DROPS every record already on disk - including
    rows produced by OTHER language arms. This is correct ONLY for a single-language
    workspace or when a caller deliberately wants a from-scratch rewrite. For the
    polyglot shared sidecar (<ws>/.auditooor/dataflow_paths.jsonl, written by the
    Solidity / Rust / Go / ZK arms in turn) use ``merge_write`` instead, which is
    language-scoped (it preserves other arms' rows). Kept for back-compat: the
    degrade path and any explicit --out single-file caller may still want truncation.
    """
    import os as _os
    parent = _os.path.dirname(_os.path.abspath(path))
    if parent:
        _os.makedirs(parent, exist_ok=True)
    n = 0
    with open(path, "w") as fh:
        for rec in records:
            fh.write(json.dumps(rec, default=str) + "\n")
            n += 1
    return n


def _rec_under_scope(rec: Dict[str, Any], norm_scope: str) -> bool:
    """True iff a record's source or sink file lives under ``norm_scope`` (an
    absolute path prefix). Used to scope a TARGETED re-slice's replace to the
    re-covered subtree only."""
    import os as _os
    for k in ("source", "sink"):
        f = (rec.get(k) or {}).get("file") or ""
        if f:
            try:
                if _os.path.abspath(f).startswith(norm_scope):
                    return True
            except Exception:
                pass
    return False


def merge_write(path: str, records: Iterable[Dict[str, Any]], language: str,
                scope_prefix: Optional[str] = None) -> int:
    """LANGUAGE-SCOPED replace into the shared polyglot sidecar.

    ``scope_prefix`` (optional): when set, this is a TARGETED re-slice that only
    re-covered a subtree, so ONLY prior rows of ``language`` whose source/sink file
    is UNDER scope_prefix are dropped+replaced; same-language rows OUTSIDE the scope
    are PRESERVED. Without it, the whole language is replaced (full-ws run). This
    prevents a targeted re-slice (e.g. dataflow-slice.py --target <subdir>) from
    silently wiping the rest of the language's coverage in the shared sidecar.

    Semantics (mirrors tools/go-dataflow.py:_merge_write, the only arm that was
    merge-correct before this helper existed):

      1. Read every record already on disk at ``path`` (if present).
      2. DROP all prior rows whose ``language`` == ``language`` (this arm's own
         rows - idempotent re-run; also drops any stale degrade for this language).
      3. KEEP every other-language row untouched.
      4. APPEND the new ``records`` (which must all be this arm's ``language``).
      5. Rewrite the file atomically-ish (single open 'w' after the merge).

    This fixes the polyglot TRUNCATION bug: before, the Solidity / Rust / ZK arms
    each opened the shared sidecar with write_jsonl ('w'), so whichever arm ran LAST
    deleted every other arm's rows. After this, running e.g. the Go arm then the
    Solidity arm leaves BOTH languages' rows in the file.

    Returns the number of NEW records written (not the total on disk), matching the
    write_jsonl/_merge_write return contract. A corrupt prior sidecar is rewritten
    from scratch (other-language rows that cannot be parsed are lost - the same
    fail-safe go-dataflow.py:_merge_write used).

    ``language`` is the canonical per-arm tag the arm stamps onto every record's
    ``language`` field (e.g. "solidity", "rust", "go", "circom"). It is passed
    explicitly (rather than inferred from ``records``) so an EMPTY ``records`` list
    still correctly purges this arm's stale rows (e.g. a re-run that now finds zero
    flows must not leave the previous run's rows behind).
    """
    import os as _os
    norm_scope = _os.path.abspath(scope_prefix) if scope_prefix else None
    kept: List[Dict[str, Any]] = []
    if _os.path.exists(path):
        try:
            with open(path) as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    rec = json.loads(line)
                    if rec.get("language") == language:
                        # full-ws run: drop all of this arm's rows. targeted run
                        # (scope_prefix): drop only rows under the re-covered scope;
                        # preserve same-language rows outside it.
                        if norm_scope is None or _rec_under_scope(rec, norm_scope):
                            continue
                    kept.append(rec)
        except Exception:
            kept = []  # corrupt sidecar -> rewrite from scratch
    new_records = list(records)
    kept.extend(new_records)
    parent = _os.path.dirname(_os.path.abspath(path))
    if parent:
        _os.makedirs(parent, exist_ok=True)
    with open(path, "w") as fh:
        for rec in kept:
            fh.write(json.dumps(rec, default=str) + "\n")
    return len(new_records)


def read_jsonl(path: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def read_paths(
    ws,
    *,
    skip_degraded: bool = True,
    languages: "List[str] | None" = None,
) -> List[Dict[str, Any]]:
    """Canonical disk reader for the shared sidecar.

    Consumers (chain-synth / function-coverage-completeness / inscope-hunt /
    dataflow-invariant-seed / mutation-verify-coverage / depth-cert) each
    re-implement "open <ws>/.auditooor/dataflow_paths.jsonl, parse jsonl, skip
    degraded rows". This is that loop, once, so they stop drifting.

    Args:
      ws: workspace root (str | Path); reads <ws>/.auditooor/dataflow_paths.jsonl.
      skip_degraded: when True (default) drop rows with degraded==True (the R80
        advisory-empty records). When False, return them too.
      languages: optional allow-list of language tags; when given, only rows whose
        ``language`` is in the set are returned.

    Returns a list of validated, schema-conforming records. Rows that fail
    ``validate`` are dropped (a producer that wrote a malformed row must not poison
    a consumer). Returns [] when the file is absent or unreadable (never raises) -
    so a no-slice workspace behaves exactly as before any slice existed.
    """
    import os as _os
    base = str(ws)
    path = _os.path.join(base, ".auditooor", "dataflow_paths.jsonl")
    if not _os.path.isfile(path):
        return []
    lang_set = set(languages) if languages is not None else None
    out: List[Dict[str, Any]] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                if not isinstance(rec, dict):
                    continue
                ok, _errs = validate(rec)
                if not ok:
                    continue
                if skip_degraded and rec.get("degraded"):
                    continue
                if lang_set is not None and rec.get("language") not in lang_set:
                    continue
                out.append(rec)
    except OSError:
        return []
    return out
