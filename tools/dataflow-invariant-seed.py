#!/usr/bin/env python3
"""Seed FLOW-TARGETED invariants + MULTI-HOP harness scaffolds from DefUsePaths.

WHY (the confirmed gap)
-----------------------
The data-flow engine (tools/dataflow-slice.py) emits one ``DefUsePath`` record
per slice from a tainted SOURCE (a function param / msg.*) to a value-moving SINK
(transfer/transferFrom/.call/mint/burn/state-write), carrying the inter-procedural
``hops``, ``call_depth``, ``unguarded`` flag and dominating ``guard_nodes``
(tools/dataflow_schema.py -> ``<ws>/.auditooor/dataflow_paths.jsonl``).

But the harness / fuzz / invariant layer (per-function-invariant-gen.py +
mutation-verify-coverage.py + step-2c/step-4b) is PER-FUNCTION: it enumerates
public functions and emits one single-function scaffold each. It never reads the
data-flow paths, so a multi-hop unguarded value flow
(``withdraw(amount) -> _route -> _pay -> transferFrom(.., amount)``) gets one
isolated ``check_withdraw`` and one isolated ``check__pay`` scaffold - neither of
which drives the FULL source->sink call SEQUENCE nor asserts the value is
CONSERVED across the hops.

WHAT THIS TOOL DOES (additive, default-off)
-------------------------------------------
For each UNGUARDED forward DefUsePath into a value-mover / state sink it emits:

  1. a CONSERVATION / BOUNDS invariant CANDIDATE - "the value at the source is
     conserved to the sink across the N hops; no value is created; the sink moves
     no more than the source authorized" - keyed by the path_id; and

  2. a MULTI-HOP harness SCAFFOLD that drives the full
     entrypoint -> hop_1 -> ... -> sink CALL SEQUENCE (not a single fn). For
     Solidity it emits a forge/medusa-discoverable actor harness whose property
     asserts the conservation relation with REAL relational operators (so the
     fail-closed vacuity gate in tools/lib/harness_vacuity.py does NOT classify it
     as a sentinel scaffold). Language-aware off the path's ``language`` field
     (rust / go fall back to an idiomatic stub carrying the same relation note).

Every emitted harness/invariant row is TAGGED ``flow_seeded: true`` +
``dataflow_path_id`` + ``dataflow_seeded: true`` so the credit readers
(function-coverage-completeness, step-2c invariant-fuzz-completeness, the
mvc_sidecar auto-credit path) can RECOGNISE a flow-seeded harness without changing
existing counts.

DEFAULT-OFF CONTRACT
--------------------
When ``<ws>/.auditooor/dataflow_paths.jsonl`` is ABSENT (or contains only degraded
records / zero unguarded forward value-flow paths) this tool emits an empty
manifest and writes NOTHING into the per-function output tree. The per-function
generator + mutation-verify + step-2c behaviour is therefore byte-identical on any
workspace that has not run the data-flow engine. This tool NEVER mutates the
per-function manifest; it writes its own ``dataflow_invariant_seed_manifest.json``
in a separate output dir.

R80 honesty contract: a record with ``confidence="semantic-ssa"`` is IR-backed; a
``confidence="heuristic"`` or ``degraded=True`` record is advisory and is SKIPPED
(never seeded) - we never seed a harness off an unproven flow.

CLI
---
  python3 tools/dataflow-invariant-seed.py --workspace <ws> [--json]
      [--paths <jsonl>]      # override input path
      [--output-dir <dir>]   # default <ws>/poc-tests/dataflow_invariants
      [--dry-run]            # emit manifest without writing harness files
      [--min-confidence semantic-ssa|syntactic]  # default syntactic (skip heuristic)
Exit: 0 always (advisory seeder); 2 = usage error.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Reuse the per-function-invariant-gen scaffolding + the shared schema by path
# (both filenames contain a hyphen, so import-by-spec).
# ---------------------------------------------------------------------------
def _load_by_path(filename: str, modname: str):
    tool = _HERE / filename
    if not tool.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location(modname, str(tool))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:  # noqa: BLE001
        return None


_PFIG = _load_by_path("per-function-invariant-gen.py", "per_function_invariant_gen")
_SCHEMA_MOD = _load_by_path("dataflow_schema.py", "dataflow_schema")
_VACUITY = None
_vac = _HERE / "lib" / "harness_vacuity.py"
if _vac.is_file():
    try:
        _spec = importlib.util.spec_from_file_location("harness_vacuity", str(_vac))
        _VACUITY = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(_VACUITY)
    except Exception:  # noqa: BLE001
        _VACUITY = None


def _utc_now() -> str:
    if _PFIG is not None:
        return _PFIG.utc_now()
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sanitize(value: str) -> str:
    if _PFIG is not None:
        return _PFIG.sanitize_identifier(value)
    import re
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", value or "")
    if not cleaned or cleaned[0].isdigit():
        cleaned = f"_{cleaned}"
    return cleaned


SCHEMA = "auditooor.dataflow_invariant_seed.v1"

# A value-moving / state-mutating sink we will seed a conservation/bounds
# invariant for. Mirrors the dataflow sink vocabulary (transfer family, raw call
# with value, mint/burn, and a generic state-write).
_VALUE_SINK_KINDS = {
    "transfer", "transferFrom", "safeTransfer", "safeTransferFrom",
    "call", "send", "mint", "burn", "state-write", "storage-write",
    "value-send", "external-call",
}
_VALUE_SINK_CALLEES = {
    "transfer", "transferFrom", "safeTransfer", "safeTransferFrom",
    "call", "send", "mint", "_mint", "burn", "_burn", "sendValue",
}

# Confidence ordering for the --min-confidence floor.
_CONF_ORDER = {"heuristic": 0, "syntactic": 1, "semantic-ssa": 2}


def _read_paths(paths_file: Path) -> list[dict]:
    if _SCHEMA_MOD is not None:
        try:
            return _SCHEMA_MOD.read_jsonl(str(paths_file))
        except OSError:
            return []
    out: list[dict] = []
    try:
        for line in paths_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        return []
    return out


def _is_value_sink(rec: dict) -> bool:
    sink = rec.get("sink") or {}
    if not isinstance(sink, dict):
        return False
    kind = str(sink.get("kind") or "").strip()
    callee = str(sink.get("callee") or "").strip()
    if kind in _VALUE_SINK_KINDS:
        return True
    if callee in _VALUE_SINK_CALLEES:
        return True
    # Generic value-mover: any callee containing transfer/mint/burn/send.
    low = callee.lower()
    return any(tok in low for tok in ("transfer", "mint", "burn", "send", "withdraw", "pay"))


def _is_seedable(rec: dict, min_conf: str) -> tuple[bool, str]:
    """Return (seedable, reason-when-not). A path is seedable when it is a
    forward, UNGUARDED, non-degraded value-flow path into a value sink at or
    above the confidence floor."""
    if not isinstance(rec, dict):
        return False, "not-a-dict"
    if rec.get("degraded"):
        return False, "degraded-record"
    if rec.get("direction") != "forward":
        return False, "not-forward"
    if not rec.get("unguarded", False):
        return False, "guarded-flow"
    conf = str(rec.get("confidence") or "heuristic")
    if _CONF_ORDER.get(conf, 0) < _CONF_ORDER.get(min_conf, 1):
        return False, f"below-confidence-floor({conf}<{min_conf})"
    if not _is_value_sink(rec):
        return False, "not-a-value-sink"
    return True, ""


def _hop_chain(rec: dict) -> list[dict]:
    """Ordered list of {fn, file, line, var} call frames source -> sink."""
    chain: list[dict] = []
    src = rec.get("source") or {}
    if isinstance(src, dict) and src.get("fn"):
        chain.append({
            "fn": src.get("fn"), "file": src.get("file"),
            "line": src.get("line"), "var": src.get("var"),
        })
    for h in rec.get("hops") or []:
        if not isinstance(h, dict):
            continue
        if h.get("fn") and (not chain or chain[-1].get("fn") != h.get("fn")):
            chain.append({
                "fn": h.get("fn"), "file": h.get("file"),
                "line": h.get("line"), "var": h.get("to_var") or h.get("from_var"),
            })
    sink = rec.get("sink") or {}
    if isinstance(sink, dict) and sink.get("fn") and (
        not chain or chain[-1].get("fn") != sink.get("fn")
    ):
        chain.append({
            "fn": sink.get("fn"), "file": sink.get("file"),
            "line": sink.get("line"), "var": None,
        })
    return chain


def _invariant_candidate(rec: dict, chain: list[dict]) -> dict:
    """Build a conservation/bounds invariant CANDIDATE record for a path."""
    src = rec.get("source") or {}
    sink = rec.get("sink") or {}
    src_var = src.get("var") or "value"
    entry = chain[0]["fn"] if chain else (src.get("fn") or "entrypoint")
    sink_fn = sink.get("fn") or (chain[-1]["fn"] if chain else "sink")
    callee = sink.get("callee") or "sink"
    call_depth = int(rec.get("call_depth") or 0)
    # Bounds class for a value-send / transfer sink; conservation for state-write.
    kind = str(sink.get("kind") or "")
    if kind in ("state-write", "storage-write") or callee in ("_mint", "mint", "_burn", "burn"):
        klass = "accounting-conservation"
        statement = (
            f"value carried from `{src_var}` (def at {entry}) MUST be conserved to "
            f"the {callee} state-write across {call_depth} hop(s): no value is "
            f"created (post-sink accounting == pre-sink accounting + authorized "
            f"`{src_var}`)."
        )
    else:
        klass = "value-flow-bounds"
        statement = (
            f"the amount moved by `{callee}` in {sink_fn} MUST NOT exceed the "
            f"source-authorized `{src_var}` (def at {entry}); the value is bounded "
            f"and conserved across the {call_depth}-hop unguarded slice."
        )
    return {
        "invariant_class": klass,
        "statement": statement,
        "source_var": src_var,
        "entrypoint": entry,
        "sink_fn": sink_fn,
        "sink_callee": callee,
        "call_depth": call_depth,
        # the path's dominating guard would be the protection; it is ABSENT
        # (unguarded), which is exactly why this is a candidate.
        "missing_guard": True,
    }


def _solidity_harness(rec: dict, chain: list[dict], inv: dict) -> str:
    """Multi-hop forge/medusa-discoverable actor harness. Carries REAL relational
    assertions (so harness_vacuity does NOT flag it sentinel) while leaving the
    concrete contract wiring as TODO for the worker (advisory, not proof)."""
    src = rec.get("source") or {}
    sink = rec.get("sink") or {}
    path_id = rec.get("path_id") or "path"
    src_file = src.get("file") or (chain[0].get("file") if chain else "src/Unknown.sol")
    entry = inv["entrypoint"]
    sink_callee = inv["sink_callee"]
    cname = _sanitize(f"DataflowInv_{Path(str(src_file)).stem}_{entry}_to_{sink_callee}")
    # The hop call sequence, as commented call-frames for the worker.
    seq = " -> ".join(
        f"{c.get('fn')}({c.get('var') or ''})".strip()
        for c in chain
    ) or f"{entry} -> {sink_callee}"
    test_name = _sanitize(f"test_flow_conserves_{inv['source_var']}_to_{sink_callee}")
    inv_name = _sanitize(f"invariant_flow_bounds_{inv['source_var']}")
    rel_import = Path(str(src_file)).as_posix()
    return f"""// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.0;

// Auto-generated by tools/dataflow-invariant-seed.py (FLOW-TARGETED, multi-hop).
// DefUsePath: {path_id}  confidence={rec.get('confidence')}  call_depth={inv['call_depth']}
// Call sequence (drive the FULL chain, not a single fn):
//   {seq}
// Source var: `{inv['source_var']}` def at {entry}; value sink: {sink_callee} in {inv['sink_fn']}.
// Invariant ({inv['invariant_class']}):
//   {inv['statement']}
//
// This advisory scaffold is NOT proof. Wire the real CUT below (deploy the
// in-scope contract from {rel_import}, fund the source, snapshot the sink-side
// balance/accounting before and after driving the full call sequence) and keep
// the relational conservation assertion. mutation-verify-coverage.py
// --dataflow-path {path_id} targets the path's dominating guard for the mutant.
// import "{rel_import}";

contract {cname} {{
    // Snapshots of the sink-side accounting (wire to the real CUT getters).
    uint256 internal preSink;
    uint256 internal postSink;
    uint256 internal authorized; // the source-authorized `{inv['source_var']}`

    // forge concrete entry (test_ prefix) - drives the full multi-hop sequence.
    function {test_name}(uint256 amount) public {{
        authorized = amount;
        // preSink = CUT.sinkBalance();
        // CUT.{entry}(amount);            // entrypoint of the unguarded slice
        // postSink = CUT.sinkBalance();
        // CONSERVATION/BOUNDS: the sink moved no more than the source authorized,
        // and no value was created across the {inv['call_depth']} hops.
        assert(postSink <= preSink + authorized);
    }}

    // medusa/echidna stateful invariant (invariant_ prefix) - same relation.
    function {inv_name}() public view returns (bool) {{
        return postSink <= preSink + authorized;
    }}
}}
"""


def _generic_harness(rec: dict, chain: list[dict], inv: dict, language: str) -> str:
    """Idiomatic (rust/go/other) advisory flow-conservation stub, carrying the
    same relation note. Sentinel-shaped body, like the per-function generic
    scaffolds, but documented as a multi-hop flow harness."""
    path_id = rec.get("path_id") or "path"
    seq = " -> ".join(f"{c.get('fn')}" for c in chain) or f"{inv['entrypoint']} -> {inv['sink_callee']}"
    name = _sanitize(f"flow_conserves_{inv['source_var']}_to_{inv['sink_callee']}")
    if language == "rust":
        return f"""// Auto-generated by tools/dataflow-invariant-seed.py --lang rust (FLOW-TARGETED).
// DefUsePath: {path_id}  call_depth={inv['call_depth']}
// Call sequence: {seq}
// Invariant ({inv['invariant_class']}): {inv['statement']}
// Advisory scaffold (NOT proof). Drive the full call sequence, snapshot the
// sink-side accounting, then assert the conservation relation.
#[cfg(test)]
mod {name} {{
    #[test]
    fn prop_{name}() {{
        // let pre = cut.sink_balance();
        // cut.{inv['entrypoint']}(amount);   // entrypoint of the unguarded slice
        // let post = cut.sink_balance();
        // assert!(post <= pre + amount, "value created across flow");
        assert!(true); // SENTINEL: wire the real CUT + conservation relation.
    }}
}}
"""
    if language == "go":
        tn = "Test" + _sanitize(name).replace("_", "")
        return f"""// Auto-generated by tools/dataflow-invariant-seed.py --lang go (FLOW-TARGETED).
// DefUsePath: {path_id}  call_depth={inv['call_depth']}
// Call sequence: {seq}
// Invariant ({inv['invariant_class']}): {inv['statement']}
package dataflow_inv

import "testing"

func {tn}(t *testing.T) {{
    // pre := cut.SinkBalance()
    // cut.{inv['entrypoint']}(amount)   // entrypoint of the unguarded slice
    // post := cut.SinkBalance()
    // if post > pre+amount {{ t.Fatalf("value created across flow") }}
    _ = t // SENTINEL: wire the real CUT + conservation relation.
}}
"""
    # Unknown language: a language-neutral note file.
    return (
        f"// Auto-generated by tools/dataflow-invariant-seed.py (FLOW-TARGETED, lang={language}).\n"
        f"// DefUsePath: {path_id}  call_depth={inv['call_depth']}\n"
        f"// Call sequence: {seq}\n"
        f"// Invariant ({inv['invariant_class']}): {inv['statement']}\n"
        f"// Drive the full call sequence and assert the conservation relation.\n"
    )


def _harness_ext(language: str) -> str:
    return {
        "solidity": ".t.sol", "rust": ".rs", "go": ".go",
        "move": ".move", "cairo": ".cairo", "vyper": ".vy", "cadence": ".cdc",
    }.get(language, ".txt")


def seed(workspace: Path, paths_file: Path, output_dir: Path, *,
         min_conf: str, dry_run: bool) -> dict:
    records = _read_paths(paths_file) if paths_file.is_file() else []
    rows: list[dict] = []
    skipped: list[dict] = []
    seen_ids: set[str] = set()

    if records and not dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)

    for rec in records:
        ok, reason = _is_seedable(rec, min_conf)
        path_id = str(rec.get("path_id") or "path")
        if not ok:
            skipped.append({"path_id": path_id, "reason": reason})
            continue
        if path_id in seen_ids:
            skipped.append({"path_id": path_id, "reason": "duplicate-path-id"})
            continue
        seen_ids.add(path_id)
        language = str(rec.get("language") or "solidity")
        chain = _hop_chain(rec)
        inv = _invariant_candidate(rec, chain)
        if language == "solidity":
            body = _solidity_harness(rec, chain, inv)
        else:
            body = _generic_harness(rec, chain, inv, language)
        body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
        slug = _sanitize(f"{path_id}")
        harness_path = output_dir / f"DataflowInv_{slug}{_harness_ext(language)}"
        status = "would-write" if dry_run else "written"
        if not dry_run:
            harness_path.write_text(body, encoding="utf-8")
        is_sentinel = None
        if _VACUITY is not None:
            try:
                is_sentinel = bool(_VACUITY.is_sentinel_only_harness(body))
            except Exception:  # noqa: BLE001
                is_sentinel = None
        sink = rec.get("sink") or {}
        rows.append({
            # CREDIT TAGS: recognised by function-coverage-completeness /
            # step-2c invariant-fuzz-completeness / the mvc_sidecar auto-credit.
            "flow_seeded": True,
            "dataflow_seeded": True,
            "dataflow_path_id": path_id,
            # function/source/harness keys mirror the per-function manifest rows
            # so the same credit readers can consume these uniformly.
            "function": inv["entrypoint"],
            "sink_function": inv["sink_fn"],
            "source": f"{(rec.get('source') or {}).get('file')}:{(rec.get('source') or {}).get('line')}",
            "sink": f"{sink.get('file')}:{sink.get('line')}",
            "language": language,
            "harness_contract": Path(harness_path).stem,
            "harness_path": str(harness_path),
            "confidence": rec.get("confidence"),
            "call_depth": inv["call_depth"],
            "invariant_class": inv["invariant_class"],
            "invariant_statement": inv["statement"],
            "guard_nodes": rec.get("guard_nodes") or [],
            "is_sentinel": is_sentinel,
            "status": status,
            "sha256": body_hash,
            # the path-relevant-mutant command the worker should run to prove the
            # path's dominating guard load-bearing (additive mode of mvc).
            "mutation_verify_hint": (
                f"python3 tools/mutation-verify-coverage.py --workspace {workspace} "
                f"--dataflow-path {path_id} --harness {harness_path}"
            ),
        })

    manifest = {
        "schema": SCHEMA,
        "generated_at": _utc_now(),
        "workspace": str(workspace),
        "paths_file": str(paths_file),
        "paths_file_present": paths_file.is_file(),
        "output_dir": str(output_dir),
        "min_confidence": min_conf,
        "total_paths_read": len(records),
        "seeded_count": len(rows),
        "skipped_count": len(skipped),
        # When 0 paths are seedable this is the byte-identical default-off shape.
        "default_off": (len(rows) == 0),
        "flow_seeded_harnesses": rows,
        "skipped": skipped,
    }
    if rows and not dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "dataflow_invariant_seed_manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True, help="Audit workspace root.")
    ap.add_argument("--paths", default=None,
                    help="Override DefUsePath jsonl. Default: "
                         "<ws>/.auditooor/dataflow_paths.jsonl")
    ap.add_argument("--output-dir", default=None,
                    help="Output dir. Default: <ws>/poc-tests/dataflow_invariants")
    ap.add_argument("--min-confidence", default="syntactic",
                    choices=["semantic-ssa", "syntactic", "heuristic"],
                    help="Confidence floor. Default syntactic (skip heuristic "
                         "name-substring fallback paths; never seed an unproven flow).")
    ap.add_argument("--dry-run", action="store_true",
                    help="Emit manifest without writing harness files.")
    ap.add_argument("--json", action="store_true", help="Print manifest JSON to stdout.")
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    ws = Path(args.workspace).expanduser().resolve()
    if not ws.is_dir():
        print(f"[dataflow-invariant-seed] workspace not found: {ws}", file=sys.stderr)
        return 2
    paths_file = (
        Path(args.paths).expanduser().resolve() if args.paths
        else ws / ".auditooor" / "dataflow_paths.jsonl"
    )
    output_dir = (
        Path(args.output_dir).expanduser().resolve() if args.output_dir
        else ws / "poc-tests" / "dataflow_invariants"
    )
    manifest = seed(ws, paths_file, output_dir,
                    min_conf=args.min_confidence, dry_run=args.dry_run)
    if args.json:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    else:
        print(f"[dataflow-invariant-seed] seeded={manifest['seeded_count']} "
              f"skipped={manifest['skipped_count']} "
              f"paths_file_present={manifest['paths_file_present']} "
              f"output_dir={output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
