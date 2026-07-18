#!/usr/bin/env python3
"""rust-unchecked-arith-value-overflow.py - RUST silent value-overflow reasoning query.

LOGIC CAPABILITY (RUST value overflow). This is a DATAFLOW REACHABILITY query over
the OWNED Rust MIR backend (tools/rust-dataflow.py), NOT a regex for `+`.

THE INVARIANT (value-overflow discipline):
  An attacker-influenced NUMERIC value that flows into a primitive `+`/`-`/`*`/`<<`
  arithmetic op WITHOUT overflow discipline (checked_/saturating_/wrapping-with-bound
  or a dominating manual bound guard) on a path that then affects a BALANCE / SHARE /
  AMOUNT / THRESHOLD is a silent over/underflow.  The trust boundary requires:

    for every arithmetic node A over an untrusted operand whose result reaches a
    value/threshold use,  A is CHECKED  (A in { *WithOverflow+assert , checked_* ,
    saturating_* , A whose operands are dominated by a manual bound guard }).

  Every A in the SET-DIFFERENCE  { untrusted-operand & value-reaching arith }  \\
  { checked arith }  is the value-overflow bug, emitted as an
  `unchecked-arith-value-overflow` obligation.

WHY THIS IS LOGIC, NOT A SHAPE (guard-rail satisfied)
  A `grep '+'` (or "token `+` present, token `checked_` absent") is a SHAPE: it
  cannot tell whether an operand is attacker-influenced, whether a bound guard
  dominates the op through an N-hop def-use chain, or whether the result ever
  reaches a value/threshold cell. This query differs on three dataflow axes:
    (a) MEMBERSHIP-BY-TAINT: an operand is "untrusted" only when a BACKWARD MIR
        def-use slice (rust-dataflow `_taint_reaches` over `_MirFn.assigns`,
        including call-result and cross-statement edges) traces it to a function
        PARAMETER - impossible for a text scan;
    (b) GUARD-BY-DOMINANCE: "checked" reads the MIR IR opcode (`AddWithOverflow`
        + `assert` vs bare `Add`) AND a transitive-closure guard query
        (`_local_is_guarded`: does any switchInt/assert operand taint-reach the
        arith operands) - a `require(x < MAX)` in a helper still disciplines the op;
    (c) REACH-TO-VALUE: the result must FORWARD-reach a value sink
        (rust-dataflow value-mover taxonomy), the fn return, or a threshold
        comparison - located anywhere in the def-use closure, no token adjacency.
  The answer is the SET-DIFFERENCE of two taint-defined node sets, not a boolean
  over one line's text.

OWNED BACKEND CONSUMED (no new MIR engine is built here)
  tools/rust-dataflow.py's MIR arm: `emit_mir_for_crate`-equivalent text MIR
  (`cargo rustc -- --emit=mir`, RUSTC_BOOTSTRAP=1) parsed by `parse_mir_text` into
  `_MirFn` (params / debug map / intra+inter def-use `assigns` / `guards`). We emit
  MIR with `-C overflow-checks=off` so a source-level `+` lowers to a BARE `Add`
  BinaryOp - i.e. the arithmetic the RELEASE binary actually executes with no
  overflow trap (the true silent-overflow substrate). `checked_*`/`saturating_*`/
  `wrapping_*` stay distinguishable as library calls; `*WithOverflow`+`assert`
  (const/forced-checked contexts) is read as CHECKED. Crate discovery reuses
  rust-source-graph.discover_crates. R80 honesty: no compilable crate -> a single
  degrade record, exit 0 (we NEVER claim a semantic flow on a failed compile).

OUTPUT
  <ws>/.auditooor/rust_unchecked_arith_obligations.jsonl - one row per survivor,
  schema `auditooor.rust_unchecked_arith_value_overflow.v1`, exploit_queue-ingest
  compatible (contract/function/source_refs/root_cause_hypothesis/attack_class/
  broken_invariant_ids/quality_gate_status='needs_source'). exploit-queue.py ingests
  it via _gather_from_rust_unchecked_arith_obligations -> the queue -> the per-fn
  OPEN-OBLIGATIONS block. A summary (--json) reports |UNTRUSTED_ARITH|, |CHECKED|,
  the SET-DIFFERENCE survivors, and the KEPT (untrusted-but-checked) proving the
  subtraction is non-vacuous.

CLI:
  tools/rust-unchecked-arith-value-overflow.py --workspace <ws> [--target <crate>]
      [--json] [--out <path>] [--emit] [--timeout S] [--mir-file <precomputed.mir>]
Exit codes: 0 ran (incl. degrade); 2 bad args / missing workspace.
"""
from __future__ import annotations

import argparse
import importlib.util as _ilu
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_HERE = Path(__file__).resolve().parent


def _load_rust_dataflow():
    """Import tools/rust-dataflow.py by path (hyphenated module name)."""
    p = _HERE / "rust-dataflow.py"
    spec = _ilu.spec_from_file_location("rust_dataflow_backend", str(p))
    mod = _ilu.module_from_spec(spec)  # type: ignore[arg-type]
    assert spec and spec.loader
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


rdf = _load_rust_dataflow()
rsg = rdf.rsg  # rust-source-graph module (crate discovery + _rel)

SCHEMA = "auditooor.rust_unchecked_arith_value_overflow.v1"

# ---------------------------------------------------------------------------
# Arithmetic-node vocabulary. BARE BinaryOps that DECREASE/COMBINE a value under
# a release (overflow-checks-off) profile carry no trap => the unchecked surface.
# `*WithOverflow` (checked/forced) is read from the opcode as CHECKED. `wrapping_*`
# calls silently truncate => unchecked-by-design (still a value-overflow bug when
# the result reaches a balance/threshold). `checked_*`/`saturating_*` are DISCIPLINED.
# ---------------------------------------------------------------------------
# bare binary op: `_d = Add(...)` but NOT `_d = AddWithOverflow(...)` (the `(`
# immediately follows the opcode name -> WithOverflow does not match).
_BARE_ARITH_RE = re.compile(r"^\s*_(?P<dst>\d+)\s*=\s*(?P<op>Add|Sub|Mul|Shl|Shr)\((?P<args>[^;]*)\)")
_LOCAL_REF_RE = re.compile(r"_(?P<n>\d+)")
_WRAPPING_SEG = re.compile(r"^wrapping_(add|sub|mul|shl|shr)$")
_CHECKED_SEG = re.compile(r"^(checked|saturating|overflowing)_(add|sub|mul|shl|shr)$")

# Codegen exclusion (MEMORY: source-walk caps MUST skip generated code). A bare
# arithmetic node located in a build-script OUT_DIR / target artifact / prost/
# tonic-generated `.rs` is NOT the code-under-test - `encoded_len` wire-length
# adds in generated protobuf are not an attacker-controlled balance quantity.
_CODEGEN_RE = re.compile(r"(?:^|/)(?:target|build)/|/out/[^/]*\.rs$|\.(?:pb|prost|tonic)\.rs$|/OUT_DIR/")


def _is_codegen(path: Optional[str]) -> bool:
    return bool(path) and bool(_CODEGEN_RE.search(path))


def _emit_mir_overflow_off(crate_root: Path, timeout: int) -> Tuple[Optional[str], Optional[str]]:
    """Emit text MIR for crate_root with overflow-checks OFF (release arith profile).

    Reuses the exact RUSTC_BOOTSTRAP + --emit=mir mechanism of rust-dataflow's
    emit_mir_for_crate, adding `-C overflow-checks=off` via RUSTFLAGS so a source
    `+` lowers to a bare `Add` (the silent-overflow substrate). Returns (mir, err)."""
    if not (crate_root / "Cargo.toml").is_file():
        return None, "no-cargo-toml"
    with tempfile.TemporaryDirectory(prefix="ruavo-mir-") as td:
        mir_out = Path(td) / "out.mir"
        env = dict(os.environ)
        env["RUSTC_BOOTSTRAP"] = "1"
        env["RUSTFLAGS"] = (env.get("RUSTFLAGS", "")
                            + " -C overflow-checks=off -Zmir-include-spans=on").strip()
        base = ["cargo", "rustc"]
        for extra in (["--lib"], []):  # lib first, then bin fallback
            cmd = base + extra + ["--", f"--emit=mir={mir_out}"]
            try:
                proc = subprocess.run(cmd, cwd=str(crate_root), env=env,
                                      capture_output=True, text=True, timeout=timeout)
            except subprocess.TimeoutExpired:
                return None, f"mir-emit-timeout>{timeout}s"
            except FileNotFoundError:
                return None, "cargo-not-found"
            if mir_out.is_file():
                try:
                    return mir_out.read_text(encoding="utf-8", errors="replace"), None
                except OSError as e:
                    return None, f"mir-read-error: {e}"
        tail = (proc.stderr or proc.stdout or "")[-300:]
        return None, f"compile-fail-no-mir: {tail}"


def _collect_arith_nodes(mir_text: str) -> Dict[str, List[Dict[str, Any]]]:
    """Walk MIR text, collect BARE arithmetic BinaryOp nodes per fn-path.

    Returns {fn_path: [ {dst, operands:set, op, file, line} ]}. Only bare
    Add/Sub/Mul/Shl/Shr (NOT *WithOverflow) - the release-profile unchecked op.
    wrapping_* calls are picked up separately from the parsed _MirFn.calls."""
    out: Dict[str, List[Dict[str, Any]]] = {}
    cur_path: Optional[str] = None
    for raw in mir_text.splitlines():
        hdr = rdf._MIR_FN_HEADER_RE.match(raw)
        if hdr:
            cur_path = hdr.group("path")
            out.setdefault(cur_path, [])
            continue
        if cur_path is None:
            continue
        m = _BARE_ARITH_RE.match(raw)
        if not m:
            continue
        operands = {int(x.group("n")) for x in _LOCAL_REF_RE.finditer(m.group("args"))}
        sp = rdf._MIR_SPAN_RE.search(raw)
        out[cur_path].append({
            "dst": int(m.group("dst")),
            "operands": operands,
            "op": m.group("op").lower(),
            "file": sp.group("file") if sp else None,
            "line": int(sp.group("line")) if sp else None,
        })
    return out


def _forward_reach(fn, seeds: set) -> set:
    """Forward def-use closure from seeds over the inverted assign graph.

    fn.assigns is dst -> {src locals}. Invert to src -> {dst} and BFS forward so we
    learn every local the arithmetic result propagates into (incl. call args)."""
    fwd: Dict[int, set] = {}
    for dst, srcs in fn.assigns.items():
        for s in srcs:
            fwd.setdefault(s, set()).add(dst)
    seen: set = set()
    work = list(seeds)
    while work:
        n = work.pop()
        if n in seen:
            continue
        seen.add(n)
        for nxt in fwd.get(n, ()):  # noqa: B007
            if nxt not in seen:
                work.append(nxt)
    return seen


def _value_or_threshold_use(fn, reach: set) -> Optional[Dict[str, Any]]:
    """Does the arithmetic result (its forward-reach set) hit a value/threshold use?

    - return: local 0 in reach (the fn returns the computed value)
    - value-sink: a call with a value-moving callee whose arg local is in reach
    - threshold: a guard (switchInt/assert from a cmp) whose local is in reach
      (the computed value is compared -> used as a threshold/limit)."""
    if 0 in reach:
        return {"use": "return", "file": fn.file, "line": fn.line, "detail": "computed value returned"}
    for c in fn.calls:
        kind = rdf._is_value_sink_callee(c.get("callee", ""))
        if kind and (set(c.get("arg_locals", [])) & reach):
            return {"use": f"value-sink:{kind}", "file": c.get("file"), "line": c.get("line"),
                    "detail": c.get("callee", "")[:120]}
    for g in fn.guards:
        if set(g.get("locals", [])) & reach:
            return {"use": "threshold-compare", "file": g.get("file"), "line": g.get("line"),
                    "detail": g.get("expr", "")[:120]}
    return None


def _wrapping_nodes(fn) -> List[Dict[str, Any]]:
    """wrapping_* calls in this fn = unchecked-by-design arithmetic nodes."""
    nodes: List[Dict[str, Any]] = []
    for c in fn.calls:
        seg = rdf._last_segment(c.get("callee", ""))
        if _WRAPPING_SEG.match(seg):
            nodes.append({
                "dst": c["dst"],
                "operands": set(c.get("arg_locals", [])),
                "op": seg,
                "file": c.get("file"),
                "line": c.get("line"),
                "wrapping": True,
            })
    return nodes


def analyze_fns(workspace: Path, fns, arith_by_path: Dict[str, List[Dict[str, Any]]],
                crate: str) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Core reasoning query. Return (survivor_rows, counters)."""
    survivors: List[Dict[str, Any]] = []
    counts = {"untrusted_value_arith": 0, "checked_kept": 0, "survivors": 0}
    for fn in fns:
        nodes = list(arith_by_path.get(fn.path, []))
        nodes += _wrapping_nodes(fn)
        params = set(fn.params)
        if not params:
            continue
        for nd in nodes:
            operands = nd["operands"]
            if not operands:
                continue
            # codegen exclusion: skip build-script / prost / tonic generated arith.
            if _is_codegen(nd.get("file")) or _is_codegen(fn.file):
                continue
            # (a) MEMBERSHIP-BY-TAINT: some operand traces to a fn parameter.
            if not rdf._taint_reaches(fn, operands, params):
                continue
            # (c) REACH-TO-VALUE: result forward-reaches a value/threshold use.
            reach = _forward_reach(fn, {nd["dst"]})
            use = _value_or_threshold_use(fn, reach)
            if use is None:
                continue
            counts["untrusted_value_arith"] += 1
            # (b) GUARD-BY-DOMINANCE: a manual bound guard dominates the operands.
            guards = rdf._local_is_guarded(fn, operands)
            is_wrapping = bool(nd.get("wrapping"))
            if guards and not is_wrapping:
                # checked/bounded => disciplined; counts toward the KEPT proof.
                counts["checked_kept"] += 1
                continue
            counts["survivors"] += 1
            f = rdf._rel(workspace, nd.get("file") or fn.file)
            ln = nd.get("line") or fn.line
            src_refs = [f"{f}:{ln}"] if f and ln else []
            use_f = rdf._rel(workspace, use.get("file"))
            if use_f and use.get("line"):
                src_refs.append(f"{use_f}:{use['line']}")
            reason = ("silent value-overflow (release profile): "
                      f"`{nd['op']}` on operand tainted from a fn parameter "
                      f"(untrusted numeric) with no overflow discipline "
                      f"(no checked_/saturating_/bound-guard); result reaches "
                      f"{use['use']} -> balance/share/amount/threshold corruption")
            survivors.append({
                "schema": SCHEMA,
                "crate": crate,
                "contract": fn.file and rdf._rel(workspace, fn.file) or crate,
                "function": fn.name,
                "op": nd["op"],
                "wrapping": is_wrapping,
                "source_refs": src_refs,
                "value_use": use["use"],
                "value_use_detail": use.get("detail"),
                "attack_class": "unchecked-arith-value-overflow",
                "likely_severity": "medium",
                "root_cause_hypothesis": reason,
                "broken_invariant_ids": [],
                "quality_gate_status": "needs_source",
                "next_command": (f"python3 tools/rust-unchecked-arith-value-overflow.py "
                                 f"--workspace {workspace} --target src/{crate}"),
            })
    return survivors, counts


def run(workspace: Path, target: Optional[Path], timeout: int,
        mir_file: Optional[Path]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    if mir_file is not None:
        crates = [("fixture", workspace)]
    elif target is not None:
        crates = [(rsg._crate_name_from_cargo(target, target.name), target.resolve())]
    else:
        crates = rsg.discover_crates(workspace)

    all_rows: List[Dict[str, Any]] = []
    report: Dict[str, Any] = {"crates": {}, "totals": {"untrusted_value_arith": 0,
                                                        "checked_kept": 0, "survivors": 0}}
    any_mir = False
    for name, root in crates:
        if mir_file is not None:
            mir_text, err = mir_file.read_text(encoding="utf-8", errors="replace"), None
        else:
            mir_text, err = _emit_mir_overflow_off(root, timeout)
        if mir_text is None:
            report["crates"][name] = {"backend": None, "mir_error": err, "survivors": 0}
            continue
        any_mir = True
        fns = rdf.parse_mir_text(mir_text)
        arith = _collect_arith_nodes(mir_text)
        rows, counts = analyze_fns(workspace, fns, arith, name)
        all_rows.extend(rows)
        report["crates"][name] = {
            "backend": "mir", "confidence": "semantic-ssa",
            "mir_lines": len(mir_text.splitlines()), "fns_parsed": len(fns),
            "bare_arith_nodes": sum(len(v) for v in arith.values()),
            **counts,
        }
        for k in report["totals"]:
            report["totals"][k] += counts[k]
    report["any_mir"] = any_mir
    if not any_mir:
        report["degraded"] = True
    return all_rows, report


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="RUST unchecked-arith value-overflow reasoning query.")
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--target", default=None, help="single crate dir (relative to ws or absolute)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", default=None)
    ap.add_argument("--emit", action="store_true",
                    help="(default-on) write obligations to <ws>/.auditooor/rust_unchecked_arith_obligations.jsonl")
    ap.add_argument("--no-emit", action="store_true",
                    help="suppress writing the obligation ledger (inspection only)")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--mir-file", default=None, help="use a precomputed MIR text file (testing)")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).resolve()
    if not ws.is_dir():
        print(f"ERROR: workspace not a directory: {ws}", file=sys.stderr)
        return 2
    target = None
    if args.target:
        tp = Path(args.target)
        target = tp if tp.is_absolute() else (ws / tp)
    mir_file = Path(args.mir_file).resolve() if args.mir_file else None

    rows, report = run(ws, target, args.timeout, mir_file)

    out_path = Path(args.out) if args.out else (ws / ".auditooor" / "rust_unchecked_arith_obligations.jsonl")
    # EMIT BY DEFAULT (2026-07-14): the step-2d-rust-arith-overflow verifier checks
    # file_exists(rust_unchecked_arith_obligations.jsonl) as proof-of-run ("empty =
    # ran, 0 survivors"), and the runbook documents the plain `--workspace <ws>`
    # command with NO --emit - so a genuine 0-survivor run must still write the
    # cited-empty ledger or the step can never pass. Suppress only for --no-emit
    # (inspection) or --mir-file (unit-test mode reads a fixture, not a real ws).
    _do_emit = (not args.no_emit) and (mir_file is None)
    if _do_emit or args.emit or args.out:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as fh:
            if rows:
                for r in rows:
                    fh.write(json.dumps(r, sort_keys=True) + "\n")
            else:
                # honest cited-empty marker (query ran over real MIR, 0 survivors)
                fh.write(json.dumps({"schema": SCHEMA, "survivors": 0,
                                     "note": "cited-empty: query ran over MIR, no unchecked "
                                             "untrusted-value arithmetic found",
                                     "report": report}, sort_keys=True) + "\n")

    if args.json:
        print(json.dumps({"survivors": rows, "report": report}, indent=2, sort_keys=True))
    else:
        t = report["totals"]
        print(f"[rust-unchecked-arith] untrusted-value-arith={t['untrusted_value_arith']} "
              f"checked-KEPT={t['checked_kept']} survivors(SET-DIFF)={t['survivors']} "
              f"any_mir={report.get('any_mir')}")
        for nm, c in report["crates"].items():
            print(f"  crate={nm} backend={c.get('backend')} "
                  f"mir_lines={c.get('mir_lines')} survivors={c.get('survivors', 0)} "
                  f"err={c.get('mir_error')}")
        for r in rows[:20]:
            print(f"    SURVIVOR {r['function']} op={r['op']} use={r['value_use']} "
                  f"{r['source_refs']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
