#!/usr/bin/env python3
"""rust-dataflow.py - native offline RUST inter-procedural data-flow backend.

Phase-1 Rust arm of the cross-language DefUsePath producer. It is the Rust
counterpart of tools/dataflow-slice.py (Solidity / Slither). It emits the SHARED
tools/dataflow_schema.py DefUsePath records to <ws>/.auditooor/dataflow_paths.jsonl
so the same downstream consumers (predicate engine, depth layer, hunt sidecar)
work uniformly across languages.

Two backends, picked PER CRATE, honestly recorded in `confidence`:

  Tier-1/2  MIR-resolved (confidence="semantic-ssa"):
    For crates that COMPILE, we drive `cargo rustc -- --emit=mir` (text MIR) with
    `-Zmir-include-spans=on` (enabled on stable via RUSTC_BOOTSTRAP=1). The text MIR
    is stable enough to parse for inter-procedural def-use:
      - fn headers `fn name(_1: T, _2: U) -> R {` give the per-fn local table
      - `debug src_name => _N;` maps source identifiers to MIR locals
      - Call terminators `_0 = callee(copy _1, move _2) -> [return: bbK, ...]`
        give the arg<->param<->return edges that cross fn boundaries
      - `switchInt(...)` / `assert(...)` after a Lt/Le/Gt/Ge/Eq/Ne or a bool call
        are the guards that dominate a downstream value move
      - every statement carries `// scope N at FILE:L:C: L:C` so we recover real
        file:line citations.
    From the call graph we do a BACKWARD slice from every value-moving SINK
    (Promise/transfer/mint/burn/near-sdk env::promise_*/token ops/state writes)
    up through the caller frames to a tainted SOURCE (a fn parameter), emitting one
    DefUsePath per source->sink chain with its inter-procedural hops.

  Tier-3  syntactic fallback (confidence="syntactic"):
    For crates that DO NOT compile or are macro-heavy (near-sdk #[near_bindgen],
    cosmwasm #[entry_point] expand the real surface only post-macro, and a
    non-compiling crate yields no MIR at all), we fall back to a tree-sitter
    (or, if tree-sitter is unavailable, a regex) call-graph + def-use over the
    parsed source. These records are advisory: confidence="syntactic", and they
    MUST NOT be cited as a proven semantic flow.

R80 honesty / degrade contract (mirrors dataflow-slice.py):
  - A record is confidence="semantic-ssa" ONLY when it was recovered from real MIR
    of a crate that actually compiled. A syntactic record is confidence="syntactic".
  - When NEITHER backend can produce anything for ANY crate (no compilable crate AND
    no parseable source), we write a single degrade record
    (engine="unsupported-or-compile-fail-degrade", degraded=True) and exit 0
    (advisory). We never claim a semantic-ssa path on a failed compile.

Reuses tools/rust-source-graph.py as the syntactic node inventory / value-mover
vocabulary (its _VALUE_MOVEMENT_RES / _EXTERNAL_CALL_RES discipline) so the two
Rust tools agree on what a "sink" is. This tool is STANDALONE: it does not edit
dataflow-slice.py or readme_runbook_steps.json.

CLI:
  tools/rust-dataflow.py --workspace <ws> [--target <crate_dir>] [--json]
        [--mode auto|mir|syntactic] [--max-hops N] [--out <path>] [--timeout S]

Exit codes:
  0  ran (including R80 advisory degrade)
  2  invalid CLI arguments / missing workspace
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# local schema helper (shared producer/consumer record)
sys.path.insert(0, str(Path(__file__).resolve().parent))
import dataflow_schema as dfs  # noqa: E402

# Reuse the Rust syntactic source-graph for crate discovery + value-mover
# vocabulary. Import by file path since the module name has a hyphen.
import importlib.util as _ilu  # noqa: E402

_RSG_PATH = Path(__file__).resolve().parent / "rust-source-graph.py"
_spec = _ilu.spec_from_file_location("rust_source_graph", str(_RSG_PATH))
rsg = _ilu.module_from_spec(_spec)  # type: ignore[arg-type]
assert _spec and _spec.loader
_spec.loader.exec_module(rsg)  # type: ignore[union-attr]


# B-hops: depth is UNBOUNDED by design (operator: "no limit to hops"). The real
# terminator is the per-walk visited-(fn,var/local) set + cycle-guard already present in
# mir_slices / syntactic_slices (mirrors slither_predicates.callee_closure's `seen`).
# MAX_HOPS_DEFAULT is now only a HIGH runaway-safety ceiling, not a small semantic cap;
# overridable via AUDITOOOR_DATAFLOW_MAX_HOPS for huge crate graphs.
def _safety_ceiling(default: int = 512) -> int:
    raw = os.environ.get("AUDITOOOR_DATAFLOW_MAX_HOPS")
    if raw:
        try:
            v = int(raw)
            if v > 0:
                return v
        except ValueError:
            pass
    return default


MAX_HOPS_DEFAULT = _safety_ceiling()
MIR_TIMEOUT_DEFAULT = 900  # seconds for one `cargo rustc` MIR emit

# ---------------------------------------------------------------------------
# Sink vocabulary (value movers + near-sdk promises + state writes).
# We deliberately reuse the rust-source-graph value-mover names so the two Rust
# tools agree, then add the near-sdk / token-op / Promise vocabulary that the
# brief calls out (Promise/transfer/mint/burn, near-sdk env::promise, token ops).
# ---------------------------------------------------------------------------
# Method/function callee names that MOVE VALUE or are externally observable
# value sinks. Matched against the MIR callee path's LAST segment.
VALUE_MOVING_CALLEES = {
    # generic token-flow vocabulary
    "transfer", "transfer_from", "safe_transfer", "safe_transfer_from",
    "mint", "mint_to", "burn", "withdraw", "deposit", "claim", "redeem", "sweep",
    # near-sdk Promise / cross-contract value movement
    "transfer",  # Promise::transfer
    "function_call", "function_call_weight",
    "ft_transfer", "ft_transfer_call", "nft_transfer", "near_deposit",
    "promise_batch_action_transfer", "promise_batch_action_function_call",
    "promise_batch_action_function_call_weight",
}
# near-sdk env:: promise primitives (path contains these segments).
NEAR_PROMISE_SEGMENTS = {
    "promise_batch_action_transfer",
    "promise_batch_action_function_call",
    "promise_batch_action_function_call_weight",
    "promise_create", "promise_batch_create", "promise_batch_then",
}
# A new Promise(...).transfer(...) builder.
PROMISE_BUILDER_SEGMENTS = {"Promise"}


# ---------------------------------------------------------------------------
# Ceremony / threshold-sig sink vocabulary (BitForge / GG20 key-extraction
# surface). A threshold-signature / DKG crate (tofn, gg20, feldman, paillier,
# mta, ...) moves NO ERC20/Promise "value" - its security-critical sinks are the
# ceremony operations that CONSUME a decoded round-message field: a proof/
# commitment VERIFY node, a secret-share AGGREGATION, or a signing FINALIZE.
# The token/Promise vocabulary above therefore finds 0 sinks on such a crate and
# rust-dataflow degrades, starving tools/mpc-round-proof-obligation.py of any
# substrate. This ceremony set restores a real def-use surface for those crates.
#
# HONESTY: this set is consulted ONLY for a ceremony crate (CEREMONY_CRATE_RE
# hit on crate name / Cargo.toml), so a generic token crate keeps its exact prior
# behavior. A row it produces is confidence-labeled exactly like any other arm
# (semantic-ssa iff recovered from real MIR of a crate that compiled; syntactic
# otherwise) - the sink label is `ceremony:<callee>`, never fabricated.
# ---------------------------------------------------------------------------
CEREMONY_SINK_CALLEES = {
    # proof / commitment VERIFY nodes (a decoded field consumed by verification)
    "verify_prehashed", "verify_primitive", "verify", "verify_vss", "feldman_verify",
    "verify_share", "verify_commitment", "check_share", "paillier_verify",
    "verify_paillier", "blum_verify", "verify_blum", "verify_range", "mta_verify",
    "verify_proof", "proof_verify", "verify_dlog", "schnorr_verify", "verify_open",
    "commitment_open", "open_commitment",
    # signing / secret-combine FINALIZERS
    "try_sign_prehashed", "sign_prehashed", "sign_finalize", "finalize_signature",
    # multi-party secret-share AGGREGATION sinks
    "combine_shares", "combine_share", "reconstruct", "reconstruct_secret",
    "reconstruct_share", "recover_secret", "lagrange_interpolate", "interpolate",
    "add_partial_signature", "combine_partial", "aggregate_sig", "combine_sig",
    "add_share", "accumulate_share", "combine_nonce", "aggregate_nonce",
}
# Crate-level gate: only a threshold-sig / DKG ceremony crate consults the
# ceremony sink vocabulary. Matched against the crate name and (shallow) Cargo.toml.
CEREMONY_CRATE_RE = re.compile(
    r"tofn|tofnd|gg20|gg18|gg1[68]|feldman|pedersen|paillier|\bvss\b|\bmta\b|"
    r"threshold[_-]?sig|thresholdsig|frost|cggmp|lindell|\bdkg\b|multi[_-]?party|"
    r"presign|reshare|schnorr[_-]?mpc|secret[_-]?share|key[_-]?gen",
    re.IGNORECASE,
)


def _is_ceremony_crate(crate_name: Optional[str], crate_root: Path) -> bool:
    """True iff this crate is a threshold-sig / DKG ceremony crate (by name or a
    shallow Cargo.toml scan). Gates the ceremony sink vocabulary so generic crates
    keep their exact token/Promise behavior."""
    if crate_name and CEREMONY_CRATE_RE.search(crate_name):
        return True
    ct = crate_root / "Cargo.toml"
    try:
        return bool(CEREMONY_CRATE_RE.search(ct.read_text(encoding="utf-8", errors="ignore")[:4000]))
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Tier-1/2 : MIR backend
# ---------------------------------------------------------------------------

# fn header: `fn <path>(_1: T, _2: U) -> R {`  (path may contain <impl ...> and ::)
# We grab the whole header up to the opening `{` so we can pull the param locals.
_MIR_FN_HEADER_RE = re.compile(r"^(?:const\s+)?fn\s+(?P<path>.+?)\s*\((?P<params>.*?)\)\s*->\s*.*\{\s*$")
# debug binding: `    debug name => _N;`  (also `=> _N.field;` for upvars)
_MIR_DEBUG_RE = re.compile(r"^\s*debug\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=>\s*(?:\(\*)?_(?P<local>\d+)")
# span tail on a statement/header: `// ... at FILE:L:C: L:C`  (last one wins)
_MIR_SPAN_RE = re.compile(r"//.*?at\s+(?P<file>[^\s:][^:]*?):(?P<line>\d+):(?P<col>\d+):")
# call terminator: `_0 = callee(args...) -> [return: bbK, ...];`
# callee can be a path `foo::bar`, a method-resolved monomorphized path, OR a
# fully-qualified trait call `<T as Trait>::method` (which STARTS with `<`). The
# leading-`<` form is how MIR prints every trait-method sink (e.g.
# `<AffinePoint as VerifyPrimitive>::verify_prehashed`, `<T as Transfer>::transfer`);
# the first char must therefore admit `<`, else all such sinks are silently dropped.
_MIR_CALL_RE = re.compile(
    r"^\s*_(?P<dst>\d+)\s*=\s*(?P<callee>[A-Za-z_<][A-Za-z0-9_:<>{}\s\.\-]*?)\s*"
    r"\((?P<args>.*?)\)\s*->\s*\[return:"
)
# plain assignment (for intra-fn def-use): `_3 = <rvalue>;`
_MIR_ASSIGN_RE = re.compile(r"^\s*_(?P<dst>\d+)\s*=\s*(?P<rval>.+?);\s*(?://.*)?$")
# guard terminators
_MIR_SWITCHINT_RE = re.compile(r"^\s*switchInt\((?:move|copy)?\s*_(?P<op>\d+)")
_MIR_ASSERT_RE = re.compile(r"^\s*assert\(")
# comparison rvalues that produce a bool used by a guard
_MIR_CMP_RE = re.compile(r"\b(?:Lt|Le|Gt|Ge|Eq|Ne)\(")
# operand local references inside an rvalue/args: `copy _N`, `move _N`, `_N`
_MIR_LOCAL_REF_RE = re.compile(r"(?:copy\s+|move\s+)?_(?P<n>\d+)\b")


def _last_segment(callee: str) -> str:
    """Reduce a monomorphized MIR callee path to its final method/fn name."""
    c = callee.strip()
    # strip trailing generic args and turbofish noise
    c = re.sub(r"<[^<>]*>", "", c)
    c = c.rstrip(":").strip()
    if "::" in c:
        c = c.split("::")[-1]
    c = c.strip()
    return c


def _callee_segments(callee: str) -> List[str]:
    c = re.sub(r"<[^<>]*>", "", callee)
    return [s for s in re.split(r"::|\.", c) if s]


def _is_value_sink_callee(callee: str, ceremony: bool = False) -> Optional[str]:
    """Return a sink-kind label if this MIR callee moves value, else None.

    When `ceremony` is True (crate is a threshold-sig / DKG crate) we ALSO treat
    ceremony operations (proof-verify / share-aggregation / signing-finalize) as
    sinks, so the def-use surface of a crypto crate that moves no ERC20/Promise
    value is not empty. The gate keeps generic crates on their exact prior set."""
    seg = _last_segment(callee)
    segments = set(_callee_segments(callee))
    if seg in VALUE_MOVING_CALLEES:
        return f"value_move:{seg}"
    if segments & NEAR_PROMISE_SEGMENTS:
        hit = next(iter(segments & NEAR_PROMISE_SEGMENTS))
        return f"near_promise:{hit}"
    if "Promise" in segments and seg in {"transfer", "function_call", "function_call_weight"}:
        return f"promise_builder:{seg}"
    if ceremony and seg in CEREMONY_SINK_CALLEES:
        return f"ceremony:{seg}"
    return None


class _MirFn:
    """One parsed MIR function: locals<->source names, calls, guards, span."""

    __slots__ = ("path", "name", "file", "line", "params", "debug",
                 "calls", "guards", "assigns")

    def __init__(self, path: str) -> None:
        self.path = path
        self.name = _last_segment(path)
        self.file: Optional[str] = None
        self.line: Optional[int] = None
        # ordered param locals (_1.._n) extracted from the header
        self.params: List[int] = []
        # source-name -> local and local -> source-name
        self.debug: Dict[int, str] = {}
        # call edges: list of dicts {dst, callee, arg_locals, file, line, raw}
        self.calls: List[Dict[str, Any]] = []
        # set of locals that are guarded (feed a switchInt/assert via a cmp)
        self.guards: List[Dict[str, Any]] = []
        # intra-fn assignments dst_local -> set of source locals (for taint walk)
        self.assigns: Dict[int, set] = {}


def _parse_mir_params(params: str) -> List[int]:
    out: List[int] = []
    for m in re.finditer(r"_(?P<n>\d+)\s*:", params):
        out.append(int(m.group("n")))
    return out


def parse_mir_text(text: str) -> List[_MirFn]:
    """Parse text MIR into a list of _MirFn with inter/intra def-use edges."""
    fns: List[_MirFn] = []
    lines = text.splitlines()
    cur: Optional[_MirFn] = None
    # track the bool locals produced by a comparison so a later switchInt can
    # mark the compared operands as guarded.
    cmp_bool_operands: Dict[int, set] = {}  # bool_local -> {operand locals}
    for raw in lines:
        hdr = _MIR_FN_HEADER_RE.match(raw)
        if hdr:
            cur = _MirFn(hdr.group("path"))
            cur.params = _parse_mir_params(hdr.group("params"))
            sp = _MIR_SPAN_RE.search(raw)
            if sp:
                cur.file = sp.group("file")
                cur.line = int(sp.group("line"))
            fns.append(cur)
            cmp_bool_operands = {}
            continue
        if cur is None:
            continue
        if raw.strip() == "}" and not raw.startswith(" " * 8):
            # likely end of fn (top-level close brace); keep parsing, headers reset
            continue

        dbg = _MIR_DEBUG_RE.match(raw)
        if dbg:
            local = int(dbg.group("local"))
            cur.debug.setdefault(local, dbg.group("name"))
            continue

        # fn-local span fallback (first stmt span if header had none)
        if cur.file is None:
            sp = _MIR_SPAN_RE.search(raw)
            if sp:
                cur.file = sp.group("file")
                cur.line = int(sp.group("line"))

        call = _MIR_CALL_RE.match(raw)
        if call:
            arg_locals = [int(m.group("n")) for m in _MIR_LOCAL_REF_RE.finditer(call.group("args"))]
            sp = _MIR_SPAN_RE.search(raw)
            cur.calls.append({
                "dst": int(call.group("dst")),
                "callee": call.group("callee").strip(),
                "arg_locals": arg_locals,
                "file": sp.group("file") if sp else cur.file,
                "line": int(sp.group("line")) if sp else cur.line,
                "raw": raw.strip()[:200],
            })
            # a call result is also an assignment for taint flow
            cur.assigns.setdefault(int(call.group("dst")), set()).update(arg_locals)
            continue

        assign = _MIR_ASSIGN_RE.match(raw)
        if assign:
            dst = int(assign.group("dst"))
            rval = assign.group("rval")
            src_locals = {int(m.group("n")) for m in _MIR_LOCAL_REF_RE.finditer(rval)}
            cur.assigns.setdefault(dst, set()).update(src_locals)
            if _MIR_CMP_RE.search(rval):
                cmp_bool_operands[dst] = src_locals
            continue

        sw = _MIR_SWITCHINT_RE.match(raw)
        if sw:
            op = int(sw.group("op"))
            guarded_operands = cmp_bool_operands.get(op, {op})
            sp = _MIR_SPAN_RE.search(raw)
            cur.guards.append({
                "locals": sorted(guarded_operands),
                "kind": "switchInt",
                "file": sp.group("file") if sp else cur.file,
                "line": int(sp.group("line")) if sp else cur.line,
                "expr": raw.strip()[:160],
            })
            continue

        if _MIR_ASSERT_RE.match(raw):
            # assert operands - mark referenced locals as guarded
            operands = {int(m.group("n")) for m in _MIR_LOCAL_REF_RE.finditer(raw)}
            sp = _MIR_SPAN_RE.search(raw)
            cur.guards.append({
                "locals": sorted(operands),
                "kind": "assert",
                "file": sp.group("file") if sp else cur.file,
                "line": int(sp.group("line")) if sp else cur.line,
                "expr": raw.strip()[:160],
            })
            continue
    return fns


def _rel(workspace: Path, file_str: Optional[str]) -> Optional[str]:
    if not file_str:
        return file_str
    p = Path(file_str)
    try:
        if p.is_absolute():
            return str(p.relative_to(workspace))
    except ValueError:
        pass
    return file_str


def _rel_to_ws(workspace: Path, crate_root: Optional[Path],
               file_str: Optional[str]) -> Optional[str]:
    """Workspace-relative path for a MIR span. MIR file spans are CRATE-relative
    (cargo's cwd is the crate root), so when the analyzed crate is a subdir of the
    workspace (e.g. src/tofn) a bare 'src/ecdsa/mod.rs' would drop the 'src/tofn/'
    prefix - and with it any ceremony/scope marker a downstream consumer keys on.
    We therefore re-root a relative span against crate_root before relativizing."""
    if not file_str:
        return file_str
    p = Path(file_str)
    if not p.is_absolute() and crate_root is not None:
        p = crate_root / file_str
    try:
        if p.is_absolute():
            return str(p.resolve().relative_to(workspace.resolve()))
    except ValueError:
        return str(p)
    return file_str


def _taint_reaches(fn: _MirFn, target_locals: set, source_locals: set) -> bool:
    """Backward reachability within a fn: do target_locals trace back to any
    source_local through the intra-fn assignment graph (incl. call results)?"""
    if target_locals & source_locals:
        return True
    seen: set = set()
    work = list(target_locals)
    while work:
        loc = work.pop()
        if loc in seen:
            continue
        seen.add(loc)
        if loc in source_locals:
            return True
        for src in fn.assigns.get(loc, set()):
            if src not in seen:
                work.append(src)
    return bool(seen & source_locals)


def _local_is_guarded(fn: _MirFn, locals_set: set) -> List[Dict[str, Any]]:
    """Return guard records whose guarded locals taint-overlap locals_set."""
    out: List[Dict[str, Any]] = []
    for g in fn.guards:
        gl = set(g["locals"])
        # a guard counts if any guarded local can reach (or is) a target local
        if gl & locals_set or _taint_reaches(fn, locals_set, gl):
            out.append(g)
    return out


def build_mir_callgraph(fns: List[_MirFn]) -> Dict[str, List[_MirFn]]:
    """Map a fn-name -> the fns that DEFINE it (callee resolution by last seg)."""
    by_name: Dict[str, List[_MirFn]] = {}
    for fn in fns:
        by_name.setdefault(fn.name, []).append(fn)
    return by_name


def mir_slices(workspace: Path, fns: List[_MirFn], crate: str,
               max_hops: int, ceremony: bool = False,
               crate_root: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Backward inter-procedural slices from value-moving sinks to fn params."""
    def _relf(f: Optional[str]) -> Optional[str]:
        return _rel_to_ws(workspace, crate_root, f)
    by_name = build_mir_callgraph(fns)
    records: List[Dict[str, Any]] = []
    idx = 0
    seen_sig: set = set()

    # callers index: callee-name -> list of (caller_fn, call_dict)
    callers_of: Dict[str, List[Tuple[_MirFn, Dict[str, Any]]]] = {}
    for fn in fns:
        for c in fn.calls:
            callers_of.setdefault(_last_segment(c["callee"]), []).append((fn, c))

    def walk_back(sink_fn: _MirFn, sink_call: Dict[str, Any],
                  tainted_arg_locals: set) -> None:
        """Emit DefUsePaths for every caller chain feeding tainted_arg_locals."""
        nonlocal idx
        # base: does the taint reach THIS fn's own params? -> source in this fn
        param_set = set(sink_fn.params)
        reaching_params = {p for p in param_set if _taint_reaches(sink_fn, tainted_arg_locals, {p})}

        # build the sink record once
        sink_rec = {
            "kind": _is_value_sink_callee(sink_call["callee"], ceremony) or "value_move",
            "callee": _last_segment(sink_call["callee"]),
            "arg_pos": None,
            "fn": sink_fn.name,
            "file": _relf( sink_call["file"]),
            "line": sink_call["line"],
        }

        # DFS over caller frames. Each frame contributes a hop.
        # state: (frame_fn, frame_tainted_locals, hops_so_far, guards_so_far, depth)
        stack: List[Tuple[_MirFn, set, List[Dict[str, Any]], List[Dict[str, Any]], int]] = []
        # seed: the sink fn itself, with the guard analysis of the sink fn
        sink_guards = _local_is_guarded(sink_fn, tainted_arg_locals)
        stack.append((sink_fn, tainted_arg_locals, [], list(sink_guards), 0))

        # B-hops: visited-(fn, tracked-locals) terminator so an UNBOUNDED ceiling
        # cannot loop on a recursive/mutually-recursive call graph (mirrors
        # slither_predicates.callee_closure's cycle-guard). Without this, raising the
        # depth ceiling from 8 to a high value would risk exponential re-expansion.
        walk_visited: set = set()

        while stack:
            frame_fn, frame_taint, hops, guards, depth = stack.pop()
            _vk = (frame_fn.name, frozenset(frame_taint))
            if _vk in walk_visited:
                continue
            walk_visited.add(_vk)
            frame_params = set(frame_fn.params)
            frame_reaching = {p for p in frame_params
                              if _taint_reaches(frame_fn, frame_taint, {p})}

            # If taint reaches a param of frame_fn, that param is a SOURCE
            # candidate -> emit a slice from frame_fn's param to the sink.
            if frame_reaching:
                for p in sorted(frame_reaching):
                    src_name = frame_fn.debug.get(p, f"_{p}")
                    source_rec = {
                        "kind": "fn_param",
                        "fn": frame_fn.name,
                        "var": src_name,
                        "file": _relf( frame_fn.file),
                        "line": frame_fn.line,
                    }
                    sig = (source_rec["fn"], source_rec["var"],
                           sink_rec["fn"], sink_rec["callee"],
                           sink_rec["line"], len(hops))
                    if sig in seen_sig:
                        continue
                    seen_sig.add(sig)
                    rec = dfs.new_path(
                        path_id=f"rdf-{idx:04d}",
                        language="rust",
                        direction="backward",
                        engine="rustc-mir.defuse-bridge",
                        source=source_rec,
                        sink=sink_rec,
                        hops=list(reversed(hops)),
                        guard_nodes=[{"file": _relf( g["file"]),
                                      "line": g["line"], "expr": g["expr"]}
                                     for g in guards],
                        source_unit_ids=[f"{crate}:{source_rec['fn']}"],
                        sink_unit_ids=[f"{crate}:{sink_rec['fn']}:{sink_rec['line']}"],
                        confidence="semantic-ssa",
                        degraded=False,
                    )
                    rec["crate"] = crate
                    # B-hops honesty: if this frame sits at the safety ceiling AND it
                    # still has un-walked callers, the chain may be incomplete -> flag it.
                    if depth >= max_hops and callers_of.get(frame_fn.name):
                        rec["dataflow_truncated"] = True
                    records.append(rec)
                    idx += 1

            # recurse into callers of frame_fn (one more hop), bounded by the
            # HIGH safety ceiling (visited-set is the real terminator below)
            if depth >= max_hops:
                continue
            for caller_fn, call in callers_of.get(frame_fn.name, []):
                if caller_fn is frame_fn:
                    continue  # avoid trivial self-recursion explosion
                # which of caller's locals feed the args that landed on
                # frame_fn's tainted params? map by positional arg index.
                # frame_reaching params are positional (_1.._n); the call's
                # arg_locals are positional too.
                frame_param_order = frame_fn.params
                propagate: set = set()
                for pos, plocal in enumerate(frame_param_order):
                    if plocal in frame_reaching or plocal in frame_taint:
                        if pos < len(call["arg_locals"]):
                            propagate.add(call["arg_locals"][pos])
                if not propagate:
                    # fall back: propagate all call arg locals (conservative)
                    propagate = set(call["arg_locals"])
                if not propagate:
                    continue
                hop = {
                    "from_var": caller_fn.debug.get(next(iter(propagate)),
                                                    f"_{next(iter(propagate))}") if propagate else "?",
                    "to_var": frame_fn.debug.get(
                        next(iter(frame_reaching)) if frame_reaching else
                        (next(iter(frame_taint)) if frame_taint else 0),
                        "?"),
                    "fn": frame_fn.name,
                    "via": "internal_call",
                    "file": _relf( call["file"]),
                    "line": call["line"],
                    "ir": call["raw"],
                    "guarded": bool(_local_is_guarded(caller_fn, propagate)),
                }
                caller_guards = _local_is_guarded(caller_fn, propagate)
                stack.append((caller_fn, propagate, hops + [hop],
                              guards + caller_guards, depth + 1))

    # enumerate sinks across all fns
    for fn in fns:
        for call in fn.calls:
            kind = _is_value_sink_callee(call["callee"], ceremony)
            if not kind:
                continue
            if not call["arg_locals"]:
                continue
            walk_back(fn, call, set(call["arg_locals"]))
    return records


def emit_mir_for_crate(crate_root: Path, timeout: int) -> Tuple[Optional[str], Optional[str]]:
    """Run `cargo rustc -- --emit=mir` for crate_root. Return (mir_text, error)."""
    if not (crate_root / "Cargo.toml").is_file():
        return None, "no-cargo-toml"
    with tempfile.TemporaryDirectory(prefix="rdf-mir-") as td:
        mir_out = Path(td) / "out.mir"
        env = dict(os.environ)
        env["RUSTC_BOOTSTRAP"] = "1"  # unlock -Z on stable rustc (MIR span flag)
        cmd = [
            "cargo", "rustc", "--lib", "--",
            f"--emit=mir={mir_out}",
            "-Zmir-include-spans=on",
        ]
        try:
            proc = subprocess.run(cmd, cwd=str(crate_root), env=env,
                                  capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return None, f"mir-emit-timeout>{timeout}s"
        except FileNotFoundError:
            return None, "cargo-not-found"
        if not mir_out.is_file():
            # try without --lib (bin crates)
            cmd2 = ["cargo", "rustc", "--",
                    f"--emit=mir={mir_out}", "-Zmir-include-spans=on"]
            try:
                proc = subprocess.run(cmd2, cwd=str(crate_root), env=env,
                                      capture_output=True, text=True, timeout=timeout)
            except subprocess.TimeoutExpired:
                return None, f"mir-emit-timeout>{timeout}s"
        if not mir_out.is_file():
            tail = (proc.stderr or proc.stdout or "")[-300:]
            return None, f"compile-fail-no-mir: {tail}"
        try:
            return mir_out.read_text(encoding="utf-8", errors="replace"), None
        except OSError as e:
            return None, f"mir-read-error: {e}"


# ---------------------------------------------------------------------------
# Tier-3 : syntactic (tree-sitter, regex fallback) backend
# ---------------------------------------------------------------------------

def _have_tree_sitter() -> bool:
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_rust  # noqa: F401
        return True
    except Exception:
        return False


class _SynFn:
    __slots__ = ("name", "file", "line", "params", "body_start", "body_end",
                 "calls", "guards")

    def __init__(self, name: str, file: str, line: int) -> None:
        self.name = name
        self.file = file
        self.line = line
        self.params: List[str] = []
        self.body_start = line
        self.body_end = line
        self.calls: List[Dict[str, Any]] = []   # {callee, args, file, line}
        self.guards: List[Dict[str, Any]] = []   # {expr, file, line, vars}


def _ts_parse_file(workspace: Path, path: Path) -> List[_SynFn]:
    """Parse one .rs file with tree-sitter into _SynFn records."""
    import tree_sitter
    import tree_sitter_rust
    lang = tree_sitter.Language(tree_sitter_rust.language())
    parser = tree_sitter.Parser(lang)
    try:
        src = path.read_bytes()
    except OSError:
        return []
    tree = parser.parse(src)
    rel = rsg._rel(workspace, path)  # reuse rust-source-graph rel logic
    fns: List[_SynFn] = []

    def text(node) -> str:
        return src[node.start_byte:node.end_byte].decode("utf-8", "replace")

    def line_of(node) -> int:
        return node.start_point[0] + 1

    # Walk all function_item nodes (free fns + impl methods).
    def visit(node) -> None:
        if node.type in ("function_item",):
            name_node = node.child_by_field_name("name")
            if name_node is None:
                return
            fn = _SynFn(text(name_node), rel, line_of(node))
            fn.body_start = line_of(node)
            fn.body_end = node.end_point[0] + 1
            # params
            params_node = node.child_by_field_name("parameters")
            if params_node is not None:
                for ch in params_node.named_children:
                    if ch.type == "parameter":
                        pat = ch.child_by_field_name("pattern")
                        if pat is not None:
                            fn.params.append(text(pat))
                    elif ch.type == "self_parameter":
                        fn.params.append("self")
            # body: collect calls + guards
            body = node.child_by_field_name("body")
            if body is not None:
                _collect_body(body, fn)
            fns.append(fn)
        for ch in node.children:
            visit(ch)

    def _collect_body(node, fn: _SynFn) -> None:
        stack = [node]
        while stack:
            n = stack.pop()
            if n.type == "call_expression":
                callee_node = n.child_by_field_name("function")
                args_node = n.child_by_field_name("arguments")
                callee = text(callee_node) if callee_node else ""
                args = text(args_node) if args_node else ""
                fn.calls.append({
                    "callee": callee, "args": args,
                    "file": fn.file, "line": line_of(n),
                })
            elif n.type == "macro_invocation":
                mname = n.child_by_field_name("macro")
                mtxt = text(mname) if mname else ""
                # assert!/require!/ensure! style guards
                if mtxt in ("assert", "assert_eq", "assert_ne", "require",
                            "ensure", "debug_assert"):
                    fn.guards.append({
                        "expr": text(n)[:160], "file": fn.file, "line": line_of(n),
                        "vars": _idents(text(n)),
                    })
            elif n.type == "if_expression":
                cond = n.child_by_field_name("condition")
                if cond is not None:
                    ctxt = text(cond)
                    if re.search(r"[<>]=?|==|!=", ctxt):
                        fn.guards.append({
                            "expr": ctxt[:160], "file": fn.file, "line": line_of(n),
                            "vars": _idents(ctxt),
                        })
            for ch in n.children:
                stack.append(ch)

    visit(tree.root_node)
    return fns


def _idents(text: str) -> List[str]:
    return list({m.group(0) for m in re.finditer(r"[A-Za-z_][A-Za-z0-9_]*", text)})


def _regex_parse_file(workspace: Path, path: Path) -> List[_SynFn]:
    """Regex fallback when tree-sitter is unavailable. Coarser but honest."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    rel = rsg._rel(workspace, path)
    fns: List[_SynFn] = []
    fn_re = re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\((?P<params>[^)]*)\)")
    call_re = re.compile(r"\b([A-Za-z_][A-Za-z0-9_:]*|\.\s*[A-Za-z_][A-Za-z0-9_]*)\s*\(")
    cur: Optional[_SynFn] = None
    depth = 0
    for idx, raw in enumerate(lines):
        m = fn_re.match(raw)
        if m:
            cur = _SynFn(m.group(1), rel, idx + 1)
            cur.params = [p.split(":")[0].strip() for p in m.group("params").split(",") if p.strip()]
            fns.append(cur)
            depth = raw.count("{") - raw.count("}")
            continue
        if cur is None:
            continue
        for label, rx in rsg._VALUE_MOVEMENT_RES:
            if rx.search(raw):
                cur.calls.append({"callee": label, "args": "", "file": rel, "line": idx + 1})
        if re.search(r"\b(assert|require|ensure|debug_assert)\s*!", raw) or \
           (re.search(r"\bif\b", raw) and re.search(r"[<>]=?|==|!=", raw)):
            cur.guards.append({"expr": raw.strip()[:160], "file": rel, "line": idx + 1,
                               "vars": _idents(raw)})
        depth += raw.count("{") - raw.count("}")
        if depth <= 0:
            cur.body_end = idx + 1
            cur = None
    return fns


def _syn_sink_kind(callee: str, ceremony: bool = False) -> Optional[str]:
    seg = _last_segment(callee)
    segments = set(_callee_segments(callee))
    if seg in VALUE_MOVING_CALLEES:
        return f"value_move:{seg}"
    if segments & NEAR_PROMISE_SEGMENTS:
        return f"near_promise:{next(iter(segments & NEAR_PROMISE_SEGMENTS))}"
    if "Promise" in segments and seg in {"transfer", "function_call"}:
        return f"promise_builder:{seg}"
    # also accept the rust-source-graph value-mover labels (regex backend)
    if seg in {"transfer", "transfer_from", "mint", "burn", "withdraw",
               "deposit", "claim", "redeem"}:
        return f"value_move:{seg}"
    if ceremony and seg in CEREMONY_SINK_CALLEES:
        return f"ceremony:{seg}"
    return None


def syntactic_slices(workspace: Path, crate: str, crate_root: Path,
                     max_hops: int, ceremony: bool = False) -> List[Dict[str, Any]]:
    """Syntactic backward slices: name-based call graph + param taint heuristic."""
    src = crate_root / "src"
    files = rsg._rs_files_in(src)
    use_ts = _have_tree_sitter()
    all_fns: List[_SynFn] = []
    for f in files:
        if use_ts:
            try:
                all_fns.extend(_ts_parse_file(workspace, f))
            except Exception:
                all_fns.extend(_regex_parse_file(workspace, f))
        else:
            all_fns.extend(_regex_parse_file(workspace, f))

    by_name: Dict[str, List[_SynFn]] = {}
    for fn in all_fns:
        by_name.setdefault(fn.name, []).append(fn)
    # callers index by callee last-segment
    callers_of: Dict[str, List[Tuple[_SynFn, Dict[str, Any]]]] = {}
    for fn in all_fns:
        for c in fn.calls:
            callers_of.setdefault(_last_segment(c["callee"]), []).append((fn, c))

    records: List[Dict[str, Any]] = []
    seen_sig: set = set()
    idx = 0

    for fn in all_fns:
        for call in fn.calls:
            kind = _syn_sink_kind(call["callee"], ceremony)
            if not kind:
                continue
            sink_rec = {
                "kind": kind, "callee": _last_segment(call["callee"]),
                "arg_pos": None, "fn": fn.name,
                "file": call["file"], "line": call["line"],
            }
            # syntactic taint heuristic: the sink fn's params are sources; walk
            # back through callers up to max_hops. We do NOT prove arg<->param
            # positional flow at this tier (no MIR), so each chain is advisory.
            stack: List[Tuple[_SynFn, List[Dict[str, Any]], List[Dict[str, Any]], int]] = [
                (fn, [], list(fn.guards), 0)
            ]
            # B-hops: visited-fn-name cycle guard so an UNBOUNDED ceiling terminates
            # on recursive call graphs (the syntactic tier walks by fn name).
            syn_visited: set = set()
            while stack:
                frame, hops, guards, depth = stack.pop()
                if frame.name in syn_visited:
                    continue
                syn_visited.add(frame.name)
                # every frame with params is a source candidate
                if frame.params:
                    src_var = next((p for p in frame.params if p != "self"), frame.params[0])
                    source_rec = {
                        "kind": "fn_param", "fn": frame.name, "var": src_var,
                        "file": frame.file, "line": frame.line,
                    }
                    sig = (frame.name, src_var, fn.name, sink_rec["callee"],
                           sink_rec["line"], len(hops))
                    if sig not in seen_sig:
                        seen_sig.add(sig)
                        rec = dfs.new_path(
                            path_id=f"rsf-{idx:04d}",
                            language="rust", direction="backward",
                            engine="treesitter.rust-defuse" if use_ts else "regex.rust-defuse",
                            source=source_rec, sink=sink_rec,
                            hops=list(reversed(hops)),
                            guard_nodes=[{"file": g["file"], "line": g["line"],
                                          "expr": g["expr"]} for g in guards],
                            source_unit_ids=[f"{crate}:{frame.name}"],
                            sink_unit_ids=[f"{crate}:{fn.name}:{sink_rec['line']}"],
                            confidence="syntactic", degraded=False,
                        )
                        rec["crate"] = crate
                        if depth >= max_hops and callers_of.get(frame.name):
                            rec["dataflow_truncated"] = True
                        records.append(rec)
                        idx += 1
                if depth >= max_hops:
                    continue
                for caller, c in callers_of.get(frame.name, []):
                    if caller is frame:
                        continue
                    hop = {
                        "from_var": (next((p for p in caller.params if p != "self"),
                                          caller.params[0]) if caller.params else "?"),
                        "to_var": (next((p for p in frame.params if p != "self"),
                                        frame.params[0]) if frame.params else "?"),
                        "fn": frame.name, "via": "internal_call",
                        "file": c["file"], "line": c["line"],
                        "ir": f"{caller.name} -> {frame.name}()",
                        "guarded": bool(caller.guards),
                    }
                    stack.append((caller, hops + [hop],
                                  guards + caller.guards, depth + 1))
    return records


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def run(workspace: Path, target: Optional[Path], mode: str,
        max_hops: int, timeout: int) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Return (records, per_crate_report)."""
    if target is not None:
        crates = [(rsg._crate_name_from_cargo(target, target.name), target.resolve())]
    else:
        crates = rsg.discover_crates(workspace)

    records: List[Dict[str, Any]] = []
    crate_report: Dict[str, Any] = {}

    for name, root in crates:
        backend = None
        err = None
        crate_recs: List[Dict[str, Any]] = []
        # ceremony crates (threshold-sig / DKG) also consult the ceremony sink
        # vocabulary so a crate that moves no ERC20/Promise value still yields a
        # real def-use surface (BitForge/GG20 key-extraction), un-starving
        # tools/mpc-round-proof-obligation.py.
        ceremony = _is_ceremony_crate(name, root)
        if mode in ("auto", "mir"):
            mir_text, err = emit_mir_for_crate(root, timeout)
            if mir_text is not None:
                fns = parse_mir_text(mir_text)
                crate_recs = mir_slices(workspace, fns, name, max_hops, ceremony,
                                        crate_root=root)
                backend = "mir"
        if backend is None and mode in ("auto", "syntactic"):
            crate_recs = syntactic_slices(workspace, name, root, max_hops, ceremony)
            backend = "syntactic" if _have_tree_sitter() else "regex"
        records.extend(crate_recs)
        max_depth = max([r.get("call_depth", 0) for r in crate_recs], default=0)
        crate_report[name] = {
            "crate_root": rsg._rel(workspace, root),
            "backend": backend,
            "ceremony_crate": ceremony,
            "mir_error": err if backend != "mir" else None,
            "records": len(crate_recs),
            "max_call_depth": max_depth,
            "multi_hop_ge2": sum(1 for r in crate_recs if r.get("call_depth", 0) >= 2),
            "unguarded": sum(1 for r in crate_recs if r.get("unguarded")),
        }
    return records, crate_report


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="rust-dataflow",
        description="Native offline Rust inter-procedural DefUsePath backend "
                    "(MIR-resolved Tier-1/2 + tree-sitter syntactic fallback).")
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument("--target", type=Path, default=None,
                    help="explicit crate dir (Cargo.toml root) to analyze")
    ap.add_argument("--mode", choices=["auto", "mir", "syntactic"], default="auto")
    ap.add_argument("--max-hops", type=int, default=MAX_HOPS_DEFAULT)
    ap.add_argument("--timeout", type=int, default=MIR_TIMEOUT_DEFAULT,
                    help="per-crate cargo-rustc MIR emit timeout (seconds)")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--no-merge", action="store_true",
                    help="truncate the sidecar instead of language-scoped merge "
                         "(legacy single-language behavior; drops other arms' rows)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    ws = args.workspace.expanduser().resolve()
    if not ws.is_dir():
        print(f"[rust-dataflow] ERR workspace not found: {ws}", file=sys.stderr)
        return 2

    out_dir = ws / ".auditooor"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = args.out.resolve() if args.out else (out_dir / "dataflow_paths.jsonl")

    # B-merge: language-scoped merge by default (preserve other arms' rows).
    _use_merge = not args.no_merge

    def _emit_records(recs: List[Dict[str, Any]]) -> int:
        if _use_merge:
            return dfs.merge_write(str(out_path), recs, "rust")
        return dfs.write_jsonl(str(out_path), recs)

    records, crate_report = run(ws, args.target, args.mode, args.max_hops, args.timeout)

    # R80 degrade: nothing from any crate -> single advisory degrade record.
    if not records:
        reasons = "; ".join(
            f"{k}:{v.get('mir_error') or v.get('backend') or 'no-records'}"
            for k, v in crate_report.items()
        ) or "no crate discovered"
        rec = dfs.degrade_record("rust", reasons[:500])
        _emit_records([rec])
        result = {"status": "degraded", "out": str(out_path), "records": 1,
                  "semantic_ssa_paths": 0, "crates": crate_report}
        print(json.dumps(result, indent=2) if args.json
              else f"DEGRADED (no flows): {out_path}\n  {reasons}")
        return 0

    # validate every record before write (keep producer honest)
    valid: List[Dict[str, Any]] = []
    invalid = 0
    for r in records:
        ok, _errs = dfs.validate(r)
        if ok:
            valid.append(r)
        else:
            invalid += 1
    n = _emit_records(valid)
    sem = sum(1 for r in valid if r.get("confidence") == "semantic-ssa" and not r.get("degraded"))
    syn = sum(1 for r in valid if r.get("confidence") == "syntactic" and not r.get("degraded"))
    unguarded = sum(1 for r in valid if r.get("unguarded"))
    multi_hop = sum(1 for r in valid if r.get("call_depth", 0) >= 2)
    max_depth = max([r.get("call_depth", 0) for r in valid], default=0)
    truncated = sum(1 for r in valid if r.get("dataflow_truncated"))

    result = {
        "status": "ok", "out": str(out_path), "records": n,
        "invalid_dropped": invalid,
        "semantic_ssa_paths": sem, "syntactic_paths": syn,
        "unguarded_paths": unguarded, "multi_hop_paths_ge2": multi_hop,
        "max_call_depth": max_depth, "dataflow_truncated_paths": truncated,
        "merged": _use_merge, "crates": crate_report,
    }
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"OK: wrote {n} DefUsePath records to {out_path}")
        print(f"  semantic-ssa={sem} syntactic={syn} unguarded={unguarded} "
              f"multi-hop(>=2)={multi_hop} max_depth={max_depth}")
        for k, v in crate_report.items():
            print(f"  crate {k}: backend={v['backend']} records={v['records']} "
                  f"max_depth={v['max_call_depth']}"
                  + (f" mir_error={v['mir_error']}" if v.get("mir_error") else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
