#!/usr/bin/env python3
"""nondeterministic-deserialization.py - NONDET-DESERIALIZATION-ON-CONSENSUS reasoner.

GENERAL LOGIC (a consensus-safety class, never a token grep for `map`/`interface`).
Untrusted bytes are DECODED/UNMARSHALLED into a Go value whose type is
NONDETERMINISTIC (a map iterated in range order, an `interface{}`/`any` dynamic
type, a `float32`/`float64`, or a non-canonical json/amino decode), AND the
decoded value FLOWS into a CONSENSUS-relevant sink (a store WRITE that becomes the
AppHash, a HASH input, an ABCI/validator-set/gas decision) on a BLOCK-PROCESSING
path (BeginBlock/EndBlock/DeliverTx/ProcessProposal/PrepareProposal/InitGenesis/
ExportGenesis/ante), with NO canonicalization / deterministic-encode / sort
barrier on that path. Two honest validators then derive DIFFERENT state from the
SAME bytes -> divergent AppHash -> chain split / halt (Critical).

REASONING QUERY (a reachability JOIN, NOT a shape):

  SURVIVOR := a decode/unmarshal NODE whose OUTPUT type is nondeterministic
    (map-with-range-iteration / interface{}/any / float32,64 / non-canonical
    json,amino) AND the decoded value reaches a CONSENSUS sink (store-write /
    hash-input / abci-decision / validator-set / gas) on a block-processing path,
    with NO canonicalization barrier (sort.* / deterministic Marshal / canonical
    encode) dominating that path.

  NONDET_DECODE_REACHING_CONSENSUS  \\  CANONICALIZED  =  SURVIVORS

GUARD-RAIL (three independent predicates ANDed, never a grep for map/interface):
  1. nondeterministic-type  - the decode's destination TYPE is provably a
     range-iterated map / interface{}/any / float / non-canonical json-amino.
  2. consensus-reachability - the enclosing fn is a block-processing entrypoint
     OR the decoded value flows to a consensus sink token in the same fn.
  3. no-canonicalization-barrier - no sort.* / canonical-marshal / deterministic
     encode on the decoded destination before the sink.
A decode into a TYPED STRUCT (deterministic) is NOT nondet-typed -> dropped. A
decode whose value never reaches a consensus sink is NOT consensus-reaching ->
dropped. A path with a dominating canonical barrier is CANONICALIZED -> dropped.

HONESTY (never silent):
  * substrate_vacuous : no in-scope .go file OR zero decode nodes over the real
    substrate -> the join CANNOT run; emit nothing, status "substrate_vacuous"
    (fail-closed under --fail-closed).
  * cited_empty       : decode nodes present, join ran, zero survivors -> honest 0
    (status "cited_empty"), every counted node cited file:line.
  * needs_source (advisory): a decode into a nondeterministic type that COULD not
    be confirmed consensus-reaching from static shape (nondet-typed but no
    in-fn consensus sink and the fn is not a recognised block-processing
    entrypoint) -> emit an ADVISORY needs_source obligation (never a survivor,
    never terminal) so it is not silently dropped.

Every emitted row cites a real file:line anchor (the decode node + the sink token).

Usage:
  python3 tools/nondeterministic-deserialization.py --workspace <ws>
        [--src-root DIR] [--emit PATH] [--json] [--fail-closed]

Output: <ws>/.auditooor/nondeterministic_deserialization_obligations.jsonl
        (schema auditooor.nondeterministic_deserialization.v1) + summary on stderr.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

SCHEMA = "auditooor.nondeterministic_deserialization.v1"
_SIDE_NAME = "nondeterministic_deserialization_obligations.jsonl"
_STRICT_ENV = "AUDITOOOR_NONDET_DESER_STRICT"
_CAPABILITY = "NONDET_DESER"
AUDITOOOR = ".auditooor"

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

# --- shared exclusion (reuse, never rebuild) --------------------------------
try:  # tools/lib/synthetic_target_exclusion.py
    from lib.synthetic_target_exclusion import (  # noqa: E402
        is_chimera_mutation_harness_path,
        is_codegen_path,
        is_test_target_path,
    )
except Exception:  # pragma: no cover - degrade to no-op if lib unavailable
    def is_test_target_path(_p):  # type: ignore
        return False

    def is_codegen_path(_p, workspace=None):  # type: ignore
        return False

    def is_chimera_mutation_harness_path(_p):  # type: ignore
        return False


_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "lib", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmarks", "script", "scripts", "deployments",
              "prior_audits", "reference", "certora", "simulation", "testdata",
              "mocks", "mock", "artifacts", "chimera_harnesses"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|testutil|testonly|testhelper|test_fixtures|mock|mocks|"
    r"benches|benchmarks?|examples|fixtures|simulation|simapp|testdata|poc|"
    r"chimera_harnesses)(/|$)")
_CODEGEN_SENTINEL = re.compile(r"Code generated .{0,80}?DO NOT EDIT", re.I)

# OFF-CONSENSUS node subsystems: tendermint/cometbft-internal RPC, pubsub,
# mempool, p2p, statesync/blocksync, light-client, privval, tx indexer are NOT
# the deterministic app state machine - a value they decode feeds an RPC response
# / subscription, never the block AppHash, so it cannot cause a consensus halt.
_OFFCONSENSUS_PATH = re.compile(
    r"(^|/)(rpc|coretypes|jsonrpc|pubsub|mempool|p2p|statesync|blocksync|"
    r"blockchain|fastsync|light|privval|indexer|inspect|proxy|libs|cmd|client|"
    r"cli|docs|testutil)(/|$)", re.I)


# ============================================================================
# comment / string masking (Go C-ish comments + backtick raw strings).
# ============================================================================
def _mask_comments(text: str) -> str:
    out = []
    i, n = 0, len(text)
    in_line = in_block = in_str = in_raw = False
    quote = ""
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line:
            out.append("\n" if c == "\n" else " ")
            if c == "\n":
                in_line = False
            i += 1
        elif in_block:
            if c == "*" and nxt == "/":
                out.append("  ")
                i += 2
                in_block = False
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
        elif in_str:
            out.append(" ")
            if c == "\\":
                out.append(" ")
                i += 2
                continue
            if c == quote:
                in_str = False
            i += 1
        elif in_raw:
            out.append("\n" if c == "\n" else " ")
            if c == "`":
                in_raw = False
            i += 1
        elif c == "`":
            in_raw = True
            out.append(" ")
            i += 1
        elif c in ('"', "'"):
            in_str = True
            quote = c
            out.append(" ")
            i += 1
        elif c == "/" and nxt == "/":
            in_line = True
            out.append("  ")
            i += 2
        elif c == "/" and nxt == "*":
            in_block = True
            out.append("  ")
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _line_of_offset(text: str, off: int) -> int:
    return text.count("\n", 0, off) + 1


def _excerpt(text: str, off: int) -> str:
    ls = text.rfind("\n", 0, off) + 1
    le = text.find("\n", off)
    if le == -1:
        le = len(text)
    return text[ls:le].strip()[:200]


def _stable_id(rel, kind, subject, line):
    h = hashlib.sha1()
    h.update(f"{rel}|{kind}|{subject}|{line}".encode())
    return h.hexdigest()[:16]


def _paren_span(text: str, open_idx: int):
    depth = 0
    n = len(text)
    i = open_idx
    while i < n:
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i], i
        i += 1
    return text[open_idx + 1:], -1


def _brace_span(text: str, open_idx: int):
    depth = 0
    n = len(text)
    i = open_idx
    while i < n:
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i], i
        i += 1
    return text[open_idx + 1:], -1


# ============================================================================
# Go function iteration.
# ============================================================================
_FUNC_RE = re.compile(
    r"\bfunc\b\s*(?:\(\s*(?P<recv>[^)]*)\)\s*)?(?P<name>[A-Za-z_]\w*)\s*\(")


class _GoFn:
    __slots__ = ("name", "receiver", "params", "return_sig", "body",
                 "body_off", "sig")

    def __init__(self, name, receiver, params, return_sig, body, body_off, sig):
        self.name = name
        self.receiver = receiver
        self.params = params
        self.return_sig = return_sig
        self.body = body
        self.body_off = body_off
        self.sig = sig


def _iter_functions(text: str):
    for m in _FUNC_RE.finditer(text):
        popen = m.end() - 1
        params, pclose = _paren_span(text, popen)
        if pclose == -1:
            continue
        brace = text.find("{", pclose)
        if brace == -1:
            continue
        return_sig = text[pclose + 1:brace].strip()
        body, bclose = _brace_span(text, brace)
        if bclose == -1:
            continue
        sig = text[m.start():brace].strip()
        yield _GoFn(m.group("name"), (m.group("recv") or "").strip(),
                    params, return_sig, body, brace + 1, sig)


# ============================================================================
# PREDICATE 1 - decode/unmarshal NODES + their destination variable.
# ============================================================================
# codec/amino/json/proto decode calls whose LAST arg is the destination pointer.
# `X.Unmarshal(bz, &dst)`, `json.Unmarshal(bz, &dst)`, `cdc.UnmarshalJSON(bz,
# &dst)`, `proto.Unmarshal(bz, &dst)`, `X.MustUnmarshalJSON(bz, &dst)`, ...
_DECODE_CALL_RE = re.compile(
    r"(?P<recv>[A-Za-z_][\w.]*)\.(?P<meth>(?:Must)?Unmarshal(?:JSON|Binary|"
    r"BinaryBare|BinaryLengthPrefixed|Amino|Length)?)\s*\(")
# `json.NewDecoder(r).Decode(&dst)` (bare-package json/amino non-canonical decode)
_DECODER_DECODE_RE = re.compile(
    r"\b(?P<pkg>json|amino|gob|xml|yaml|toml)\.NewDecoder\s*\(")
_DECODE_METHOD_RE = re.compile(r"\.Decode\s*\(")


def _last_arg_ident(argtext: str) -> str | None:
    """Return the bare identifier the decode targets (`&dst` or `dst` as the LAST
    argument), stripping `&`, `*` and a leading dotted receiver's last segment."""
    # split top-level commas
    depth = 0
    parts = []
    cur = []
    for ch in argtext:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    if not parts:
        return None
    last = parts[-1].strip()
    last = last.lstrip("&*").strip()
    m = re.match(r"([A-Za-z_][\w.]*)", last)
    if not m:
        return None
    return m.group(1)


def _iter_decode_nodes(body: str):
    """Yield (offset, dst_ident, decode_kind, call_excerpt_frag). decode_kind in
    {'json','amino','proto','binary','decoder'}."""
    # method-style X.Unmarshal(...)
    for m in _DECODE_CALL_RE.finditer(body):
        popen = m.end() - 1
        args, close = _paren_span(body, popen)
        if close == -1:
            continue
        dst = _last_arg_ident(args)
        if not dst:
            continue
        meth = m.group("meth").lower()
        recv = m.group("recv").lower()
        if "json" in meth:
            kind = "json"
        elif "amino" in meth or "amino" in recv:
            kind = "amino"
        elif "binary" in meth or "length" in meth:
            kind = "binary"
        elif "proto" in recv:
            kind = "proto"
        else:
            # bare Unmarshal via a codec/cdc receiver -> amino/proto family
            kind = "amino" if ("cdc" in recv or "codec" in recv
                               or "amino" in recv) else "binary"
        yield m.start(), dst, kind, body[m.start():close + 1][:160]
    # decoder-style pkg.NewDecoder(r).Decode(&dst)
    for m in _DECODER_DECODE_RE.finditer(body):
        popen = m.end() - 1
        _inner, close = _paren_span(body, popen)
        if close == -1:
            continue
        dm = _DECODE_METHOD_RE.search(body, close, close + 40)
        if not dm:
            continue
        popen2 = dm.end() - 1
        args, close2 = _paren_span(body, popen2)
        if close2 == -1:
            continue
        dst = _last_arg_ident(args)
        if not dst:
            continue
        pkg = m.group("pkg")
        kind = "json" if pkg in ("json", "yaml", "xml", "toml") else "decoder"
        yield m.start(), dst, kind, body[m.start():close2 + 1][:160]


# ============================================================================
# PREDICATE 2 - nondeterministic destination TYPE.
# ============================================================================
def _decl_type_of(ident: str, scopes) -> str | None:
    """Best-effort static type of a bare identifier from a var/param/short decl in
    any scope. Returns the raw type text (e.g. 'map[string]int', 'interface{}',
    'float64', '[]float64', 'MyStruct')."""
    seg = ident.split(".")[-1]
    e = re.escape(seg)
    pats = (
        rf"\bvar\s+{e}\s+([^\n=]+)",              # var x T
        rf"\b{e}\s+(map\[[^\n]+)",                # struct field / param  x map[...]
        rf"\b{e}\s+(interface\s*\{{\s*\}})",       # x interface{}
        rf"\b{e}\s+(any)\b",                       # x any
        rf"\b{e}\s+(\[\]\s*(?:float32|float64|interface\s*\{{\s*\}}|any))",
        rf"\b{e}\s+(float32|float64)\b",           # x float64
        rf"\b{e}\s*:?=\s*make\((map\[[^\n)]+)\)",  # x := make(map[...])
        rf"\b{e}\s*:?=\s*(map\[[^\n{{]+)\{{",       # x := map[...]{...}
        rf"\b{e}\s*:?=\s*(\[\]\s*(?:float32|float64))\s*\{{",
    )
    for s in scopes:
        if not s:
            continue
        for p in pats:
            mm = re.search(p, s)
            if mm:
                return mm.group(1).strip()
    return None


_MAP_T = re.compile(r"^\s*(?:\*)?map\[")
_IFACE_T = re.compile(r"interface\s*\{\s*\}|(^|[\[\]\s])any($|[\s,\}])")
_FLOAT_T = re.compile(r"\bfloat(?:32|64)\b")


def _range_iterates(ident: str, body: str) -> bool:
    e = re.escape(ident.split(".")[-1])
    return bool(re.search(r"\brange\s+" + e + r"\b", body))


def _classify_nondet_type(ident, decode_kind, scopes, body):
    """-> (nondet_kind, confirmed_type) or (None, None). nondet_kind in
    {'map-range','interface-any','float','noncanonical-json-amino'}."""
    t = _decl_type_of(ident, scopes)
    if t:
        if _MAP_T.search(t):
            # a decoded map is nondet ONLY if it is later range-iterated (the
            # ordering leak). A keyed lookup m[k] is order-invariant.
            if _range_iterates(ident, body):
                return "map-range", t
            # map decoded but not range-iterated: still non-canonical json/amino
            # if the decode is json/amino (map serialization order differs), but
            # weaker -> tag noncanonical only for json/amino.
            if decode_kind in ("json", "amino", "decoder"):
                return "noncanonical-json-amino", t
            return None, None
        if _IFACE_T.search(t):
            return "interface-any", t
        if _FLOAT_T.search(t):
            return "float", t
        # a concrete typed struct decode -> deterministic; not nondet.
        return None, None
    # type unknown: if the decode is json/amino into an unknown dest, it MAY be a
    # map/interface (non-canonical) - treat as advisory noncanonical (needs_source
    # decided later by reachability). We DON'T claim a confirmed nondet type.
    if decode_kind in ("json", "amino", "decoder"):
        return "noncanonical-json-amino", None
    return None, None


# ============================================================================
# PREDICATE 3 - consensus reachability + canonicalization barrier.
# ============================================================================
# block-processing entrypoints (fn is ON the consensus path by name).
_BLOCKPROC_NAME = re.compile(
    r"\b(BeginBlock(?:er)?|EndBlock(?:er)?|DeliverTx|PrepareProposal|"
    r"ProcessProposal|InitGenesis|ExportGenesis|AnteHandle|PostHandle|"
    r"ExtendVote|VerifyVoteExtension|Commit)\b")
# consensus SINK tokens the decoded value can flow into (in-fn).
_STORE_WRITE = re.compile(
    r"\b(?:store|ctx\.KVStore\([^)]*\)|prefixStore|k\.store|\w*[Ss]tore)\.Set\b|"
    r"\.Set\(\s*|SetParams\b|\.Save\(|\.Insert\(|\.Write\(")
_HASH_SINK = re.compile(
    r"\b(?:sha256|sha3|keccak256|blake2b|Sum256|crypto\.Hash|tmhash|"
    r"HashFromBytes|AppHash|merkle\.)\b", re.I)
_ABCI_SINK = re.compile(
    r"\bValidatorUpdate\b|\babci\.Event\b|\bsdk\.Events\b|GasMeter|ConsumeGas|"
    r"\bValsetUpdate\b|SetValidator\b")
# canonicalization / deterministic-encode / sort barriers.
_CANON_BARRIER = re.compile(
    r"\b(?:sort\.(?:Slice|SliceStable|Strings|Sort|Stable|Ints|Float64s)|"
    r"slices\.(?:Sort|SortFunc|SortStableFunc)|"
    r"(?:Must)?MarshalBinary(?:Bare|LengthPrefixed)?|proto\.Marshal|"
    r"MarshalDeterministic|CanonicalizeJSON|sdk\.SortJSON|"
    r"MarshalCanonical|deterministicMarshal|ModuleCdc\.MustMarshal)\s*\(")


def _consensus_sink_hit(ident: str, sink_scope: str):
    """Return (sink_kind, sink_excerpt) if the decoded ident flows to a consensus
    sink within sink_scope (text after the decode). Requires the ident (or its
    last segment) to appear near a sink token OR the fn to be a block entrypoint.
    We look for a sink token in sink_scope AND the ident used in sink_scope."""
    e = re.escape(ident.split(".")[-1])
    ident_used = re.search(r"\b" + e + r"\b", sink_scope)
    if not ident_used:
        return None, None
    for rx, kind in ((_STORE_WRITE, "store-write"), (_HASH_SINK, "hash-input"),
                     (_ABCI_SINK, "abci-decision")):
        m = rx.search(sink_scope)
        if m:
            return kind, sink_scope[max(0, m.start() - 20):m.start() + 60].strip()
    return None, None


def _barrier_dominates(ident: str, pre_sink_scope: str) -> bool:
    """True if a canonicalization/sort barrier is applied to the decoded ident (or
    the decode is re-marshalled deterministically) before the sink."""
    for m in _CANON_BARRIER.finditer(pre_sink_scope):
        # barrier applies if the decoded ident (last seg) appears in the barrier
        # call's arg span, OR a deterministic re-marshal happens at all in-scope.
        popen = pre_sink_scope.find("(", m.end() - 1)
        if popen == -1:
            continue
        args, close = _paren_span(pre_sink_scope, popen)
        seg = re.escape(ident.split(".")[-1])
        if re.search(r"\b" + seg + r"\b", args):
            return True
        # a deterministic Marshal* of anything before an AppHash sink neutralises
        # the ordering nondeterminism for the serialized bytes.
        if "arshal" in m.group(0):
            return True
    return False


# ============================================================================
# CORE JOIN per function.
# ============================================================================
def _scan_function(fn: _GoFn, file_text: str, rel: str, stats, rows, needs_src):
    body = fn.body
    if "arshal" not in body and "Decode" not in body:
        return
    scopes = (file_text, fn.params, fn.receiver, body)
    is_blockproc = bool(_BLOCKPROC_NAME.search(fn.name)
                        or _BLOCKPROC_NAME.search(fn.sig))
    for off, dst, dkind, frag in _iter_decode_nodes(body):
        stats["decode_nodes"] += 1
        # PREDICATE 1 done (decode node + dst).
        nondet_kind, ctype = _classify_nondet_type(dst, dkind, scopes, body)
        if nondet_kind is None:
            continue  # deterministic typed decode -> not nondet-typed
        stats["nondet_typed"] += 1
        # scope AFTER the decode is where the value flows to a sink.
        sink_scope = body[off:]
        pre_sink_scope = body[off:]
        sink_kind, sink_excerpt = _consensus_sink_hit(dst, sink_scope)
        consensus_reaching = bool(sink_kind) or is_blockproc
        if consensus_reaching:
            stats["consensus_reaching"] += 1
        # PREDICATE 3 - canonicalization barrier.
        canonicalized = _barrier_dominates(dst, pre_sink_scope)
        if canonicalized:
            stats["canonicalized"] += 1

        loop_off = fn.body_off + off
        line = _line_of_offset(file_text, loop_off)
        excerpt = _excerpt(file_text, loop_off)

        if not consensus_reaching:
            # nondet-typed but reachability unconfirmed -> ADVISORY needs_source.
            # A confirmed-type nondet decode is a stronger advisory than an
            # unknown-type json/amino guess; only emit needs_source when the
            # nondet TYPE was CONFIRMED (avoid spraying every json decode).
            if ctype is not None:
                needs_src.append({
                    "unit": f"{rel}::{fn.name}",
                    "file": rel, "line": line, "function": fn.name,
                    "decode_var": dst, "decode_kind": dkind,
                    "nondet_kind": nondet_kind, "nondet_type": ctype,
                    "excerpt": excerpt,
                    "reason": ("decode into a CONFIRMED nondeterministic type but "
                               "no in-fn consensus sink and the enclosing fn is "
                               "not a recognised block-processing entrypoint - "
                               "consensus-reachability needs a call-path trace"),
                })
            continue
        if canonicalized:
            continue  # a canonical/sort barrier neutralises the ordering leak
        # SURVIVOR.
        sink_desc = sink_kind or ("block-processing-entrypoint")
        sink_ln = line
        if sink_excerpt:
            # locate sink line for citation
            sm = _consensus_sink_hit(dst, sink_scope)
        confirmed = ctype is not None
        severity = "high" if confirmed else "medium"
        rows.append(_mk_row(
            rel, fn.name, line, dst, dkind, nondet_kind, ctype, sink_desc,
            sink_excerpt or "", is_blockproc, severity, excerpt,
            _why(fn, dst, dkind, nondet_kind, ctype, sink_desc, is_blockproc,
                 confirmed)))


def _why(fn, dst, dkind, nondet_kind, ctype, sink_desc, is_blockproc, confirmed):
    tdesc = {
        "map-range": f"a Go map (`{ctype}`) that is iterated with `range` (RANDOMIZED order)",
        "interface-any": f"an `interface{{}}`/`any` dynamic type (`{ctype}`) whose concrete decode is input-dependent",
        "float": f"a floating-point type (`{ctype}`) whose bit-result is NOT deterministic across architectures/compilers",
        "noncanonical-json-amino": "a non-canonical json/amino target (key/field ordering is not canonicalised)",
    }.get(nondet_kind, nondet_kind)
    path = ("the enclosing fn is a block-processing entrypoint "
            f"`{fn.name}` (ON the consensus path)" if is_blockproc
            else f"the decoded value flows to a {sink_desc} consensus sink in `{fn.name}`")
    base = (
        f"`{dkind}` decodes untrusted bytes into `{dst}`, which is {tdesc}; "
        f"{path}, with NO canonicalization / deterministic-encode / sort barrier "
        f"on `{dst}` before the {sink_desc} sink. Two honest validators decoding "
        f"the SAME bytes therefore derive DIFFERENT consensus state -> divergent "
        f"AppHash -> chain split / halt (consensus-safety, Critical).")
    if confirmed:
        return base + (
            f" The nondeterministic type is STATICALLY CONFIRMED ({nondet_kind}); "
            f"severity=high. Fix: decode into a deterministic typed struct, or "
            f"sort/canonicalize `{dst}` before it reaches the sink.")
    return base + (
        f" The nondeterministic type could not be STATICALLY CONFIRMED (json/amino "
        f"decode into an unresolved dest); severity=medium pending the dest-type "
        f"trace. Fix: confirm the dest type; canonicalize before the sink.")


def _mk_row(rel, fn, line, dst, dkind, nondet_kind, ctype, sink_desc,
            sink_excerpt, is_blockproc, severity, excerpt, why):
    return {
        "schema": SCHEMA,
        "capability": _CAPABILITY,
        "id": _stable_id(rel, nondet_kind, fn + "|" + dst, line),
        "verdict": "survivor",
        "proof_status": "open",
        "attack_class": "nondeterministic-deserialization-consensus",
        "file": rel,
        "line": line,
        "function": fn,
        "decode_var": dst,
        "decode_kind": dkind,
        "nondet_kind": nondet_kind,
        "nondet_type": ctype,
        "consensus_sink": sink_desc,
        "sink_excerpt": sink_excerpt,
        "block_processing_entrypoint": is_blockproc,
        "canonicalization_barrier": False,
        "excerpt": excerpt,
        "severity": severity,
        "why_severity_anchored": why,
        "advisory": True,
        "auto_credit": False,
    }


# ============================================================================
# per-file scan
# ============================================================================
def scan_file(path: Path, rel: str, stats, file_text: str = None):
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    if not rel.lower().endswith(".go"):
        return [], []
    text = _mask_comments(raw)
    rows, needs_src = [], []
    for fn in _iter_functions(text):
        _scan_function(fn, text, rel, stats, rows, needs_src)
    return rows, needs_src


# ============================================================================
# tree walk
# ============================================================================
def _iter_source_files(root: Path, workspace: Path = None):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        if _TEST_HINT.search(dp.replace(os.sep, "/")):
            continue
        for f in fn:
            low = f.lower()
            if not low.endswith(".go"):
                continue
            if low.endswith("_test.go") or low.endswith(".pb.go") \
                    or low.endswith(".pulsar.go"):
                continue
            if _TEST_HINT.search(f) or low.startswith("mock") \
                    or low.startswith("test"):
                continue
            p = Path(dp) / f
            rel = str(p)
            if _OFFCONSENSUS_PATH.search(rel.replace(os.sep, "/")):
                continue
            if (is_test_target_path(rel)
                    or is_chimera_mutation_harness_path(rel)
                    or is_codegen_path(rel, workspace)):
                continue
            try:
                head = p.read_text(encoding="utf-8", errors="replace")[:4096]
                if _CODEGEN_SENTINEL.search(head):
                    continue
            except OSError:
                continue
            yield p


def scan_tree(root: Path, workspace: Path = None):
    stats = {"files": 0, "decode_nodes": 0, "nondet_typed": 0,
             "consensus_reaching": 0, "canonicalized": 0}
    rows, needs_src = [], []
    for p in _iter_source_files(root, workspace):
        stats["files"] += 1
        try:
            rel = str(p.relative_to(root))
        except ValueError:
            rel = str(p)
        try:
            r, ns = scan_file(p, rel, stats)
            rows.extend(r)
            needs_src.extend(ns)
        except Exception:
            continue
    return rows, needs_src, stats


# ============================================================================
# report + emit
# ============================================================================
def run(ws: Path, src_root: str | None = None) -> dict:
    if src_root:
        root = Path(src_root)
    else:
        src = ws / "src"
        root = src if src.exists() else ws
    rows, needs_src, stats = scan_tree(root, workspace=ws)

    substrate_vacuous = (stats["files"] == 0) or (stats["decode_nodes"] == 0)
    status = "substrate_vacuous" if substrate_vacuous else (
        "survivors" if rows else "cited_empty")

    kept = sorted({f"{r['file']}:{r['line']}::{r['function']}" for r in rows})
    return {
        "schema": SCHEMA,
        "capability": _CAPABILITY,
        "workspace": str(ws),
        "src_root": str(root),
        "status": status,
        "substrate": {
            "go_files": stats["files"],
            "decode_nodes": stats["decode_nodes"],
            "nondeterministic_typed": stats["nondet_typed"],
            "consensus_reaching": stats["consensus_reaching"],
            "canonicalized": stats["canonicalized"],
            "vacuous": substrate_vacuous,
        },
        "survivor_count": len(rows),
        "needs_source_count": len(needs_src),
        "survivors": rows,
        "needs_source": needs_src,
        "kept": kept,
        "by_nondet_kind": _count(rows, "nondet_kind"),
        "by_severity": _count(rows, "severity"),
        "advisory": True,
        "auto_credit": False,
    }


def _count(rows, key):
    out: dict = defaultdict(int)
    for r in rows:
        out[str(r.get(key, ""))] += 1
    return dict(sorted(out.items()))


def _emit_rows(rep: dict, outp: Path) -> int:
    outp.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with outp.open("w") as fh:
        for s in rep["survivors"]:
            fh.write(json.dumps(s) + "\n")
            n += 1
        for ns in rep["needs_source"]:
            row = {
                "schema": SCHEMA,
                "capability": _CAPABILITY,
                "verdict": "needs_source",
                "proof_status": "open",
                "advisory": True,
                "auto_credit": False,
                "attack_class": "nondeterministic-deserialization-consensus",
                **ns,
            }
            fh.write(json.dumps(row) + "\n")
            n += 1
        # Capability-vacuity-telltale: the decode-node join RAN over a real (non-
        # vacuous) Go surface and produced 0 survivors. PERSIST an explicit cited-
        # empty examined-record so the reasoner-firing gate scores this FIRED_CLEAN
        # (ran, examined, recorded 0) instead of reading the silently-empty ledger
        # as VACUOUS. Never emit nothing after a non-vacuous examination.
        if n == 0 and rep.get("status") == "cited_empty":
            fh.write(json.dumps({
                "schema": SCHEMA,
                "capability": _CAPABILITY,
                "verdict": "cited_empty",
                "note": ("cited-empty: decode-node join ran over the in-scope Go "
                         "surface, 0 nondeterministic-deserialization survivors"),
                "advisory": True,
                "auto_credit": False,
                "survivors": [],
                "report": {
                    "reasoner": "nondeterministic-deserialization",
                    "status": rep.get("status"),
                    "substrate": rep.get("substrate", {}),
                    "totals": {"examined": int(
                        rep.get("substrate", {}).get("decode_nodes", 0) or 0)},
                },
            }) + "\n")
            n += 1
    return n


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", "--ws", required=True)
    ap.add_argument("--src-root", default=None,
                    help="source root to scan (default <ws>/src or <ws>)")
    ap.add_argument("--emit", default=None,
                    help="output jsonl (default <ws>/.auditooor/"
                         + _SIDE_NAME + ")")
    ap.add_argument("--json", action="store_true",
                    help="emit full report JSON to stdout")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit non-zero on substrate_vacuous (join cannot run)")
    args = ap.parse_args(argv)

    ws = Path(args.workspace)
    if not ws.is_absolute():
        cand = Path("/Users/wolf/audits") / args.workspace
        if cand.exists():
            ws = cand
    ws = ws.resolve()
    if not ws.exists():
        print(f"[err] workspace not found: {ws}", file=sys.stderr)
        return 2

    strict = args.fail_closed or os.environ.get(
        _STRICT_ENV, "").strip() not in ("", "0", "false")

    rep = run(ws, src_root=args.src_root)

    outp = Path(args.emit) if args.emit else (ws / AUDITOOOR / _SIDE_NAME)
    n = _emit_rows(rep, outp)

    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        s = rep["substrate"]
        print(f"[nondet-deser] ws={ws.name} status={rep['status']} "
              f"decode_nodes={s['decode_nodes']} nondet_typed={s['nondeterministic_typed']} "
              f"consensus_reaching={s['consensus_reaching']} canonicalized={s['canonicalized']} "
              f"survivors={rep['survivor_count']} needs_source={rep['needs_source_count']} "
              f"-> {outp} ({n} rows)", file=sys.stderr)
        for k, c in rep["by_nondet_kind"].items():
            print(f"    {k:26s} survivors={c}", file=sys.stderr)

    if strict and rep["status"] == "substrate_vacuous":
        print("[nondet-deser] FAIL-CLOSED: substrate vacuous (no decode nodes)",
              file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
