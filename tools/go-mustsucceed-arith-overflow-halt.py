#!/usr/bin/env python3
"""go-mustsucceed-arith-overflow-halt.py - the Go Dec/Int overflow-panic
consensus-halt reasoning query.

LOGIC CAPABILITY (docs/LOGIC_ARSENAL_BURNDOWN.md ranks 2-3; the UNBUILT sibling
dimension of tools/go-mustsucceed-panic-reachability.py). This is a SET-DIFFERENCE
over a dominance relation on the Go call graph, NOT a grep for `.Mul(`.

THE INVARIANT (Cosmos/Go-L1 deterministic validator halt via arithmetic panic)
  A Cosmos math.LegacyDec / sdkmath.Int operation PANICS on overflow (a result
  wider than 315 bits) or on division-by-zero. baseapp runs the ABCI / module-
  lifecycle path - BeginBlock(er) / EndBlock(er) / PreBlock(er) / FinalizeBlock /
  PrepareProposal / ProcessProposal / ExtendVote / VerifyVoteExtension / InitChain
  / Commit - OUTSIDE the per-tx `recoverTx` deferred-recover, so an un-recovered
  panic there is NOT caught-and-rolled-back (as it is for a Msg handler). It
  propagates, every honest validator re-executes the same block deterministically,
  and the chain HALTS = permanent freeze of all funds. The trust boundary requires:

    For every overflow-/div-zero-capable arithmetic node N whose magnitude operand
    is data-dependent on a msg-settable / persisted value (interest rate, NAV,
    principal, duration, bips): N is EITHER unreachable in the forward call-closure
    of a MUST-SUCCEED root, OR a range / cap / IsZero dominator on that operand
    precedes N on every path.

  Set relation computed:
    SURVIVORS = ( ARITH_PANIC_NODES
                  INTERSECT REACHABLE_FROM_MUSTSUCCEED
                  INTERSECT MAGNITUDE_PARAM_OR_STATE_TAINTED )
                MINUS BOUND_DOMINATED

WHY THIS IS LOGIC, NOT A SHAPE (guard-rail satisfied)
  `body_contains('.Mul(') and not body_contains('Bound')` is REJECTED - it cannot
  distinguish a recover-wrapped Msg handler (panic = failed tx, harmless) from a
  must-succeed ABCI hook (panic = chain halt), and it never proves the magnitude is
  externally influenceable nor that a bound *dominates* the node. This query differs
  on three relational axes:
    (a) SINK membership is a semantic fact: a Dec/Int Mul/Quo/Power/ExpDec whose
        magnitude operand a lightweight backward slice traces to a *parameter* or a
        *persisted-state read* - the Safe* variants (SafeMul/SafeQuo) that return an
        error instead of panicking are excluded.
    (b) the answer is a RELATION between two function sets: {fns in the forward
        call-closure of a must-succeed root} INTERSECT {fns holding a tainted
        arith-panic node} - a node three helper-hops below EndBlocker is INCLUDED, the
        identical op inside a recover-wrapped Msg handler is EXCLUDED (goes to KEPT).
    (c) BOUND_DOMINATED is a dominance query: a `RequireBound` / `LTE(max)` / `IsZero`
        token appearing ANYWHERE in the body does NOT clear the node unless it
        dominates the arithmetic (a prior line on the operand's identifier).

SELF-CONTAINED SUBSTRATE (do-NOT #10: reuse, do not rebuild an engine)
  The owned tools/go-dataflow.py arm does NOT yet emit an arith-panic sink kind (its
  panic arm is type-assert/index/nil-deref only) and its Go call-edge set under-emits
  the ABCI->keeper closure (see MEMORY: "Go dataflow arm under-emits"). So this tool:
    1. CONSUMES <ws>/.auditooor/dataflow_paths*.jsonl for auxiliary taint edges when
       present (advisory enrichment), AND
    2. runs its OWN lightweight, SSA-free source pass over the in-scope Go tree to
       build a name-based call graph, locate arith-panic nodes, slice magnitude taint,
       and test bound-dominance. The ideal go-dataflow extension is documented in
       agent_outputs/WIRING_SPEC_go_arith_overflow_halt.md.
  Must-succeed ROOT names come from tools/go_entrypoint_surface (single source of
  truth: _ABCI_CONSENSUS_NAMES | _MODULE_LIFECYCLE_NAMES minus recover-wrapped).

OUTPUT
  <ws>/.auditooor/mustsucceed_arith_overflow_obligations.jsonl - one row per
  survivor, schema `auditooor.mustsucceed_arith_overflow.v1`. A --json summary
  reports |must-succeed roots|, |arith-panic nodes|, |tainted|, |survivors|, and the
  KEPT set (tainted arith nodes NOT reachable from any root, or bound-dominated) to
  prove the reachability + dominance filters are non-vacuous. Honest cited-empty
  (survivors=0 with a non-empty KEPT witness) vs substrate_vacuous (no arith nodes
  found at all) are distinguished. Every survivor is advisory_only=needs_source when
  taint / dominance is heuristic (an executed restart-survival PoC per R82 is the
  terminal verdict).
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent

# ---------------------------------------------------------------------------
# MUST-SUCCEED entrypoint families (single source of truth: go_entrypoint_surface)
# ---------------------------------------------------------------------------
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
try:
    from go_entrypoint_surface import (  # type: ignore
        _ABCI_CONSENSUS_NAMES as _ABCI,
        _MODULE_LIFECYCLE_NAMES as _LIFECYCLE,
    )
    _MUSTSUCCEED_NAMES = set(_ABCI) | set(_LIFECYCLE)
    _MUSTSUCCEED_SRC = "go_entrypoint_surface"
except Exception:  # pragma: no cover - defensive fallback
    _MUSTSUCCEED_NAMES = {
        "InitChain", "PrepareProposal", "ProcessProposal", "ExtendVote",
        "VerifyVoteExtension", "FinalizeBlock", "Commit",
        "BeginBlock", "EndBlock", "Midblock", "MidBlock",
        "PreBlocker", "PreBlock", "BeginBlocker", "EndBlocker", "Midblocker",
    }
    _MUSTSUCCEED_SRC = "local-fallback"

# CheckTx/DeliverTx/Query/Info are recover-wrapped or read-only in baseapp - a panic
# there does NOT halt consensus; exclude them from the must-succeed ROOT set.
_RECOVER_WRAPPED_ROOTS = {"CheckTx", "DeliverTx", "Query", "Info"}
_MUSTSUCCEED_NAMES = {n for n in _MUSTSUCCEED_NAMES
                      if n not in _RECOVER_WRAPPED_ROOTS}

# ---------------------------------------------------------------------------
# scope OOS guard (single source of truth); degrade to a conservative default.
# ---------------------------------------------------------------------------
try:
    from lib.scope_exclusion import is_oos  # type: ignore
except Exception:  # pragma: no cover
    _LIB = _HERE / "lib"
    if str(_LIB) not in sys.path:
        sys.path.insert(0, str(_LIB))
    try:
        from scope_exclusion import is_oos  # type: ignore
    except Exception:
        def is_oos(rel: str, **_) -> bool:  # type: ignore[misc]
            n = ("/" + str(rel).replace("\\", "/")).lower()
            return any(m in n for m in (
                "/test/", "/tests/", "_test.", "/mock", "/mocks/", "/vendor/",
                "/node_modules/", "/out/", "/build/", "/target/", "/.auditooor/",
                "/simulation/",
            ))

_VENDOR_MARKERS = ("/pkg/mod/", "/go/pkg/", "/vendor/", "/node_modules/")
_CODEGEN_SUFFIXES = (".pb.go", ".pb.gw.go", ".gen.go")

# ---------------------------------------------------------------------------
# arith-panic sink taxonomy. The captured Go method name maps to an arith_op class.
# The Safe* variants return an error instead of panicking -> NOT sinks (excluded by
# construction: "SafeMul" is not a key here).
# ---------------------------------------------------------------------------
_MUL_METHODS = {
    "Mul": "dec-mul", "MulTruncate": "dec-mul", "MulRoundUp": "dec-mul",
    "MulInt": "int-mul", "MulInt64": "int-mul", "MulRaw": "int-mul",
    "MulTruncateMut": "dec-mul", "MulMut": "dec-mul",
}
_QUO_METHODS = {
    "Quo": "dec-quo", "QuoTruncate": "dec-quo", "QuoRoundUp": "dec-quo",
    "QuoInt": "int-quo", "QuoInt64": "int-quo", "QuoRaw": "int-quo",
    "QuoMut": "dec-quo", "Rem": "int-rem", "ModInt64": "int-rem",
}
_POW_METHODS = {
    "Power": "dec-power", "ApproxRoot": "dec-root", "ApproxSqrt": "dec-root",
    "PowerMut": "dec-power",
}
# bare-call arith helpers (package-level fns that panic on overflow internally).
_CALL_ARITH = {
    "ExpDec": "expdec", "LnDec": "lndec",
}
_ARITH_METHODS = {}
_ARITH_METHODS.update(_MUL_METHODS)
_ARITH_METHODS.update(_QUO_METHODS)
_ARITH_METHODS.update(_POW_METHODS)
# arith_ops whose panicking magnitude operand is the DIVISOR (first arg) -> div-zero.
_DIVZERO_OPS = {"dec-quo", "int-quo", "int-rem"}

# only treat a file as Dec/Int-arithmetic-bearing if it imports cosmos math or uses
# LegacyDec / sdkmath - keeps the pass scoped and cuts false positives on plain ints.
_MATH_MARKERS = (
    "cosmossdk.io/math", "sdkmath", "LegacyDec", "math.Int", "math.LegacyDec",
    "cosmosmath",
)

# bound / zero-guard tokens that, when they dominate an operand, clear a node.
_BOUND_TOKENS = (
    "IsZero", "IsNil", "RequireBound", "LTE", "GTE", "LT(", "GT(",
    "<= 0", ">= 0", "< 0", "> 0", "== 0", "!= 0",
    "Max", "Min", "Clamp", "clamp", "Cap(", "Bound", "InRange", "Within",
)

_FUNC_RE = re.compile(r"^\s*func\s+(?:\(\s*\w+\s+[\*\w\.]+\s*\)\s+)?(\w+)\s*\(")
_RECV_TYPE_RE = re.compile(r"^\s*func\s+\(\s*\w+\s+\*?([\w\.]+)\s*\)")
_PKG_RE = re.compile(r"^\s*package\s+(\w+)")
_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
# a method / bare call: optional dotted-receiver chain, method name, open paren.
_CALL_RE = re.compile(r"(?:([A-Za-z_][\w\.\)\]]*?)\.)?([A-Za-z_]\w*)\s*\(")

_STATE_READ_HINTS = (".Get", "Keeper", "keeper", "Store", "store", "Walk",
                     "Iterate", ".Amount", "vault.", "params.", "Params",
                     "GetParam")


def _walk_go_files(src_root: Path, include_oos: bool):
    for p in sorted(src_root.rglob("*.go")):
        low = str(p).replace("\\", "/").lower()
        if any(m in low for m in _VENDOR_MARKERS):
            continue
        if low.endswith("_test.go"):
            continue
        if any(low.endswith(s) for s in _CODEGEN_SUFFIXES):
            continue
        try:
            rel = p.relative_to(src_root)
        except Exception:
            rel = p
        if not include_oos and is_oos(str(rel)):
            continue
        yield p


class Fn:
    __slots__ = ("name", "recv", "pkg", "file", "start", "end", "lines",
                 "params", "callees")

    def __init__(self, name, recv, pkg, file, start):
        self.name = name
        self.recv = recv
        self.pkg = pkg
        self.file = file
        self.start = start        # 1-indexed line of the `func` header
        self.end = start
        self.lines = []           # list of (lineno, text) for the body
        self.params = set()       # parameter identifiers
        self.callees = set()      # bare callee names referenced in the body


def _parse_params(header: str) -> set:
    """Extract parameter identifiers from a Go func header's (...) list.
    Best-effort: takes the first identifier of each comma group inside the OUTER
    parameter parens (the one right after the fn name)."""
    # isolate the parameter parens: from the '(' after the fn name to its match.
    m = re.search(r"func\s+(?:\([^)]*\)\s+)?\w+\s*\(", header)
    if not m:
        return set()
    i = header.index("(", m.end() - 1)
    depth = 0
    j = i
    for j in range(i, len(header)):
        c = header[j]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                break
    inner = header[i + 1:j]
    params = set()
    for grp in inner.split(","):
        toks = _IDENT_RE.findall(grp)
        # `name type` or shared-type group `a, b type`; the leading ident(s) are
        # param names. Conservatively take the first token of each group.
        if toks:
            params.add(toks[0])
    # also capture shared-type groups: `a, b int` splits to ["a"],["b int"].
    return params


def parse_file(path: Path, src_root: Path):
    """Return (list[Fn], raw_lines, pkg, is_math_file). Brace-count body spans."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return [], [], "", False
    lines = text.splitlines()
    pkg = ""
    is_math = any(mk in text for mk in _MATH_MARKERS)
    fns = []
    cur = None
    depth = 0
    for idx, raw in enumerate(lines, start=1):
        if not pkg:
            mp = _PKG_RE.match(raw)
            if mp:
                pkg = mp.group(1)
        if cur is None:
            mf = _FUNC_RE.match(raw)
            if mf:
                recv = ""
                mr = _RECV_TYPE_RE.match(raw)
                if mr:
                    recv = mr.group(1).split(".")[-1]
                cur = Fn(mf.group(1), recv, pkg, str(path), idx)
                cur.params = _parse_params(raw)
                depth = raw.count("{") - raw.count("}")
                cur.lines.append((idx, raw))
                if depth <= 0 and "{" in raw:
                    # single-line func
                    cur.end = idx
                    fns.append(cur)
                    cur = None
                continue
        else:
            cur.lines.append((idx, raw))
            depth += raw.count("{") - raw.count("}")
            if depth <= 0:
                cur.end = idx
                fns.append(cur)
                cur = None
    if cur is not None:
        cur.end = len(lines)
        fns.append(cur)
    return fns, lines, pkg, is_math


def _extract_callees(fn: Fn) -> set:
    callees = set()
    for _, raw in fn.lines:
        # strip trailing line comments cheaply
        code = raw.split("//", 1)[0]
        for m in _CALL_RE.finditer(code):
            name = m.group(2)
            if name in ("func", "if", "for", "switch", "return", "go", "defer"):
                continue
            callees.add(name)
    return callees


def _receiver_and_args(code: str, meth_start: int, meth_name: str):
    """Given code and the index where `meth_name(` begins, return (receiver_chain,
    [arg_substrings]). receiver_chain is the dotted expression immediately before
    `.meth_name`."""
    # receiver: walk left over the `.name` chain preceding the method name.
    left = code[:meth_start].rstrip()
    recv = ""
    if left.endswith("."):
        # collect the dotted chain: [\w\.\)\]]  including index/call tails
        j = len(left) - 1  # points at '.'
        k = j - 1
        while k >= 0 and (left[k].isalnum() or left[k] in "_.)]"):
            k -= 1
        recv = left[k + 1:j]
    # args: from the '(' after meth_name to its matching ')'
    op = code.find("(", meth_start)
    args = []
    if op != -1:
        depth = 0
        buf = []
        for c in code[op:]:
            if c == "(":
                depth += 1
                if depth == 1:
                    continue
            elif c == ")":
                depth -= 1
                if depth == 0:
                    break
            if depth == 1 and c == ",":
                args.append("".join(buf))
                buf = []
                continue
            buf.append(c)
        if buf and "".join(buf).strip():
            args.append("".join(buf))
    return recv, [a.strip().strip("()") for a in args if a.strip()]


def _base_ident(expr: str) -> str:
    m = _IDENT_RE.search(expr)
    return m.group(0) if m else ""


def compute_taint(fn: Fn):
    """Fixpoint taint over the fn body. tainted-set seeds = params; a local `x := E`
    (or `x, y := E`) becomes tainted if E references a tainted ident OR a state-read
    pattern. Returns (tainted_idents, state_idents)."""
    tainted = set(fn.params)
    state = set()
    changed = True
    passes = 0
    assign_re = re.compile(r"^\s*([A-Za-z_][\w,\s]*?)\s*:?=\s*(.+)$")
    # gather assignments once
    assigns = []
    for lineno, raw in fn.lines:
        code = raw.split("//", 1)[0]
        m = assign_re.match(code)
        if not m or "==" in code.split("=", 1)[0]:
            continue
        lhs = [t for t in _IDENT_RE.findall(m.group(1))]
        rhs = m.group(2)
        assigns.append((lhs, rhs))
    while changed and passes < 8:
        changed = False
        passes += 1
        for lhs, rhs in assigns:
            rhs_idents = set(_IDENT_RE.findall(rhs))
            is_state = any(h in rhs for h in _STATE_READ_HINTS)
            hits_tainted = bool(rhs_idents & tainted)
            if is_state or hits_tainted:
                for name in lhs:
                    if name and name != "err" and name not in ("_",):
                        if name not in tainted:
                            tainted.add(name)
                            changed = True
                        if is_state:
                            state.add(name)
    # also treat any dotted state-field expr operands as state-tainted implicitly
    return tainted, state


def _dominating_guard(fn: Fn, node_line: int, operand_idents: set):
    """Return (file:line, expr) of a bound/zero guard that DOMINATES the node: a line
    strictly before node_line, in the same fn, containing a bound token AND one of
    the operand identifiers as a whole word. None if no dominator."""
    if not operand_idents:
        return None
    idre = {ident: re.compile(r"\b" + re.escape(ident) + r"\b")
            for ident in operand_idents if len(ident) >= 1}
    for lineno, raw in fn.lines:
        if lineno >= node_line:
            break
        code = raw.split("//", 1)[0]
        if not any(bt in code for bt in _BOUND_TOKENS):
            continue
        for ident, rx in idre.items():
            if rx.search(code):
                return (f"{fn.file}:{lineno}", code.strip())
    return None


def _has_local_recover(fn: Fn, node_line: int) -> bool:
    """True if a `recover()` appears in the fn body (a deferred recover mitigates the
    halt but is recorded as an advisory downgrade, not a silent drop)."""
    for lineno, raw in fn.lines:
        if "recover()" in raw:
            return True
    return False


class ArithNode:
    __slots__ = ("fn", "file", "line", "arith_op", "meth", "recv", "args",
                 "tainted", "taint_source", "operand_idents", "dominator",
                 "local_recover", "reachable")

    def __init__(self, fn: Fn, line, arith_op, meth, recv, args):
        self.fn = fn
        self.file = fn.file
        self.line = line
        self.arith_op = arith_op
        self.meth = meth
        self.recv = recv
        self.args = args
        self.tainted = False
        self.taint_source = ""
        self.operand_idents = set()
        self.dominator = None
        self.local_recover = False
        self.reachable = False


def find_arith_nodes(fn: Fn, is_math_file: bool):
    """Locate arith-panic sink nodes in the fn body, slice their magnitude taint, and
    test bound-dominance. Requires the file to carry Dec/Int math markers."""
    if not is_math_file:
        return []
    tainted, state = compute_taint(fn)
    nodes = []
    for lineno, raw in fn.lines:
        if lineno == fn.start:
            # the func header itself (a `func ExpDec(` decl is not a call site).
            continue
        code = raw.split("//", 1)[0]
        for m in _CALL_RE.finditer(code):
            meth = m.group(2)
            arith_op = _ARITH_METHODS.get(meth)
            call_kind = None
            if arith_op is not None:
                call_kind = "method"
            elif meth in _CALL_ARITH and m.group(1) is None:
                arith_op = _CALL_ARITH[meth]
                call_kind = "call"
            if arith_op is None:
                continue
            recv, args = _receiver_and_args(code, m.start(2), meth)
            # operands whose magnitude matters:
            if arith_op in _DIVZERO_OPS:
                # divisor = first arg; also flag receiver magnitude for overflow.
                op_exprs = ([args[0]] if args else []) + ([recv] if recv else [])
            elif call_kind == "call":
                op_exprs = list(args)
            else:
                op_exprs = ([recv] if recv else []) + list(args)
            operand_idents = set()
            for e in op_exprs:
                for tok in _IDENT_RE.findall(e):
                    operand_idents.add(tok)
            node = ArithNode(fn, lineno, arith_op, meth, recv, args)
            node.operand_idents = operand_idents
            # taint: an operand ident is a param/state-derived local, OR a dotted
            # state-field expr (contains a state-read hint).
            src = ""
            for e in op_exprs:
                if any(h in e for h in _STATE_READ_HINTS):
                    src = "state"
                    break
            hit = operand_idents & tainted
            if hit or src:
                node.tainted = True
                if src:
                    node.taint_source = "state-read"
                elif hit & state:
                    node.taint_source = "state-read"
                elif hit & fn.params:
                    node.taint_source = "param"
                else:
                    node.taint_source = "derived-local"
            node.dominator = _dominating_guard(fn, lineno, operand_idents)
            node.local_recover = _has_local_recover(fn, lineno)
            nodes.append(node)
    return nodes


def forward_closure(root_names: set, callgraph: dict) -> set:
    seen = set(root_names)
    stack = list(root_names)
    while stack:
        cur = stack.pop()
        for nxt in callgraph.get(cur, ()):  # noqa: SIM118
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def load_dataflow_edges(ws: Path):
    """Auxiliary taint/call edges from any dataflow_paths*.jsonl (advisory enrichment;
    the analysis does not depend on them - the Go arm under-emits the ABCI closure)."""
    adir = ws / ".auditooor"
    edges = collections.defaultdict(set)
    n = 0
    if not adir.is_dir():
        return edges, n

    def _short(fn):
        s = fn or ""
        if ")." in s:
            s = s.rsplit(").", 1)[-1]
        s = s.split("(")[0].replace("*", "")
        return s.split(".")[-1]
    for p in sorted(adir.glob("dataflow_paths*.jsonl")):
        try:
            with p.open(encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    if str(rec.get("language") or "") != "go":
                        continue
                    src = rec.get("source") or {}
                    sink = rec.get("sink") or {}
                    chain = ([src.get("fn")]
                             + [h.get("fn") for h in (rec.get("hops") or [])]
                             + [sink.get("fn")])
                    chain = [_short(c) for c in chain if c]
                    for a, b in zip(chain, chain[1:]):
                        if a and b and a != b:
                            edges[a].add(b)
                            n += 1
        except Exception:
            continue
    return edges, n


def make_obligation(node: ArithNode, root_name: str, invariant_id: str) -> dict:
    short = node.fn.name
    contract = node.fn.recv or node.fn.pkg
    src_ref = f"{node.file}:{node.line}"
    op_desc = {
        "dec-mul": "a LegacyDec multiplication (Mul) that panics on >315-bit overflow",
        "int-mul": "an sdkmath.Int multiplication that panics on overflow",
        "dec-quo": "a LegacyDec division (Quo) that panics on a zero divisor",
        "int-quo": "an sdkmath.Int division that panics on a zero divisor",
        "int-rem": "an sdkmath.Int modulo that panics on a zero divisor",
        "dec-power": "a LegacyDec Power that panics on overflow",
        "dec-root": "a LegacyDec root that panics on overflow",
        "expdec": "an ExpDec Maclaurin series whose power.Mul term panics on overflow",
        "lndec": "an LnDec series that panics on overflow",
    }.get(node.arith_op, f"a panic-capable {node.arith_op} node")
    root = (
        f"MUST-SUCCEED consensus path '{root_name}' reaches {op_desc} in "
        f"'{node.fn.recv + '.' if node.fn.recv else ''}{short}' whose magnitude "
        f"operand is data-dependent on a "
        f"{'persisted-state' if node.taint_source == 'state-read' else 'msg/param'}"
        f" value"
        + (f" (operand '{node.recv or (node.args[0] if node.args else '')}')")
        + ". Because baseapp runs ABCI/module-lifecycle paths OUTSIDE the per-tx "
        "deferred recover, driving this magnitude to the overflow/zero-divisor value "
        "panics every validator deterministically on block re-execution -> chain "
        "halt (permanent fund freeze)."
    )
    fr = [
        "RECOVER_WRAP: prove the node is NOT run inside a deferred recover (an inner "
        "recover in this fn or an enclosing app.EndBlocker recover KILLS the halt "
        "claim - a same-fn `recover()` was "
        + ("DETECTED, so this is an advisory downgrade until the caller's error "
           "handling is confirmed to not itself panic/halt." if node.local_recover
           else "NOT detected in this fn.")
        + ")",
        "MAGNITUDE_REACH: confirm the operand is externally drivable to the "
        "overflow/zero value (a msg field or settable state with no dominating "
        "ValidateBasic / clamp / IsZero between ingress and the node).",
        "DETERMINISM+RESTART (R82): show every validator panics identically AND the "
        "chain cannot restart past the poisoned block without a migration - an "
        "executed restart-survival PoC is the terminal verdict.",
    ]
    advisory = node.taint_source in ("derived-local", "") or node.local_recover
    return {
        "schema": "auditooor.mustsucceed_arith_overflow.v1",
        "obligation_type": "mustsucceed-arith-overflow",
        "contract": contract,
        "function": short,
        "function_signature": f"{node.fn.recv + '.' if node.fn.recv else ''}{short}",
        "language": "go",
        "file": node.file,
        "line": node.line,
        "source_refs": [src_ref],
        "arith_op": node.arith_op,
        "arith_method": node.meth,
        "taint_source": node.taint_source or "unconfirmed",
        "operand": node.recv or (node.args[0] if node.args else ""),
        "mustsucceed_root_name": root_name,
        "local_recover_detected": node.local_recover,
        "attack_class": "mustsucceed-arith-overflow-consensus-halt",
        "likely_severity": "high",
        "broken_invariant_ids": [invariant_id],
        "root_cause_hypothesis": root,
        "quality_gate_status": "needs_source",
        "proof_status": "needs_source",
        "advisory_only": ("needs_source" if advisory else False),
        "learning_route": "mine-source",
        "falsification_requirements": fr,
        "next_command": (
            "read the fn body + the must-succeed caller closure; if the magnitude is "
            "genuinely externally drivable, unguarded and un-recovered, drive an "
            "executed restart-survival PoC (R82)."
        ),
    }


def run(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--src-root", default=None,
                    help="Go source root to scan (default <ws>/src, else <ws>)")
    ap.add_argument("--include-oos", action="store_true",
                    help="do NOT apply the scope OOS filter (debug)")
    ap.add_argument("--invariant-id",
                    default="INV-MUSTSUCCEED-PATH-NO-ARITH-OVERFLOW-HALT")
    ap.add_argument("--emit", default=None,
                    help="output jsonl path (default "
                         "<ws>/.auditooor/mustsucceed_arith_overflow_obligations.jsonl)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit non-zero if no arith-panic node substrate was found "
                         "at all (the reasoner ran over an empty universe)")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    if args.src_root:
        src_root = Path(args.src_root).expanduser().resolve()
    else:
        cand = ws / "src"
        src_root = cand if cand.is_dir() else ws

    # 1. parse all in-scope go files; build fn table + name-based call graph.
    fns: list[Fn] = []
    math_files: set = set()
    for p in _walk_go_files(src_root, args.include_oos):
        file_fns, _lines, _pkg, is_math = parse_file(p, src_root)
        if is_math:
            math_files.add(str(p))
        for fn in file_fns:
            fn.callees = _extract_callees(fn)
            fns.append(fn)

    callgraph: dict[str, set] = collections.defaultdict(set)
    for fn in fns:
        callgraph[fn.name] |= fn.callees
    # enrich with dataflow edges (advisory; does not gate the analysis).
    df_edges, n_df = load_dataflow_edges(ws)
    for a, bs in df_edges.items():
        callgraph[a] |= bs

    # 2. roots = fns whose name is a must-succeed family name.
    root_names = {fn.name for fn in fns if fn.name in _MUSTSUCCEED_NAMES}
    reach = forward_closure(set(root_names), callgraph)

    # 3. arith-panic nodes across every math-bearing in-scope fn.
    all_nodes: list[ArithNode] = []
    for fn in fns:
        is_math = fn.file in math_files
        for node in find_arith_nodes(fn, is_math):
            node.reachable = fn.name in reach
            all_nodes.append(node)

    tainted_nodes = [n for n in all_nodes if n.tainted]
    reachable_tainted = [n for n in tainted_nodes if n.reachable]
    survivors = [n for n in reachable_tainted if n.dominator is None]
    # KEPT = the non-vacuity witnesses: tainted arith nodes removed by the reachability
    # filter (not reachable from any root) OR by the dominance filter (bound-dominated).
    kept_unreachable = [n for n in tainted_nodes if not n.reachable]
    kept_dominated = [n for n in reachable_tainted if n.dominator is not None]

    # nearest root for citation: any root that reaches the node's fn (1 shown).
    def _nearest_root(node: ArithNode) -> str:
        if node.fn.name in root_names:
            return node.fn.name
        for r in sorted(root_names):
            if node.fn.name in forward_closure({r}, callgraph):
                return r
        return "(transitive must-succeed root)"

    obligations = []
    _seen = set()
    for node in sorted(survivors, key=lambda n: (n.file, n.line)):
        dk = (node.file, node.line, node.fn.name)
        if dk in _seen:
            continue
        _seen.add(dk)
        obligations.append(
            make_obligation(node, _nearest_root(node), args.invariant_id))

    emit = Path(args.emit).expanduser() if args.emit else \
        ws / ".auditooor" / "mustsucceed_arith_overflow_obligations.jsonl"
    emit.parent.mkdir(parents=True, exist_ok=True)
    with emit.open("w", encoding="utf-8") as fh:
        for ob in obligations:
            fh.write(json.dumps(ob) + "\n")

    substrate_vacuous = (len(all_nodes) == 0)
    cited_empty = (not substrate_vacuous and len(survivors) == 0)

    def _view(n: ArithNode):
        return {
            "fn": (n.fn.recv + "." if n.fn.recv else "") + n.fn.name,
            "arith_op": n.arith_op, "method": n.meth,
            "operand": n.recv or (n.args[0] if n.args else ""),
            "taint_source": n.taint_source,
            "file": n.file, "line": n.line,
            "local_recover": n.local_recover,
            "dominator": n.dominator[0] if n.dominator else None,
        }

    summary = {
        "schema": "auditooor.mustsucceed_arith_overflow_summary.v1",
        "workspace": str(ws),
        "src_root": str(src_root),
        "mustsucceed_family_source": _MUSTSUCCEED_SRC,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "n_go_fns": len(fns),
        "n_math_files": len(math_files),
        "n_dataflow_edges": n_df,
        "n_mustsucceed_roots": len(root_names),
        "mustsucceed_roots": sorted(root_names),
        "n_arith_panic_nodes": len(all_nodes),
        "n_tainted": len(tainted_nodes),
        "n_reachable_tainted": len(reachable_tainted),
        "n_survivors": len(survivors),
        "n_kept_unreachable": len(kept_unreachable),
        "n_kept_bound_dominated": len(kept_dominated),
        "arith_op_breakdown": dict(collections.Counter(
            n.arith_op for n in survivors)),
        "survivors": [_view(n) for n in survivors[:80]],
        "kept_unreachable_sample": [_view(n) for n in kept_unreachable[:25]],
        "kept_bound_dominated_sample": [
            dict(_view(n), dominator_line=n.dominator[0]) for n in kept_dominated[:25]],
        "obligations_written": len(obligations),
        "obligations_path": str(emit),
        "substrate_vacuous": substrate_vacuous,
        "cited_empty": cited_empty,
        "advisory_only": True,
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[mustsucceed-arith-overflow] {ws.name}: "
              f"|must-succeed roots|={summary['n_mustsucceed_roots']} "
              f"|arith-panic nodes|={summary['n_arith_panic_nodes']} "
              f"|tainted|={summary['n_tainted']} "
              f"reachable-tainted={summary['n_reachable_tainted']} "
              f"SURVIVORS={summary['n_survivors']} "
              f"KEPT(unreachable={summary['n_kept_unreachable']}, "
              f"dominated={summary['n_kept_bound_dominated']}) "
              f"-> {len(obligations)} obligation(s)")
        for s in summary["survivors"][:40]:
            rec = " [recover]" if s["local_recover"] else ""
            print(f"  SURVIVOR {s['fn']} [{s['arith_op']}/{s['method']}] "
                  f"operand={s['operand']} src={s['taint_source']}{rec}  "
                  f"{s['file']}:{s['line']}")
        for s in summary["kept_bound_dominated_sample"][:10]:
            print(f"  KEPT-guarded {s['fn']} [{s['arith_op']}] "
                  f"dominator={s['dominator_line']}  {s['file']}:{s['line']}")
        if substrate_vacuous:
            print("  SUBSTRATE-VACUOUS: no Dec/Int arith-panic node found "
                  "(the reasoner ran over an empty universe, NOT proven-clean).",
                  file=sys.stderr)
        elif cited_empty:
            print(f"  CITED-EMPTY: 0 survivors over {len(all_nodes)} arith nodes "
                  f"({len(kept_unreachable)} unreachable + "
                  f"{len(kept_dominated)} bound-dominated witnesses prove the "
                  f"filters ran non-vacuously).")
        print(f"  -> {emit}")

    if args.fail_closed and substrate_vacuous:
        return 3
    return summary


if __name__ == "__main__":
    out = run()
    if out == 3:
        sys.exit(3)
