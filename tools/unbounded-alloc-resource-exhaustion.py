#!/usr/bin/env python3
"""unbounded-alloc-resource-exhaustion.py - the unbounded-alloc / loop / recursion
resource-exhaustion DoS reasoning query (RANK-10 logic dimension, HIGH x10).

LOGIC CAPABILITY. This is an UNTRUSTED-SIZE-TAINT + BOUND-DOMINANCE relation over
alloc / loop / recursion nodes, NOT a grep for `make(` or `for`. Guard-rail:
`body_contains('make(') or body_contains('for')` is REJECTED - it cannot tell a
fixed-size / constant-bound alloc from one whose SIZE operand an attacker sets from a
message field / decoded length / unbounded queue, and cannot see the cap/bound check
(`n <= MAX`, `len <= K`, param-validate, gas/height bound) that DOMINATES the alloc on
every path (which makes the blowup impossible).

DISTINCTNESS FROM RANK-3 (permanent-freeze-dos)
  RANK-3 is an EXIT-PATH revert / stuck-loop on a value-release path -> funds frozen.
  THIS (RANK-10) is a MEMORY / CPU alloc blow-up on ANY attacker-reachable handler:
  `make([]T, n)` / `append`-in-loop / grow-map / self-recursion where the SIZE/COUNT/
  DEPTH operand is attacker-sized and NOT bound-dominated -> OOM / CPU blow-up / node
  crash. The impact is resource-exhaustion DoS (liveness), not a frozen exit.

THE INVARIANT (attacker input must not drive an unbounded allocation / loop / recursion)
  A size-driven allocation node N (a slice/map make of size s, an append inside a loop
  bounded by s, a range over an attacker-supplied collection, or a self-recursion whose
  depth is attacker data) must have its size/count/depth operand DOMINATED by a
  cap/bound check on every path from ingress to N. The trust boundary requires: for
  every alloc/loop/recursion node N, EITHER N's size operand traces only to
  trusted/constant sources, OR a bound check (`s <= MAX`, `len(x) <= K`, a
  param-validate, a gas/height/config bound) dominates N.

  Set relation computed (a SURVIVOR is an alloc/loop/recursion node N whose size
  operand is untrusted-tainted and NOT bound-dominated):
    SURVIVORS = UNTRUSTED_SIZE_ALLOC_NODES  \\  BOUND_DOMINATED
              = { N in ALLOC_LOOP_RECURSION_NODES :
                    (a) untrusted_size_taint(size_operand(N))   # msg/decode/queue
                    AND (b) NOT bound_dominated(N) }            # no cap on every path

WHY THIS IS LOGIC, NOT A SHAPE (guard-rail satisfied on two relational axes)
  (a) UNTRUSTED-SIZE TAINT is a backward-slice fact: N's size/count/depth operand is
      data-dependent on an UNTRUSTED source - a message/request field (a decoded proto
      field, an RPC arg, a caller-supplied length/count), a `binary.*`/`Decode`/
      `Unmarshal` decoded length, or an unbounded queue/collection walked without a cap.
      A constant literal size, or a size read from validated config / a bounded loop
      index, is NOT untrusted (goes to KEPT).
  (b) BOUND-DOMINANCE is a control-flow fact: N is cleared ONLY if a cap/bound check on
      the SAME operand (or its collection's len) executes on every path BEFORE N -
      `require(n <= MAX)` / `if len(x) > K { return err }` / a param-validate / a
      gas-meter or height/window bound. Adding such a dominating cap makes a survivor
      DISAPPEAR (the non-vacuous mutation), as does replacing the size with a constant.

SELF-CONTAINED SUBSTRATE (do-NOT #10: reuse, do not rebuild an engine)
  The owned tools/go-dataflow.py arm emits no unbounded-alloc sink kind and its Go
  call-edge set under-emits deep closures (MEMORY: "Go dataflow arm under-emits"). So
  this tool: (1) CONSUMES <ws>/.auditooor/dataflow_paths*.jsonl as advisory taint edges
  when present, AND (2) runs its OWN SSA-free source pass over the in-scope Solidity +
  Go tree to locate alloc/loop/recursion nodes, backward-slice each size operand to an
  untrusted source, and test cap/bound dominance in the enclosing function. The ideal
  go-dataflow / slither-arm extension is documented in
  agent_outputs/WIRING_SPEC_unbounded_alloc_resource_exhaustion.md.

OUTPUT
  <ws>/.auditooor/unbounded_alloc_resource_exhaustion_obligations.jsonl - one row per
  survivor, schema `auditooor.unbounded_alloc_resource_exhaustion.v1`. A --json summary
  reports |alloc/loop nodes|, |untrusted-size-tainted|, |bound-dominated|, |survivors|
  and the KEPT witness set (nodes removed by the taint / bound filters) to prove the
  filters ran non-vacuously. Honest cited-empty (survivors=0 with a non-empty KEPT
  witness) vs substrate_vacuous (no alloc/loop node found at all) are distinguished.
  Every survivor is advisory_only=needs_source: a CONFIRMED finding needs an EXECUTED
  resource-exhaustion PoC (the attacker-sized input drives OOM / CPU blow-up / crash) -
  that is a downstream hunt obligation, not asserted here. Nodes whose untrusted-size
  taint is unproven are emitted advisory needs_source in a separate bucket, never
  counted as strict survivors.
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

if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

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
                "/simulation/", "/script/", "/scripts/",
            ))

_VENDOR_MARKERS = ("/pkg/mod/", "/go/pkg/", "/vendor/", "/node_modules/",
                   "/lib/forge-std/", "/lib/openzeppelin", "/out/", "/cache/")
_CODEGEN_SUFFIXES = (".pb.go", ".pb.gw.go", ".pulsar.go", ".gen.go", ".t.sol")

# ---------------------------------------------------------------------------
# lexicons
# ---------------------------------------------------------------------------
# ALLOC nodes: a size-driven allocation. Go make([]T, n) / make(map, n) / make(chan,n),
# and Solidity `new T[](n)` dynamic-memory-array allocation.
_MAKE_RE_GO = re.compile(r"\bmake\s*\(\s*(?:\[\s*\]|map\[|chan\b)[^,)]*,\s*([^,)]+)")
_NEW_ARR_RE_SOL = re.compile(r"\bnew\s+[A-Za-z_][\w\.]*\s*\[\s*\]\s*\(\s*([^)]+)\)")

# LOOP nodes: a for/range/while. The bound operand is sliced below.
_LOOP_RE_SOL = re.compile(r"\b(for|while)\s*\(")
_LOOP_RE_GO = re.compile(r"\bfor\b")
# APPEND-in-loop grows an unbounded slice.
_APPEND_RE_GO = re.compile(r"=\s*append\s*\(\s*([A-Za-z_][\w\.]*)\s*,")
_PUSH_RE_SOL = re.compile(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*\.push\s*\(")

# loop bound referencing a collection length / a numeric operand.
_LEN_SOL_RE = re.compile(r"([A-Za-z_]\w*)\s*\.length\b")
_LEN_GO_RE = re.compile(
    r"(?:len\(\s*([A-Za-z_][\w\.]*)\s*\)|range\s+([A-Za-z_][\w\.\(\)]*))")
# an explicit for(i=0;i<N;...) numeric upper bound.
_FORBOUND_SOL_RE = re.compile(r"<\s*([A-Za-z_][\w\.]*)")

# WIRE-SOURCE markers: an external ingress a size operand can slice to - a message /
# request field, a decode/unmarshal, a calldata/payload. These are DISTINCTIVE
# structural tokens (contain '.'/'(' punctuation) so a plain substring test does not
# collide with a benign identifier; they are the only tokens that establish
# untrusted-msg / decoded-len taint.
_WIRE_DECODE_TOKENS = ("binary.", "unmarshal", "decode", "rlp.", "uvarint")
_WIRE_MSG_TOKENS = ("msg.", "req.", "request.", "params.", "input.", "payload",
                    "calldata")
# GENERIC size-nouns: a bare `count` / `length` / `size` operand is NOT untrusted on
# its own (a governance member-count, a validated-config length, an internal cardinality
# all use these words). It taints ONLY when a lightweight backward-slice reaches a
# wire source (handled by the decode/msg branches above), so at the token stage these
# are DROPPED, never counted. Anchored to whole-identifier word boundaries either way.
_GENERIC_SIZE_NOUNS = frozenset((
    "count", "length", "size", "len", "batch", "numitems", "num_items", "nitems",
    "n_items", "itemcount", "amount_of", "amountof", "getcount", "getlen",
))
# COLLECTION nouns: an attacker-supplied collection walked without a cap. Matched only
# as a WHOLE identifier (word boundary), so `getRoleMemberCount` (which merely CONTAINS
# `count`) and `app.mm.Modules` do NOT match a bare noun. These stay untrusted
# (unbounded-queue) because the identifier itself names an external-message collection.
_COLLECTION_NOUNS = frozenset((
    "recipients", "attributes", "signatures", "commands", "messages", "proofs",
))
# tokens that make a size operand TRUSTED (constant / validated config / bounded index).
_TRUSTED_SIZE_RE = re.compile(
    r"^\s*(?:\d+|0x[0-9a-fA-F]+|[A-Z_][A-Z0-9_]*|len\(\s*[A-Za-z_]\w*\.[A-Za-z_]\w*"
    r"\s*\))\s*$")
_CONST_LITERAL_RE = re.compile(r"^\s*(?:\d+|0x[0-9a-fA-F]+)\s*$")

# CAP / BOUND check tokens: a dominating guard on the size operand.
_BOUND_CMP_RE = re.compile(
    r"(?:<=|<|>=|>|==)\s*([A-Za-z_][\w\.]*|\d+)")
_BOUND_KEYWORDS = (
    "require(", "require (", "if ", "assert(", "maxlen", "max_len", "maxsize",
    "max_size", "maxcount", "max_count", "maxitems", "max_items", "gaslimit",
    "gas_limit", "consumegas", "gasmeter", "blocklimit", "limit", "cap(",
    "invalidlength", "toolong", "exceeds", "errorsmod", "errinvalid",
)
_BOUND_MAX_RE = re.compile(r"(?i)\b(max|limit|cap|bound|k_?max|maxlen|maxsize)\b")

_FUNC_RE_GO = re.compile(r"^\s*func\s+(?:\(\s*\w+\s+[\*\w\.]+\s*\)\s+)?(\w+)\s*\(")
_RECV_RE_GO = re.compile(r"^\s*func\s+\(\s*\w+\s+\*?([\w\.]+)\s*\)")
_PKG_RE_GO = re.compile(r"^\s*package\s+(\w+)")
_CONTRACT_RE_SOL = re.compile(r"^\s*(?:abstract\s+)?(?:contract|library)\s+(\w+)")
_FUNC_RE_SOL = re.compile(r"^\s*function\s+(\w+)\s*\(")
_CALL_RE = re.compile(r"(?:([A-Za-z_][\w\.\)\]]*?)\.)?([A-Za-z_]\w*)\s*\(")
_CTRL = {"if", "for", "while", "switch", "return", "go", "defer", "func",
         "require", "assert", "revert", "emit", "else", "catch", "make", "len",
         "range", "append", "new"}


def _walk_files(src_root: Path, include_oos: bool):
    for p in sorted(list(src_root.rglob("*.sol")) + list(src_root.rglob("*.go"))):
        low = str(p).replace("\\", "/").lower()
        if any(m in low for m in _VENDOR_MARKERS):
            continue
        if low.endswith("_test.go") or low.endswith(".t.sol"):
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
    __slots__ = ("name", "contract", "lang", "file", "start", "end", "lines",
                 "header", "visibility", "callees", "params")

    def __init__(self, name, contract, lang, file, start, header):
        self.name = name
        self.contract = contract      # sol contract or go recv/pkg
        self.lang = lang              # "sol" | "go"
        self.file = file
        self.start = start
        self.end = start
        self.lines = []               # (lineno, text)
        self.header = header
        self.visibility = ""
        self.callees = set()
        self.params = set()


def _sol_visibility(header: str) -> str:
    for v in ("external", "public", "internal", "private"):
        if re.search(r"\b" + v + r"\b", header):
            return v
    return "public"


def parse_file(path: Path):
    """Return list[Fn]. Brace-count body spans; works for Solidity and Go (both are
    C-brace languages)."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    lang = "go" if str(path).endswith(".go") else "sol"
    lines = text.splitlines()
    fns: list[Fn] = []
    pkg = ""
    contract = ""
    cur = None
    depth = 0
    pending_header = ""
    pending_name = ""
    pending_start = 0
    for idx, raw in enumerate(lines, start=1):
        if lang == "go" and not pkg:
            mp = _PKG_RE_GO.match(raw)
            if mp:
                pkg = mp.group(1)
        if lang == "sol":
            mc = _CONTRACT_RE_SOL.match(raw)
            if mc and cur is None:
                contract = mc.group(1)

        if cur is None and not pending_name:
            if lang == "go":
                mf = _FUNC_RE_GO.match(raw)
                if mf:
                    recv = ""
                    mr = _RECV_RE_GO.match(raw)
                    if mr:
                        recv = mr.group(1).split(".")[-1]
                    cur = Fn(mf.group(1), recv or pkg, "go", str(path), idx, raw)
                    depth = raw.count("{") - raw.count("}")
                    cur.lines.append((idx, raw))
                    if depth <= 0 and "{" in raw:
                        cur.end = idx
                        fns.append(cur)
                        cur = None
                    continue
            else:
                mf = _FUNC_RE_SOL.match(raw)
                if mf:
                    pending_header = raw
                    pending_name = mf.group(1)
                    pending_start = idx
                    if "{" in raw:
                        cur = Fn(pending_name, contract, "sol", str(path),
                                 pending_start, pending_header)
                        cur.visibility = _sol_visibility(pending_header)
                        depth = raw.count("{") - raw.count("}")
                        cur.lines.append((idx, raw))
                        pending_name = ""
                        pending_header = ""
                        if depth <= 0:
                            cur.end = idx
                            fns.append(cur)
                            cur = None
                    elif ";" in raw:
                        pending_name = ""
                        pending_header = ""
                    continue
        elif pending_name:
            pending_header += " " + raw
            if "{" in raw:
                cur = Fn(pending_name, contract, "sol", str(path),
                         pending_start, pending_header)
                cur.visibility = _sol_visibility(pending_header)
                depth = raw.count("{") - raw.count("}")
                cur.lines.append((idx, raw))
                pending_name = ""
                pending_header = ""
                if depth <= 0:
                    cur.end = idx
                    fns.append(cur)
                    cur = None
            elif ";" in raw:
                pending_name = ""
                pending_header = ""
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
    return fns


def _fn_params(fn: Fn) -> set:
    """Best-effort parameter-name extraction from the header (the ingress args are the
    most direct untrusted-size sources for a handler). For Go, the FIRST paren group is
    the RECEIVER (`func (k Keeper) F(...)`), NOT a param - it must be skipped or every
    receiver-field loop (`app.mm.Modules`, `gs.Vaults`) is mis-tainted as
    caller-supplied. Extract from the params paren that follows the function name."""
    params: set = set()
    hdr = fn.header or ""
    if fn.lang == "go":
        # drop a leading receiver `(recv T)` then take the params paren after the name.
        stripped = re.sub(r"^\s*func\s*\(\s*[^)]*\)\s*", "func ", hdr, count=1)
        m = re.search(r"\bfunc\s+\w+\s*\(([^)]*)\)", stripped) or \
            re.search(r"\w+\s*\(([^)]*)\)", stripped)
    else:
        m = re.search(r"\(([^)]*)\)", hdr)
    if not m:
        return params
    for piece in m.group(1).split(","):
        piece = piece.strip()
        if not piece:
            continue
        toks = re.findall(r"[A-Za-z_]\w*", piece)
        if toks:
            # last token is the name in Go (name Type) or Solidity (Type name).
            params.add(toks[-1])
            if fn.lang == "go" and len(toks) >= 2:
                params.add(toks[0])
    return params


def _extract_callees(fn: Fn) -> set:
    callees = set()
    for _, raw in fn.lines:
        code = raw.split("//", 1)[0]
        for m in _CALL_RE.finditer(code):
            name = m.group(2)
            if name in _CTRL:
                continue
            callees.add(name)
    return callees


def _is_entrypoint(fn: Fn) -> bool:
    if fn.lang == "sol":
        return fn.visibility in ("external", "public")
    return bool(fn.name) and fn.name[0].isupper()


class AllocNode:
    __slots__ = ("fn", "file", "line", "kind", "text", "size_operand", "taint",
                 "taint_reason", "bound", "bound_reason")

    def __init__(self, fn, line, kind, text, size_operand):
        self.fn = fn
        self.file = fn.file
        self.line = line
        self.kind = kind            # "make-alloc" | "new-array" | "loop" |
                                    # "append-in-loop" | "recursion"
        self.text = text
        self.size_operand = size_operand
        self.taint = "unproven"     # "untrusted-msg" | "decoded-len" |
                                    # "unbounded-queue" | "param" | "unproven"
        self.taint_reason = ""
        self.bound = False
        self.bound_reason = ""


def _operand_idents(operand: str) -> set:
    return set(re.findall(r"[A-Za-z_]\w*", operand or ""))


def _resolve_local(operand: str, fn: Fn, node_line: int) -> str:
    """Light local-variable backward slice: when the size operand is a single bare
    identifier, find its most recent assignment (`x := RHS` / `x = RHS`) before the
    node and return the RHS so the token match sees the real untrusted source (e.g.
    `n := binary.BigEndian.Uint32(data)`). Returns the operand unchanged otherwise."""
    op = (operand or "").strip()
    if not op or not re.fullmatch(r"[A-Za-z_]\w*", op):
        return operand
    assign_re = re.compile(r"\b" + re.escape(op) + r"\s*(?::=|=)\s*(.+)$")
    rhs = ""
    for lineno, raw in fn.lines:
        if lineno >= node_line:
            break
        code = raw.split("//", 1)[0]
        m = assign_re.search(code)
        if m:
            rhs = m.group(1).strip().rstrip(";").rstrip("{").strip()
    return rhs or operand


_GO_INGRESS_RECV_RE = re.compile(r"(?i)(msgserver|queryserver|querier|grpcquerier)")
_GO_MSG_PARAM_RE = re.compile(r"\*?[\w.]*(?:Msg[A-Z]\w*|\w*Request)\b")
# ABCI RUNTIME handlers process attacker-submitted transactions/votes. NOTE: InitGenesis
# is deliberately EXCLUDED - genesis state is trusted config set at chain launch /
# governance, NOT attacker-supplied runtime ingress, so a genesis-param loop is not a
# certain survivor (it falls to KEPT taint-unproven).
_GO_ABCI_FNS = frozenset((
    "BeginBlock", "EndBlock", "BeginBlocker", "EndBlocker", "DeliverTx", "CheckTx",
))


def _fn_is_ingress(fn: Fn) -> bool:
    """Is the enclosing fn an EXTERNAL attacker-supplied ingress? A caller-controlled
    param is only ATTACKER-controlled when the fn is reachable from an external message
    boundary - a public/external Solidity entry, or a Go gRPC msg-server / query-server /
    Tx / ABCI handler. An internal helper whose param a trusted caller sets is NOT
    untrusted, so its param-sized loop must NOT be counted a certain survivor."""
    if fn.lang == "sol":
        return fn.visibility in ("external", "public")
    hdr = fn.header or ""
    # cosmos msg-server / query-server receiver type (`func (s msgServer) F(...)`).
    if _GO_INGRESS_RECV_RE.search(fn.contract or ""):
        return True
    if _GO_INGRESS_RECV_RE.search(hdr.split(")", 1)[0] if ")" in hdr else hdr):
        return True
    # gRPC / Tx handler signature: a context.Context plus a proto Msg*/*Request param.
    if "context.Context" in hdr and _GO_MSG_PARAM_RE.search(hdr):
        return True
    # ABCI block / tx lifecycle handlers process externally-queued messages.
    if fn.name in _GO_ABCI_FNS:
        return True
    return False


def _classify_taint(operand: str, fn: Fn, node_line: int = 0) -> tuple:
    """Backward-slice a size/count/depth operand to an untrusted source. Returns
    (taint_class, reason) - taint_class is 'unproven' when only constant/trusted.

    Trust discipline (guard-rail: token present/absent must NOT be the whole story):
      - a wire source (decode/unmarshal/msg/req/calldata) = untrusted regardless of name;
      - a bare GENERIC size-noun (count/length/size) is DROPPED unless it slices to a
        wire source (a governance member-count / validated-config length is trusted);
      - a caller PARAM only taints when the enclosing fn is an external ingress;
      - a COLLECTION noun matches ONLY as a whole identifier (word boundary), so
        `getRoleMemberCount` (contains `count`) and `app.mm.Modules` do not collide.
    """
    if node_line:
        resolved = _resolve_local(operand, fn, node_line)
        if resolved != operand and resolved.strip():
            operand = resolved
    low = (operand or "").lower()
    if not low.strip():
        return "unproven", ""
    if _CONST_LITERAL_RE.match(operand or ""):
        return "unproven", "constant-literal"
    # decoded length: a binary/decode/unmarshal-derived size (wire source).
    if any(t in low for t in _WIRE_DECODE_TOKENS):
        return "decoded-len", f"decoded-length operand '{operand.strip()[:60]}'"
    # explicit message / request field (wire source).
    if any(t in low for t in _WIRE_MSG_TOKENS):
        return "untrusted-msg", f"message/request field '{operand.strip()[:60]}'"
    idents = _operand_idents(operand)
    idents_low = {i.lower() for i in idents}
    # a parameter name feeding the size = caller-supplied - untrusted ONLY when the
    # enclosing fn is an external attacker-reachable ingress (not an internal helper,
    # and NOT the receiver: `_fn_params` excludes the Go receiver).
    if (idents & fn.params) and _fn_is_ingress(fn):
        return "param", (f"caller-supplied param "
                         f"{sorted(idents & fn.params)[:3]} sizes the alloc in an "
                         f"external ingress")
    # a WHOLE-identifier match on an attacker-collection noun (word boundary, so a
    # generic noun that is merely a substring of a larger identifier does NOT match).
    if idents_low & _COLLECTION_NOUNS:
        hit = sorted(idents_low & _COLLECTION_NOUNS)[:2]
        return "unbounded-queue", (f"untrusted-collection identifier {hit} in size "
                                   f"operand '{operand.strip()[:60]}'")
    # a bare GENERIC size-noun with no wire source above = TRUSTED (taint unproven):
    # this is where a governance count / validated-config length falls out to KEPT.
    return "unproven", ""


def _find_alloc_nodes(fn: Fn) -> list:
    """Locate make/new-array/loop/append-in-loop/recursion nodes and record each one's
    size operand for the taint slice."""
    nodes: list[AllocNode] = []
    lang = fn.lang
    loop_re = _LOOP_RE_SOL if lang == "sol" else _LOOP_RE_GO
    len_re = _LEN_SOL_RE if lang == "sol" else _LEN_GO_RE
    self_name = fn.name
    for lineno, raw in fn.lines:
        if lineno == fn.start:
            # header line; still allow recursion detection below via body only.
            continue
        code = raw.split("//", 1)[0]
        # ---- make-alloc (Go) ----
        if lang == "go":
            for m in _MAKE_RE_GO.finditer(code):
                operand = m.group(1).strip()
                nodes.append(AllocNode(fn, lineno, "make-alloc",
                                       code.strip()[:200], operand))
        # ---- new-array (Solidity) ----
        if lang == "sol":
            for m in _NEW_ARR_RE_SOL.finditer(code):
                operand = m.group(1).strip()
                nodes.append(AllocNode(fn, lineno, "new-array",
                                       code.strip()[:200], operand))
        # ---- loop node ----
        if loop_re.search(code):
            operand = ""
            for m in len_re.finditer(code):
                operand = (m.group(1) or (m.lastindex and m.group(m.lastindex))
                           or "")
                if operand:
                    break
            if not operand and lang == "sol":
                mb = _FORBOUND_SOL_RE.search(code)
                if mb:
                    operand = mb.group(1)
            nodes.append(AllocNode(fn, lineno, "loop", code.strip()[:200],
                                   operand.strip()))
        # ---- append-in-loop grow (Go) ----
        if lang == "go":
            for m in _APPEND_RE_GO.finditer(code):
                base = m.group(1).split(".")[-1]
                nodes.append(AllocNode(fn, lineno, "append-in-loop",
                                       code.strip()[:200], base))
        # ---- self-recursion ----
        if self_name and re.search(r"\b" + re.escape(self_name) + r"\s*\(", code):
            # only count a call that is not the definition line.
            nodes.append(AllocNode(fn, lineno, "recursion",
                                   code.strip()[:200], self_name))
    return nodes


def _has_dominating_bound(fn: Fn, node: AllocNode) -> tuple:
    """Control-flow fact: does a cap/bound check on the SAME size operand (or its
    collection) execute BEFORE the node on every path? Heuristic: scan the fn body from
    ingress to node.line for a bound-keyword line that references one of the operand's
    identifiers together with a MAX/limit comparison, at shallow (function-level)
    scope."""
    idents = _operand_idents(node.size_operand)
    if not idents:
        return False, ""
    for lineno, raw in fn.lines:
        if lineno >= node.line:
            break
        low = raw.split("//", 1)[0].lower()
        if not any(k in low for k in _BOUND_KEYWORDS):
            continue
        # must mention one of the operand identifiers.
        if not any(re.search(r"\b" + re.escape(i.lower()) + r"\b", low)
                   for i in idents):
            continue
        # and must be a real cap: a comparison against a MAX/limit/const, a
        # gas/limit guard, or a length-exceeds error.
        has_cmp = bool(_BOUND_CMP_RE.search(low))
        has_max = bool(_BOUND_MAX_RE.search(low)) or bool(
            re.search(r"[<>]=?\s*\d", low))
        gas_guard = any(g in low for g in ("gaslimit", "gas_limit", "consumegas",
                                           "gasmeter", "blocklimit"))
        len_exceed = any(g in low for g in ("exceeds", "toolong", "invalidlength",
                                            "maxlen", "max_len", "maxsize",
                                            "maxcount", "max_count", "maxitems"))
        if (has_cmp and has_max) or gas_guard or len_exceed:
            return True, f"cap/bound at {fn.file}:{lineno} :: {raw.strip()[:90]}"
    return False, ""


def forward_closure(root: str, callgraph: dict) -> set:
    seen = {root}
    stack = [root]
    while stack:
        cur = stack.pop()
        for nxt in callgraph.get(cur, ()):  # noqa: SIM118
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def load_dataflow_edges(ws: Path):
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


def make_obligation(entry_fn: Fn, node: AllocNode, invariant_id: str) -> dict:
    contract = entry_fn.contract or Path(entry_fn.file).stem
    src_ref = f"{node.file}:{node.line}"
    kind_desc = {
        "make-alloc": "a make([]T/map/chan, n) allocation whose size n is attacker-set",
        "new-array": "a `new T[](n)` dynamic-array allocation whose size n is "
                     "attacker-set",
        "loop": "a for/range loop whose iteration count is an attacker-sized collection",
        "append-in-loop": "an append growing a slice inside an attacker-bounded loop",
        "recursion": "a self-recursion whose depth is driven by attacker data",
    }.get(node.kind, "an alloc/loop/recursion node")
    taint_desc = {
        "untrusted-msg": "the size traces to a message/request field an attacker "
                         "controls",
        "decoded-len": "the size is a decoded/unmarshalled length an attacker sets in "
                       "the wire payload",
        "unbounded-queue": "the size is the length of an attacker-growable "
                           "queue/collection walked with no cap",
        "param": "the size is a caller-supplied count/length parameter",
        "unproven": "an untrusted-size channel not yet proven from source",
    }.get(node.taint, node.taint)
    root = (
        f"Handler '{contract}.{entry_fn.name}' reaches {kind_desc} at {src_ref} "
        f"({taint_desc}). NO cap/bound check on the size operand dominates the node on "
        f"every path, so an attacker who supplies a large size/count/depth drives an "
        f"unbounded allocation / loop / recursion -> memory OOM, CPU blow-up, or node "
        f"crash = resource-exhaustion DoS."
    )
    fr = [
        "UNTRUSTED-SIZE: prove the size/count/depth operand is externally drivable to a "
        "large value from ingress (a message/decoded field / caller param / growable "
        "queue) with no clamp between ingress and the node.",
        "NO-BOUND: confirm no cap/bound check (`n <= MAX`, `len <= K`, param-validate, "
        "gas/height/window bound) dominates the node on every path.",
        "EXHAUSTION-POC: drive an EXECUTED PoC where the attacker-sized input causes "
        "OOM / CPU blow-up / crash (measured allocation or timeout), not a prose "
        "estimate - the executed exhaustion is the terminal verdict.",
    ]
    return {
        "schema": "auditooor.unbounded_alloc_resource_exhaustion.v1",
        "obligation_type": "unbounded-alloc-resource-exhaustion",
        "contract": contract,
        "function": entry_fn.name,
        "function_signature": f"{contract}.{entry_fn.name}",
        "language": entry_fn.lang,
        "file": node.file,
        "line": node.line,
        "source_refs": [src_ref, f"{entry_fn.file}:{entry_fn.start}"],
        "entry_fn": entry_fn.name,
        "entry_fn_line": entry_fn.start,
        "alloc_kind": node.kind,
        "node_text": node.text,
        "taint_class": node.taint,
        "taint_reason": node.taint_reason,
        "size_operand": node.size_operand,
        "bound_dominated": False,
        "attack_class": "unbounded-alloc-resource-exhaustion",
        "likely_severity": "high",
        "broken_invariant_ids": [invariant_id],
        "root_cause_hypothesis": root,
        "quality_gate_status": "needs_source",
        "proof_status": "needs_source",
        "advisory_only": "needs_source",
        "learning_route": "mine-source",
        "falsification_requirements": fr,
        "next_command": (
            "read the handler + the alloc/loop/recursion node; if the size operand is "
            "externally drivable and no cap dominates it, drive an EXECUTED "
            "resource-exhaustion PoC (OOM / CPU blow-up / crash)."
        ),
    }


def analyze(fns: list, ws: Path, invariant_id: str):
    for fn in fns:
        fn.callees = _extract_callees(fn)
        fn.params = _fn_params(fn)
    # Per-LANGUAGE call graphs (a Sol handler cannot reach a Go keeper node).
    callgraphs: dict[str, dict] = {"sol": collections.defaultdict(set),
                                   "go": collections.defaultdict(set)}
    for fn in fns:
        callgraphs[fn.lang][fn.name] |= fn.callees
    df_edges, n_df = load_dataflow_edges(ws)
    for a, bs in df_edges.items():
        for lang in callgraphs:
            callgraphs[lang][a] |= bs

    # alloc/loop/recursion nodes per fn (compute once).
    fn_nodes: dict[int, list] = {}
    for fn in fns:
        fn_nodes[id(fn)] = _find_alloc_nodes(fn)

    entry_fns = [fn for fn in fns if _is_entrypoint(fn)]

    survivors = []          # (entry_fn, node)
    kept_taint = []         # node reachable but untrusted-size taint unproven
    kept_bound = []         # node untrusted-tainted but a dominating cap exists
    all_nodes = []          # every alloc/loop/recursion node in some entry closure
    tainted_nodes = []      # untrusted-size-tainted subset

    seen_pair = set()
    for entry_fn in entry_fns:
        cg = callgraphs[entry_fn.lang]
        closure = forward_closure(entry_fn.name, cg)
        closure_fns = [fn for fn in fns
                       if fn.lang == entry_fn.lang and fn.name in closure]
        for cfn in closure_fns:
            for node in fn_nodes[id(cfn)]:
                key = (id(entry_fn), node.file, node.line, node.kind,
                       node.size_operand)
                if key in seen_pair:
                    continue
                seen_pair.add(key)
                all_nodes.append((entry_fn, node))
                # taint: slice the size operand IN THE NODE'S OWN fn (params/tokens).
                tcls, treason = _classify_taint(node.size_operand, cfn, node.line)
                node.taint = tcls
                node.taint_reason = treason
                if tcls == "unproven":
                    kept_taint.append((entry_fn, node))
                    continue
                tainted_nodes.append((entry_fn, node))
                # bound-dominance: a cap on the operand in the node's own fn.
                bounded, breason = _has_dominating_bound(cfn, node)
                if bounded:
                    node.bound = True
                    node.bound_reason = breason
                    kept_bound.append((entry_fn, node))
                    continue
                survivors.append((entry_fn, node))

    # dedup to DISTINCT physical nodes (a name-based closure attributes one physical
    # node to every entry fn whose closure reaches it - a cartesian blow-up).
    obligations = []
    survivor_nodes = []
    _seen = set()
    for entry_fn, node in sorted(survivors,
                                 key=lambda t: (t[1].file, t[1].line,
                                                t[1].kind, t[0].name)):
        dk = (node.file, node.line, node.kind, node.size_operand)
        if dk in _seen:
            continue
        _seen.add(dk)
        survivor_nodes.append((entry_fn, node))
        obligations.append(make_obligation(entry_fn, node, invariant_id))

    return {
        "callgraph_edges": sum(len(v) for g in callgraphs.values()
                               for v in g.values()),
        "n_dataflow_edges": n_df,
        "entry_fns": entry_fns,
        "survivors": survivor_nodes,
        "survivor_pairs": survivors,
        "kept_taint": kept_taint,
        "kept_bound": kept_bound,
        "all_nodes": all_nodes,
        "tainted_nodes": tainted_nodes,
        "obligations": obligations,
    }


def _view(entry_fn: Fn, node: AllocNode, extra=None):
    v = {
        "entry_fn": f"{entry_fn.contract}.{entry_fn.name}",
        "lang": entry_fn.lang,
        "alloc_kind": node.kind,
        "taint": node.taint,
        "size_operand": node.size_operand,
        "file": node.file,
        "line": node.line,
        "node": node.text[:120],
    }
    if extra:
        v.update(extra)
    return v


def run(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--src-root", default=None,
                    help="source root to scan (default <ws>/src, else <ws>)")
    ap.add_argument("--include-oos", action="store_true")
    ap.add_argument("--invariant-id",
                    default="INV-NO-UNBOUNDED-ALLOC-RESOURCE-EXHAUSTION")
    ap.add_argument("--emit", default=None,
                    help="output jsonl path (default <ws>/.auditooor/"
                         "unbounded_alloc_resource_exhaustion_obligations.jsonl)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit non-zero if no alloc/loop/recursion substrate was found "
                         "at all (the reasoner ran over an empty universe, NOT "
                         "proven-clean)")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    if args.src_root:
        src_root = Path(args.src_root).expanduser().resolve()
    else:
        cand = ws / "src"
        src_root = cand if cand.is_dir() else ws

    fns: list[Fn] = []
    for p in _walk_files(src_root, args.include_oos):
        fns.extend(parse_file(p))

    res = analyze(fns, ws, args.invariant_id)

    emit = Path(args.emit).expanduser() if args.emit else \
        ws / ".auditooor" / \
        "unbounded_alloc_resource_exhaustion_obligations.jsonl"
    emit.parent.mkdir(parents=True, exist_ok=True)
    with emit.open("w", encoding="utf-8") as fh:
        for ob in res["obligations"]:
            fh.write(json.dumps(ob) + "\n")

    substrate_vacuous = (len(res["all_nodes"]) == 0)
    cited_empty = (not substrate_vacuous and len(res["survivors"]) == 0)

    summary = {
        "schema": "auditooor.unbounded_alloc_resource_exhaustion_summary.v1",
        "workspace": str(ws),
        "src_root": str(src_root),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "n_fns": len(fns),
        "n_callgraph_edges": res["callgraph_edges"],
        "n_dataflow_edges": res["n_dataflow_edges"],
        "n_entry_fns": len(res["entry_fns"]),
        "n_alloc_loop_nodes": len(res["all_nodes"]),
        "n_untrusted_size_tainted": len(res["tainted_nodes"]),
        "n_bound_dominated": len(res["kept_bound"]),
        "n_survivor_pairs": len(res["survivor_pairs"]),
        "n_survivors": len(res["survivors"]),
        "n_kept_taint_unproven": len(res["kept_taint"]),
        "n_kept_bound_dominated": len(res["kept_bound"]),
        "taint_breakdown": dict(collections.Counter(
            n.taint for _, n in res["survivors"])),
        "kind_breakdown": dict(collections.Counter(
            n.kind for _, n in res["survivors"])),
        "survivors": [_view(e, n) for e, n in res["survivors"][:80]],
        "kept_taint_sample": [_view(e, n) for e, n in res["kept_taint"][:25]],
        "kept_bound_sample": [
            _view(e, n, {"bound_reason": n.bound_reason})
            for e, n in res["kept_bound"][:25]],
        "obligations_written": len(res["obligations"]),
        "obligations_path": str(emit),
        "substrate_vacuous": substrate_vacuous,
        "cited_empty": cited_empty,
        "advisory_only": True,
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[unbounded-alloc-resource-exhaustion] {ws.name}: "
              f"|alloc/loop nodes|={summary['n_alloc_loop_nodes']} "
              f"|untrusted-size-tainted|={summary['n_untrusted_size_tainted']} "
              f"|bound-dominated|={summary['n_bound_dominated']} "
              f"SURVIVORS={summary['n_survivors']} "
              f"KEPT(taint-unproven={summary['n_kept_taint_unproven']}, "
              f"bound-dominated={summary['n_kept_bound_dominated']}) "
              f"-> {len(res['obligations'])} obligation(s)")
        for s in summary["survivors"][:40]:
            print(f"  SURVIVOR {s['entry_fn']} [{s['alloc_kind']}/{s['taint']}] "
                  f"operand={s['size_operand']}  {s['file']}:{s['line']}")
        for s in summary["kept_bound_sample"][:8]:
            print(f"  KEPT-bounded {s['entry_fn']} [{s['alloc_kind']}] "
                  f"({s.get('bound_reason', '')[:70]})  {s['file']}:{s['line']}")
        if substrate_vacuous:
            print("  SUBSTRATE-VACUOUS: no alloc/loop/recursion node found (the "
                  "reasoner ran over an empty universe, NOT proven-clean).",
                  file=sys.stderr)
        elif cited_empty:
            print(f"  CITED-EMPTY: 0 survivors over {summary['n_alloc_loop_nodes']} "
                  f"alloc/loop nodes ({summary['n_kept_taint_unproven']} "
                  f"taint-unproven + {summary['n_kept_bound_dominated']} "
                  f"bound-dominated witnesses prove the filters ran non-vacuously).")
        print(f"  -> {emit}")

    if args.fail_closed and substrate_vacuous:
        return 3
    return summary


if __name__ == "__main__":
    out = run()
    if out == 3:
        sys.exit(3)
