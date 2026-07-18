#!/usr/bin/env python3
"""slice-oob-bounds-taint.py - RANK-8 [HIGH] untrusted length/offset -> OOB slice/pointer.

GENERAL TAINT + DOMINANCE class (NOT a grep for "["). An untrusted length or
offset (network / message / deserialized wire byte) that flows into a slice
expression, `copy`, `make([]T, n)`, `binary.BigEndian.Uint*` over a short
buffer, or `unsafe.Pointer` arithmetic WITHOUT a bounds check dominating the
node yields an out-of-bounds read/write, a panic (DoS), or memory corruption.

--- North-star method (backward-slice + dominance), applied ---
REASONING QUERY (two set operations, not a shape):
  SURVIVOR = a slice/index/copy/make/pointer-arith node N whose length / offset
  / index OPERAND the backward slicer traces to an UNTRUSTED source
  (decode / Unmarshal / msg field / wire read), MINUS the set of nodes whose
  operand is dominated by a bounds check (a `len(s)` / `cap` compare, an
  `if n > X { return }`, a `ValidateBasic` length guard) on every path.

      SURVIVORS = TAINTED_SLICE_NODES  MINUS  BOUNDS_DOMINATED

CORE PREDICATES (load-bearing, mutation-checkable - neutralise any one and the
planted survivor stops surviving):
  1. is_slice_node(line)        - is this a slice/index/copy/make/binary-read/
                                  pointer-arith site with a variable operand?
  2. taints_from_untrusted(var, body_before) - does the operand's value trace
                                  back (backward, within the fn) to an untrusted
                                  source (Unmarshal / Decode / binary read /
                                  []byte param / msg field), and NOT to a
                                  compile-time constant?
  3. bounds_check_dominates(var, slice_var, body_before) - is there, textually
                                  before the node, a length/offset guard on the
                                  operand or on the sliced buffer that returns /
                                  panics / breaks on the out-of-range branch?

--- DISCIPLINE (fail-open, advisory-first) ---
Every survivor row is ADVISORY: verdict='needs-source' when taint OR dominance
is UNCERTAIN (the backward slice is textual, not a real SSA def-use chain), else
verdict='needs-fuzz'. auto_credit=False always. A guarded / constant-length node
is SILENT. Any parse degradation yields FEWER rows, never a false survivor -
it never flips a verdict or credits a finding. --fail-closed only changes the
process exit code (for a gate), never the row verdicts.

STATUS SEMANTICS (honest emptiness):
  * ok                 - >=1 survivor emitted.
  * cited-empty        - files scanned AND >=1 tainted slice node found, but
                         every one was bounds-dominated -> honest zero (cited).
  * substrate_vacuous  - no Go source, or zero slice nodes at all -> the tool
                         had nothing to reason over (NOT an honest zero).

Emits (when --emit): <ws>/.auditooor/slice_oob_bounds_taint.jsonl (one row per
survivor) + slice_oob_bounds_taint.accounting.json (counts + status).
Schema: auditooor.slice_oob_bounds_taint.v1
"""
from __future__ import annotations

import argparse
import signal
import sys
import time


class _FileScanTimeout(Exception):
    """Raised by the per-file SIGALRM to abandon a single pathological file (a huge
    file or regex catastrophic-backtrack) without hanging the whole scan."""


def _file_scan_alarm(signum, frame):
    raise _FileScanTimeout()
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCHEMA = "auditooor.slice_oob_bounds_taint.v1"
DETECTOR = "memsafety.slice_oob.untrusted_length_offset"

_SKIP_DIR = {"vendor", "node_modules", "testdata", ".git", "third_party", "mocks", "mock"}
_SKIP_SUFFIX = (
    "_test.go", ".pb.go", ".pb.gw.go", "_string.go", "_gen.go", ".gen.go",
    ".pulsar.go", "_mock.go",
)

# --------------------------------------------------------------------------
# UNTRUSTED-SOURCE lexicon. A value whose provenance touches one of these is
# attacker-influenced (wire / decode / message). Backward slice bottoms out
# here. Kept as a named constant so a test can neutralise it.
# --------------------------------------------------------------------------
UNTRUSTED_TOKENS: Tuple[str, ...] = (
    "Unmarshal", "Decode", "Deserialize", "ReadBytes", "ReadString",
    "ReadFull", "io.ReadFull", "binary.Read", "proto.Unmarshal",
    "json.Unmarshal", ".GetData(", ".GetPayload(", ".Payload", ".RawBytes",
    "msg.", "req.", "request.", "packet.", "FromBytes", "ParseFrom",
    "abi.Decode", "rlp.Decode", "wire.", ".Bytes()",
)

# Function-parameter provenance. We split slice params into two classes:
#   * BYTE-SHAPED ([]byte, []uint8, named Bytes/RawMessage aliases) - genuine
#     wire input; a length/offset derived from it is CERTAIN untrusted taint.
#   * BARE []T ([]Order, []string, []*Foo) - a trusted typed collection. It is
#     NOT wire bytes. Indexing it with a variable is at most a needs-source
#     advisory (certain=False), never a needs-fuzz survivor, absent a real
#     decode/msg/wire anchor. (Old _PARAM_BYTES_RE matched EVERY []T param and
#     mis-credited []struct/[]string as a certain []byte wire source - FP.)
_PARAM_SLICE_RE = re.compile(r"\b([A-Za-z_]\w*)\s+(\[\])+([\w\.\*]+)")


def _classify_params(header_line: str) -> Tuple[set, set]:
    """Split a func header's slice params into (byte_shaped, bare_slice) name sets.

    Byte-shaped := element type is `byte`/`uint8`, or a named alias whose (last
    path segment, lowercased) ends in `bytes` or `rawmessage` (e.g. HexBytes,
    cmtbytes.HexBytes, json.RawMessage). Everything else ([]Order, []string,
    []*Tx) is a bare typed slice - trusted collection, not wire bytes.
    """
    byte_shaped: set = set()
    bare_slice: set = set()
    for m in _PARAM_SLICE_RE.finditer(header_line):
        name, elem = m.group(1), m.group(3)
        base = elem.replace("*", "")
        short = base.split(".")[-1].lower()
        if short in ("byte", "uint8") or short.endswith("bytes") or short.endswith("rawmessage"):
            byte_shaped.add(name)
        else:
            bare_slice.add(name)
    return byte_shaped, bare_slice

# --------------------------------------------------------------------------
# SLICE-NODE recognisers. Each returns (var_being_indexed_or_copied,
# operand_expr) or None. Operand_expr is the length/offset/index text whose
# taint we then chase.
# --------------------------------------------------------------------------
_RE_SLICE2 = re.compile(r"\b([A-Za-z_]\w*)\s*\[\s*([^\]:]*?)\s*:\s*([^\]]*?)\s*\]")   # s[a:b]
_RE_INDEX = re.compile(r"\b([A-Za-z_]\w*)\s*\[\s*([A-Za-z_]\w[\w\.\+\-\*]*)\s*\]")     # s[i]
_RE_COPY = re.compile(r"\bcopy\s*\(\s*([^,]+?)\s*,\s*([^)]+?)\s*\)")                   # copy(dst,src)
_RE_MAKE = re.compile(r"\bmake\s*\(\s*\[\][\w\.\*\[\]]+\s*,\s*([^,)]+?)\s*[,)]")       # make([]T, n)
_RE_BINREAD = re.compile(r"\bbinary\.(?:Big|Little)Endian\.Uint(?:16|32|64)\s*\(\s*([A-Za-z_]\w*)\s*\[\s*([^\]]*?)\s*\]")
_RE_PTRARITH = re.compile(r"\bunsafe\.Pointer\s*\(\s*uintptr\([^)]*\)\s*\+\s*([^)]+)\)")

# Bounds-guard recognisers (a comparison against a length/offset/index).
_RE_LEN_CMP = re.compile(r"\blen\s*\(\s*([A-Za-z_]\w*)\s*\)\s*(<=?|>=?|==|!=)")
_RE_CAP_CMP = re.compile(r"\bcap\s*\(\s*([A-Za-z_]\w*)\s*\)")
_RE_VALIDATE = re.compile(r"\b(?:ValidateBasic|Validate|checkLength|assertLen)\b")

_CONST_RE = re.compile(r"^\s*(?:[0-9]+|0x[0-9a-fA-F]+|[A-Za-z_]\w*Size|[A-Za-z_]\w*Len|[A-Za-z_]\w*LENGTH)\s*$")

_FUNC_RE = re.compile(r"\bfunc\b[^\n{]*\{")


# =========================================================================
# CORE PREDICATE 1
# =========================================================================
def is_slice_node(line: str) -> List[Tuple[str, str, str, str]]:
    """Return list of (kind, sliced_var, operand_expr, evidence) on this line.

    A slice/index/copy/make/binary-read/pointer-arith site with a VARIABLE
    operand. A pure-constant operand (`s[:4]`, `make([]byte, 32)`) is NOT a
    node - constants cannot be attacker-controlled. Empty list => not a node.
    """
    out: List[Tuple[str, str, str, str]] = []
    for m in _RE_SLICE2.finditer(line):
        var, lo, hi = m.group(1), m.group(2).strip(), m.group(3).strip()
        for op in (lo, hi):
            if op and not _is_constant(op):
                out.append(("slice-range", var, op, m.group(0)))
    for m in _RE_INDEX.finditer(line):
        var, op = m.group(1), m.group(2).strip()
        # skip when this index is actually the low/high of a range already caught
        if ":" in line[m.start():m.end() + 1]:
            continue
        # Go MAP false-positive class (2026-07-14 axelar): a Go map access never OOBs
        # (missing key -> zero value / comma-ok), and `map[K]V` is a TYPE literal, not
        # an index. Suppress: (a) the `map` keyword as the indexed var (a map[K]V type
        # literal / type assertion, e.g. `map[string]string` / `.(map[string]any)`);
        # (b) a comma-ok map access tied to THIS var (`v, ok := <var>[k]`) - only slice/
        # array indexing can OOB, and slices/arrays have no comma-ok form.
        if var.strip() == "map":
            continue
        if re.search(r",\s*ok\s*:?=\s*[\w.]*" + re.escape(var.split(".")[-1]) + r"\s*\[", line):
            continue
        if op and not _is_constant(op):
            out.append(("index", var, op, m.group(0)))
    for m in _RE_COPY.finditer(line):
        dst, src = m.group(1).strip(), m.group(2).strip()
        # Go's builtin copy is memory-safe: it copies min(len(dst),len(src)) and can
        # never OOB/panic. The ONLY OOB risk on a copy line is a slice EXPRESSION with
        # a VARIABLE bound inside src/dst (e.g. src[off:end]) - and that slice is
        # already caught independently by _RE_SLICE. So only surface the copy when a
        # src/dst slice carries a non-trivial (variable) bound; a bare full-slice
        # `x[:]` or a constant-bound slice is provably in-bounds (2026-07-14: this was
        # the dominant slice-oob false-positive class on axelar - a[:]/h[:]/c[:]).
        node_op = src
        if _has_variable_slice_bound(src) or _has_variable_slice_bound(dst):
            out.append(("copy", dst.split("[")[0].strip(), node_op, m.group(0)))
    for m in _RE_MAKE.finditer(line):
        op = m.group(1).strip()
        if op and not _is_constant(op) and not _is_len_bounded(op):
            out.append(("make", "", op, m.group(0)))
    for m in _RE_BINREAD.finditer(line):
        var, op = m.group(1), m.group(2).strip()
        out.append(("binary-read", var, op if op else var, m.group(0)))
    for m in _RE_PTRARITH.finditer(line):
        op = m.group(1).strip()
        if op and not _is_constant(op):
            out.append(("pointer-arith", "", op, m.group(0)))
    return out


def _is_constant(expr: str) -> bool:
    """True iff the operand is a compile-time constant / const-name (untaintable)."""
    e = expr.strip()
    if e == "":
        return True
    return bool(_CONST_RE.match(e))


_SLICE_BOUND_RE = re.compile(r"\[([^\]]*)\]")


# tolerant of a truncated operand (the make regex captures `len(addrs` without the
# closing paren) - the close paren is optional.
_LEN_CALL_RE = re.compile(r"\b(?:len|cap)\s*\(\s*[\w.\[\]:+\-*/ ]*\)?")


def _is_len_bounded(expr: str) -> bool:
    """True iff a make() size is derived only from len()/cap() of existing values plus
    constants (len(addrs), len(a)+len(b), len(x)+32). Such a make is bounded by an
    existing allocation and cannot OOB/OOM on attacker input, so it is not a slice-oob
    survivor. A raw attacker int (make([]byte, msg.Size)) carries no len()/cap() and is
    NOT suppressed (2026-07-14 axelar make(len(...)) false-positive class)."""
    if "len(" not in expr and "cap(" not in expr:
        return False
    stripped = _LEN_CALL_RE.sub("", expr)
    stripped = re.sub(r"[0-9\s+\-*/()]", "", stripped)
    return stripped == ""


def _has_variable_slice_bound(expr: str) -> bool:
    """True iff `expr` contains a slice/index `[...]` whose bound is a VARIABLE (not a
    bare full-slice `[:]` and not a compile-time constant). `x[:]` and `x[3]`/`x[:32]`
    are provably in-bounds-or-const; `x[off:end]` / `x[i]` (variable) is the real OOB
    risk. Used to suppress the copy() false-positive class (Go copy is length-safe)."""
    for inner in _SLICE_BOUND_RE.findall(expr):
        parts = inner.split(":") if ":" in inner else [inner]
        for p in parts:
            p = p.strip()
            if p and not _is_constant(p):
                return True
    return False


def _operand_vars(expr: str) -> List[str]:
    """Extract identifier tokens from an operand expression (i, off+n, len(x))."""
    return [t for t in re.findall(r"[A-Za-z_]\w*", expr)
            if t not in ("len", "cap", "int", "uint", "int64", "uint64",
                         "uint32", "int32", "uintptr", "byte")]


# =========================================================================
# CORE PREDICATE 2
# =========================================================================
def taints_from_untrusted(operand: str, sliced_var: str, body_before: str,
                          param_bytes: set,
                          param_slices: Optional[set] = None) -> Tuple[bool, bool, str]:
    """Backward-slice the operand to decide untrusted provenance.

    Returns (tainted, certain, reason). `certain` is False when the chain is
    ambiguous (we saw a candidate but could not confirm a direct assignment) ->
    the row becomes verdict='needs-source'. A constant operand is untainted.
    """
    if _is_constant(operand):
        return (False, True, "constant-operand")

    param_slices = param_slices or set()
    vars_ = set(_operand_vars(operand))
    # The sliced buffer being a []byte param is itself provenance when the
    # operand is an offset/index into it.
    candidates = set(vars_)
    if sliced_var:
        candidates.add(sliced_var)

    # Direct: any candidate var is a BYTE-SHAPED wire parameter -> CERTAIN taint.
    for v in candidates:
        if v in param_bytes:
            return (True, True, f"operand/buffer '{v}' is a []byte wire parameter")

    # Backward: a candidate var is assigned from an untrusted token upstream.
    for v in vars_:
        assign = re.search(rf"\b{re.escape(v)}\s*(?::=|=)\s*(.+)", body_before)
        if assign:
            rhs = assign.group(1)
            for tok in UNTRUSTED_TOKENS:
                if tok in rhs:
                    return (True, True, f"'{v}' derives from untrusted `{tok}`")
    # Ambiguous: operand var appears on the SAME line as an untrusted token but
    # with no clean def-use edge -> tainted-but-uncertain. Line-scoped (cheap,
    # no `.*` backtracking) to keep the pass linear on large substrates.
    vword = {v: re.compile(rf"\b{re.escape(v)}\b") for v in vars_}
    for bl in body_before.splitlines():
        if not any(tok in bl for tok in UNTRUSTED_TOKENS):
            continue
        for v in vars_:
            if vword[v].search(bl):
                tok = next(t for t in UNTRUSTED_TOKENS if t in bl)
                return (True, False, f"'{v}' co-occurs with untrusted `{tok}` (uncertain chain)")

    # Weak provenance: the operand/buffer is a BARE []T param ([]Order, []string,
    # []*Tx) with no byte shape and no decode/wire anchor. A trusted typed slice
    # is NOT wire bytes, so this is at most a needs-source advisory (certain=False)
    # - never a certain/needs-fuzz survivor. (This is the FP that _PARAM_BYTES_RE
    # used to mis-credit as a []byte wire parameter.)
    for v in candidates:
        if v in param_slices:
            return (True, False,
                    f"operand/buffer '{v}' is a bare []T param (needs-source; "
                    f"no byte-shape or wire/decode anchor)")
    return (False, True, "no-untrusted-provenance")


# =========================================================================
# CORE PREDICATE 3
# =========================================================================
def bounds_check_dominates(operand: str, sliced_var: str, body_before: str) -> bool:
    """True iff a length/offset bounds guard textually dominates the node.

    Textual (line-order) dominance approximation: a `len(buf) </>/== ...`, a
    `cap(buf)`, an `if n > X { return }`, or a `ValidateBasic` guard on the
    operand var or the sliced buffer, appearing before the node. Approximate
    (not a real CFG) - so a match SILENCES conservatively, a miss keeps the row
    ADVISORY rather than asserting exploitability.
    """
    guard_vars = set(v for _, v in _RE_LEN_CMP.findall(body_before)) if False else set()
    for m in _RE_LEN_CMP.finditer(body_before):
        guard_vars.add(m.group(1))
    for m in _RE_CAP_CMP.finditer(body_before):
        guard_vars.add(m.group(1))
    if _RE_VALIDATE.search(body_before):
        return True

    checked = set()
    if sliced_var:
        checked.add(sliced_var)
    checked.update(_operand_vars(operand))

    # A guard on the sliced buffer's length dominates an index/range into it.
    if sliced_var and sliced_var in guard_vars:
        return True
    # A guard directly comparing the operand var (`if n > X { return }`).
    for v in _operand_vars(operand):
        if re.search(rf"\bif\b[^\n{{]*\b{re.escape(v)}\b[^\n{{]*(<=?|>=?|==|!=)"
                     rf"[^\n{{]*\{{[^}}]*\b(return|break|continue|panic)\b", body_before):
            return True
        if v in guard_vars:
            return True
    return False


# =========================================================================
# Function-body slicing over one file
# =========================================================================
def scan_go_source(text: str, path: str) -> Tuple[List[Dict[str, Any]], int, int]:
    """Return (survivor_rows, n_slice_nodes, n_tainted_nodes) for one file."""
    lines = text.splitlines()
    rows: List[Dict[str, Any]] = []
    n_nodes = 0
    n_tainted = 0

    # Determine, per line, the enclosing function's []byte params (cheap: scan
    # the nearest preceding `func ... {` header).
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        nodes = is_slice_node(line)
        if not nodes:
            continue

        # Nearest preceding func header for param context + body_before.
        header_start = _nearest_func_start(lines, idx)
        header_line = lines[header_start] if header_start is not None else ""
        param_bytes, param_slices = _classify_params(header_line)
        body_before = "\n".join(lines[(header_start or 0): idx + 1])

        for kind, svar, operand, evidence in nodes:
            n_nodes += 1
            tainted, certain, reason = taints_from_untrusted(
                operand, svar, body_before, param_bytes, param_slices)
            if not tainted:
                continue
            n_tainted += 1
            if bounds_check_dominates(operand, svar, body_before):
                continue  # bounds-dominated -> SILENT (honest cited-empty feeds this)
            verdict = "needs-fuzz" if certain else "needs-source"
            rows.append(_row(kind, path, idx + 1, svar, operand, evidence,
                             reason, verdict, certain))
    return rows, n_nodes, n_tainted


def _nearest_func_start(lines: List[str], idx: int) -> Optional[int]:
    for j in range(idx, -1, -1):
        if _FUNC_RE.search(lines[j]) or lines[j].lstrip().startswith("func "):
            return j
    return None


def _row(kind, path, line, svar, operand, evidence, reason, verdict, certain) -> Dict[str, Any]:
    inv = (f"the {kind} operand `{operand}` into `{svar or 'buffer'}` must be "
           f"bounds-checked against the backing length before use; an untrusted "
           f"length/offset must not index past the buffer")
    hq = (f"Can an attacker supply a wire length/offset that makes `{operand}` "
          f"exceed len({svar or 'buf'}) at this {kind}, forcing an out-of-bounds "
          f"read/write or a panic (DoS)?")
    return {
        "schema": SCHEMA,
        "detector": DETECTOR,
        "kind": kind,
        "file": path,
        "line": line,
        "sliced_var": svar,
        "operand": operand,
        "evidence": evidence.strip(),
        "taint_reason": reason,
        "invariant": inv,
        "hacker_question": hq,
        "verdict": verdict,
        "taint_certain": certain,
        "advisory": True,
        "auto_credit": False,
    }


def _iter_go_files(root: Path) -> List[Path]:
    out: List[Path] = []
    if root.is_file():
        return [root] if root.suffix == ".go" else []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIR]
        # client-side CLI tx/query builders (`.../client/cli/`) are not consensus /
        # attacker-tx reachable - an OOB there crashes the user's CLI, not a validator;
        # excluded from the on-chain slice-oob surface (mirrors value-moving's
        # _go_is_client_cli). 2026-07-14.
        if "/client/cli/" in (dirpath.replace("\\", "/") + "/"):
            continue
        for fn in filenames:
            if not fn.endswith(".go"):
                continue
            if any(fn.endswith(sfx) for sfx in _SKIP_SUFFIX):
                continue
            out.append(Path(dirpath) / fn)
    return out


# =========================================================================
# Driver
# =========================================================================
def run(ws: Path, src_root: Optional[Path], emit: bool,
        max_rows: int = 5000, time_budget_s: float = 120.0,
        max_file_lines: int = 6000, per_file_timeout_s: float = 10.0) -> Dict[str, Any]:
    # ws/src is preferred when present (mirrors the goroutine reasoner + VMF): the
    # in-scope source lives under src/, not the whole workspace tree.
    if src_root:
        root = src_root
    else:
        _src = ws / "src"
        root = _src if _src.exists() else ws
    files = _iter_go_files(Path(root))
    all_rows: List[Dict[str, Any]] = []
    scanned = 0
    total_nodes = 0
    total_tainted = 0
    # BOUNDED SCAN (2026-07-14): scan_go_source is O(nodes^2)-ish; on a large
    # Cosmos monorepo (axelar-core ~2000 .go) the unbounded loop ran >250s and the
    # step-2d-slice-oob step never completed. A per-file line cap skips pathological
    # oversized files and a total wall-clock budget stops the loop, both LOGGED
    # (scan_capped / oversized_skipped) so a capped run is never silently mistaken
    # for a clean 0-survivor scan (no-silent-truncation rule).
    oversized_skipped = 0
    per_file_timed_out = 0
    scan_capped = False
    _have_alarm = hasattr(signal, "SIGALRM") and per_file_timeout_s > 0
    if _have_alarm:
        signal.signal(signal.SIGALRM, _file_scan_alarm)
    _t0 = time.monotonic()
    for f in files:
        if time.monotonic() - _t0 > time_budget_s:
            scan_capped = True
            break
        try:
            text = f.read_text(errors="replace")
        except Exception:
            continue  # fail-open: a bad read never manufactures a survivor
        if max_file_lines and text.count("\n") > max_file_lines:
            oversized_skipped += 1
            continue  # skip a pathological oversized file (logged); rare + usually generated
        scanned += 1
        # per-file SIGALRM: abandon a single file whose scan_go_source hangs (regex
        # catastrophic backtrack / O(n^2) blowup) so it can never stall the whole scan.
        if _have_alarm:
            signal.setitimer(signal.ITIMER_REAL, per_file_timeout_s)
        try:
            rows, n_nodes, n_tainted = scan_go_source(text, str(f))
        except _FileScanTimeout:
            per_file_timed_out += 1
            continue  # logged; a hung file is skipped, not silently counted clean
        except Exception:
            continue  # fail-open on a parse hiccup
        finally:
            if _have_alarm:
                signal.setitimer(signal.ITIMER_REAL, 0)
        total_nodes += n_nodes
        total_tainted += n_tainted
        all_rows.extend(rows)
        if len(all_rows) >= max_rows:
            all_rows = all_rows[:max_rows]
            break

    n_dominated = total_tainted - len(all_rows)
    if scanned == 0 or total_nodes == 0:
        status = "substrate_vacuous"
    elif len(all_rows) == 0:
        status = "cited-empty"
    else:
        status = "ok"

    acct: Dict[str, Any] = {
        "schema": SCHEMA,
        "detector": DETECTOR,
        "status": status,
        "files_scanned": scanned,
        "files_total": len(files),
        "scan_capped": scan_capped,
        "oversized_skipped": oversized_skipped,
        "per_file_timed_out": per_file_timed_out,
        "slice_nodes": total_nodes,
        "untrusted_tainted": total_tainted,
        "bounds_dominated": max(0, n_dominated),
        "survivors": len(all_rows),
        "advisory": True,
        "kept": [
            {"file": r["file"], "line": r["line"], "kind": r["kind"],
             "operand": r["operand"], "verdict": r["verdict"]}
            for r in all_rows[:200]
        ],
    }

    if emit:
        out_dir = Path(ws) / ".auditooor"
        out_dir.mkdir(parents=True, exist_ok=True)
        if all_rows:
            body = "".join(json.dumps(r) + "\n" for r in all_rows)
        else:
            # cited-empty proof-of-run marker (query ran, 0 survivors) so the
            # step-2d-slice-oob verifier's file_exists passes on a clean run.
            body = json.dumps({"schema": "slice_oob_bounds_taint.v1", "survivors": 0,
                               "note": "cited-empty: untrusted length/offset OOB taint+"
                                       "dominance screen ran, no survivor"}) + "\n"
        (out_dir / "slice_oob_bounds_taint.jsonl").write_text(body)
        (out_dir / "slice_oob_bounds_taint.accounting.json").write_text(
            json.dumps(acct, indent=2))
    return acct


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="RANK-8 untrusted length/offset -> OOB slice/pointer taint+dominance screen")
    ap.add_argument("--workspace", required=True, help="workspace root (sidecar dest)")
    ap.add_argument("--src-root", default=None, help="alt dir/file to scan (real substrate)")
    ap.add_argument("--emit", action="store_true", help="(default-on) write jsonl + accounting sidecars")
    ap.add_argument("--no-emit", action="store_true", help="suppress writing the sidecars")
    ap.add_argument("--json", action="store_true", help="print accounting json to stdout")
    ap.add_argument("--max-rows", type=int, default=5000)
    ap.add_argument("--time-budget", type=float, default=120.0,
                    help="total wall-clock seconds; the scan stops after this and logs "
                         "scan_capped=true (never a silent truncation)")
    ap.add_argument("--max-file-lines", type=int, default=6000,
                    help="skip (and count) a single file larger than this many lines")
    ap.add_argument("--per-file-timeout", type=float, default=10.0,
                    help="SIGALRM seconds per file; a hung file (regex backtrack / O(n^2)) "
                         "is abandoned + counted in per_file_timed_out, never silently clean")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit 2 if any survivor found (for a gate); never changes verdicts")
    args = ap.parse_args(argv)

    # EMIT BY DEFAULT (2026-07-14): the step-2d-slice-oob verifier checks file_exists
    # on slice_oob_bounds_taint.jsonl as proof-of-run; the runbook documents the plain
    # command with no --emit, so a genuine run (0 survivors included) must write the
    # cited-empty ledger. --no-emit opts out (inspection only).
    acct = run(Path(args.workspace),
               Path(args.src_root) if args.src_root else None,
               (not args.no_emit), args.max_rows,
               time_budget_s=args.time_budget, max_file_lines=args.max_file_lines,
               per_file_timeout_s=args.per_file_timeout)
    if acct.get("scan_capped") or acct.get("oversized_skipped") or acct.get("per_file_timed_out"):
        print(f"[slice-oob] NOTE scan_capped={acct.get('scan_capped')} "
              f"oversized_skipped={acct.get('oversized_skipped')} "
              f"per_file_timed_out={acct.get('per_file_timed_out')} "
              f"files_scanned={acct.get('files_scanned')}/{acct.get('files_total')}",
              file=sys.stderr)

    if args.json:
        print(json.dumps(acct, indent=2))
    else:
        print(f"[{DETECTOR}] status={acct['status']} "
              f"files={acct['files_scanned']} nodes={acct['slice_nodes']} "
              f"tainted={acct['untrusted_tainted']} "
              f"dominated={acct['bounds_dominated']} survivors={acct['survivors']}")

    if args.fail_closed and acct["survivors"] > 0:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
