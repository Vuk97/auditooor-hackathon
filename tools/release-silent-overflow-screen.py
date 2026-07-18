#!/usr/bin/env python3
"""release-silent-overflow-screen.py - GEN-R5, the RELEASE-MODE SILENT INTEGER
OVERFLOW -> ALLOC/INDEX screen (lang-intrinsic layer = rust-soundness).

RUST-ONLY. A GENERAL advisory screen (never a specific bug-shape).

GENERAL LOGIC. In RELEASE mode Rust integer arithmetic WRAPS silently - the
`overflow-checks` flag defaults OFF in release, so `a + b`, `a - b`, `a * b`,
`a << b`, and a NARROWING cast (`as u32` / `as usize` / `as u16` from a wider
type) do NOT panic; they wrap to a wrong (small or huge) value. When an
UNTRUSTED numeric value flows through such an UNCHECKED op into a
MEMORY-SAFETY-relevant sink, the wrapped value can produce an UNDERSIZED
allocation (later OOB write) or a wrapped offset/index (OOB pointer / index).

FIRES when BOTH hold at a memory-safety sink:
  (a) UNTRUSTED-SOURCE TAINT - the length/index operand traces to a decode /
      deserialize read (`read_u32` / `from_le_bytes` / `Decode` / `deserialize`
      / `get_u32` ...), a network / message field, or a PUBLIC-fn numeric
      parameter - NOT a local constant, config, or the `.len()` of an
      already-bounded in-memory collection; AND
  (b) a BARE arithmetic op (`+ - * <<`) or a NARROWING cast (`as u32/usize/u16`
      from a wider type) with NO `checked_` / `saturating_` /
      `wrapping_`-with-comment / `try_into` / `TryFrom` / explicit range-assert
      guard on the contributing chain, REACHING a MEMORY-SAFETY sink:
        `Vec::with_capacity` / `reserve` / `reserve_exact` / `Vec::set_len` /
        `get_unchecked` / `get_unchecked_mut` / slice range index `s[a..b]` /
        `ptr::add` / `.add` / `ptr::offset` / `.offset` / `from_raw_parts` /
        `copy_nonoverlapping` length.

FP-CONTROL (critical - bare arithmetic is everywhere; sound forms stay SILENT):
  * BOTH an untrusted-source taint AND a memory-safety sink are REQUIRED; a bare
    `i + 1` in a bounded loop, arithmetic between two `.len()` values of owned
    Vecs, or an op whose operands are all `.len()` / literals / ALL_CAPS consts
    -> SILENT.
  * ANY `checked_` / `saturating_` / `wrapping_` / `try_into` / `try_from` /
    `.min(` / preceding range-`assert!`/`ensure!` on the contributing chain ->
    SILENT (the wrap is guarded).
  * a trusted CONSTANT / CONFIG source -> SILENT.
  * When taint is UNCERTAIN (param-name / message-field heuristic rather than an
    explicit decode read) the row is tagged `medium`, not `high`.

RELATIONSHIP (cite both, per dispatch brief):
  * COMPOSES with GEN-EL6, which flags the release `overflow-checks = false`
    CONFIG (Cargo profile). GEN-R5 is the SOURCE-SITE dataflow (the specific
    untrusted-arith -> memory-sink), independent of the profile flag.
  * INVERSE of `rust-panic-reach` (RU2 axis in rust-detector-runner.py), which
    flags a DEBUG-mode panic (index-out-of-bounds / overflow PANIC = liveness
    DoS). GEN-R5 flags the RELEASE silent-wrap = MEMORY unsafety, the other side
    of the same `overflow-checks` coin.

DEDUP (tool-duplication preflight, do-NOT #10 - cite):
  * `rust-panic-reach` (RU2): an untrusted value reaching a DEBUG-panic
    arithmetic (index-OOB / overflow PANIC = DoS in debug). NOT the RELEASE
    silent-wrap-to-memory-sink. GEN-R5 is the memory-unsafety inverse.
  * `rust-eager-alloc-nomax-screen` (RU8) / `rust-decode-bomb-scan` /
    `rust-host-length-cast-unbounded-alloc-scan`: an UNBOUNDED alloc SIZE (a
    huge but CORRECT value = memory DoS / OOM). NOT a WRAPPED / NARROWED value
    producing an UNDERSIZED alloc + a later OOB write. GEN-R5 keys on the WRONG
    (wrapped-small) value, not the big-correct value.
  * `rust-numeric-overflow-underflow-scan`: `<coll>.len() - 1` empty-guard wraps
    and bounded-int-field `+ 1` increments, PANIC/precision faults - it screens
    `.len()` arithmetic on owned collections (which GEN-R5 explicitly EXCLUDES
    from taint) and a PANIC impact, not the untrusted-wrap-into-memory-sink.
  GEN-R5 = the untrusted-arith-WRAPS-into-memory-sink JOIN. A site that reduces
  to one of the above is dropped as overlap.

nuva has NO Rust surface -> nuva-verify is correctly N/A for this capability.

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False; exit 0 by default. The opt-in env
AUDITOOOR_RELEASE_SILENT_OVERFLOW_STRICT (or --strict) raises the exit code when
a fired row exists.

Excludes test / vendor / codegen via the shared exclusion libs.

Usage:
  --workspace <ws>   scan <ws>/src (or <ws>) -> .auditooor/
                     release_silent_overflow_hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON (NO sidecar)
  --file <f>         scan a single .rs file, print rows as JSON
  --check            re-read the emitted sidecar, print cert verdict (advisory)
  --strict           (or env) elevate exit code when a fired row exists
  --json             machine summary to stdout
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

HYP_SCHEMA = "auditooor.release_silent_overflow_hypotheses.v1"
_SIDE_NAME = "release_silent_overflow_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_RELEASE_SILENT_OVERFLOW_STRICT"
_CAPABILITY = "GEN_R5"

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
              "cache", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmarks", "examples", "example", "script",
              "scripts", "deployments", "prior_audits", "reference", "certora",
              "simulation", "testdata", "mocks", "mock", "artifacts", "fuzz",
              "chimera_harnesses"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|testutil|testonly|testhelper|test_fixtures|mock|mocks|"
    r"benches|benchmarks?|examples?|fixtures|simulation|testdata|poc|pocs|"
    r"chimera_harnesses)(/|$)")
_CODEGEN_SENTINEL = re.compile(r"Code generated .{0,80}?DO NOT EDIT", re.I)


# ============================================================================
# Rust-aware comment / string masking. Rust uses //, /* */ and "..." strings.
# We do NOT mask ' because it is a lifetime marker (not a char delimiter) in the
# code we care about, so lifetimes survive intact.
# ============================================================================
def _mask(text: str) -> str:
    out = []
    i, n = 0, len(text)
    in_line = in_block = in_str = False
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
            if c == '"':
                in_str = False
            i += 1
        elif c == '"':
            in_str = True
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


def _stable_id(rel, sink, subject, line):
    h = hashlib.sha1()
    h.update(f"{rel}|{sink}|{subject}|{line}".encode())
    return h.hexdigest()[:16]


# ============================================================================
# balanced extraction helpers
# ============================================================================
def _balanced_parens(text: str, open_idx: int):
    """(inner, close_idx) for a '(' at text[open_idx]. -1 if unbalanced."""
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
    return "", -1


def _balanced_bracket(text: str, open_idx: int):
    """(inner, close_idx) for a '[' at text[open_idx]. -1 if unbalanced."""
    depth = 0
    n = len(text)
    i = open_idx
    while i < n:
        ch = text[i]
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i], i
        i += 1
    return "", -1


def _top_level_split(inner: str, sep: str = ","):
    parts, depth, cur = [], 0, []
    for ch in inner:
        if ch in "<([{":
            depth += 1
            cur.append(ch)
        elif ch in ">)]}":
            depth -= 1
            cur.append(ch)
        elif ch == sep and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail or parts:
        parts.append(tail)
    return parts


# ============================================================================
# function extraction: (name, sig, body_text, body_start_offset)
# ============================================================================
_FN_DECL_RE = re.compile(
    r"(?P<vis>pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(?:const\s+)?"
    r"(?:extern\s+\"[^\"]*\"\s+)?fn\s+(?P<name>[A-Za-z_]\w*)")


def _iter_functions(text: str):
    """Yield (name, is_pub, sig_params, body, body_off). Brace-matched bodies."""
    n = len(text)
    for m in _FN_DECL_RE.finditer(text):
        # signature params: the first '(...)' after the name.
        popen = text.find("(", m.end())
        if popen == -1:
            continue
        sig, pclose = _balanced_parens(text, popen)
        if pclose == -1:
            continue
        # find the body '{' after the signature (skip the return type / where).
        bopen = text.find("{", pclose)
        if bopen == -1:
            continue
        # a ';' before '{' means a trait-decl / fn-pointer -> no body.
        semi = text.find(";", pclose)
        if semi != -1 and semi < bopen:
            continue
        depth = 0
        i = bopen
        while i < n:
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        body = text[bopen:i + 1]
        yield (m.group("name"), bool(m.group("vis")), sig, body, bopen)


# ============================================================================
# taint model
# ============================================================================
# explicit decode / deserialize / wire-read tokens (untrusted, HIGH confidence).
_DECODE_READ_RE = re.compile(
    r"\b(read_u(?:8|16|32|64|128)|read_i(?:8|16|32|64|128)|read_uint|read_int|"
    r"read_var\w*|read_compact\w*|read_len\w*|read_exact|read_to_end|"
    r"from_le_bytes|from_be_bytes|from_ne_bytes|get_u(?:8|16|32|64|128)"
    r"(?:_le)?|get_i(?:8|16|32|64|128)(?:_le)?|next_u(?:32|64)|"
    r"deserialize\w*|BorshDeserialize|from_reader|decode_len)\b")
_DECODE_DECODE_RE = re.compile(r"(?:::|\.)decode\s*\(")

# message / packet field access (untrusted, MEDIUM confidence).
_MSG_RECV = (r"(?:msg|message|packet|pkt|frame|header|hdr|payload|hint|req|"
             r"request|record|entry|item|input|decoded|parsed|raw|wire)")
_MSG_FIELD_RE = re.compile(
    r"\b" + _MSG_RECV + r"\s*\.\s*[A-Za-z_]\w*")

# guard tokens that discharge the wrap on the contributing chain.
_GUARD_RE = re.compile(
    r"\b(checked_(?:add|sub|mul|shl|shr|pow)|saturating_(?:add|sub|mul|shl)|"
    r"overflowing_(?:add|sub|mul|shl)|wrapping_(?:add|sub|mul|shl)|"
    r"try_into|try_from|TryInto|TryFrom|checked_next_power_of_two)\b|\.\s*min\s*\(")
# a preceding explicit range guard (assert!/ensure!/require/if ... > CONST).
_RANGE_GUARD_RE = re.compile(
    r"\b(assert!|assert_eq!|debug_assert!|ensure!|require!?)\b")

# narrowing cast to a bounded width (the classic wrap on truncation).
_NARROW_CAST_RE = re.compile(r"\bas\s+(u8|u16|u32|usize|i8|i16|i32|isize)\b")
# a bare arithmetic operator (masking already removed strings/comments).
_BARE_ARITH_RE = re.compile(r"(?<![<>=!+\-*/%&|^])(\+|-|\*|<<)(?!=)")
# operand tokens that are TRUSTED / bounded (never a taint source).
_LEN_CALL_RE = re.compile(r"\.\s*len\s*\(\s*\)")
_NUMERIC_PRIM_RE = re.compile(
    r"^(?:u8|u16|u32|u64|u128|usize|i8|i16|i32|i64|i128|isize)$")


def _ident_tokens(expr: str):
    return set(re.findall(r"[A-Za-z_]\w*", expr))


def _sig_params(sig: str):
    """name -> type_string for the fn signature params."""
    out = {}
    for part in _top_level_split(sig):
        part = part.strip()
        if not part or part.startswith("&self") or part == "self" \
                or part.startswith("self") or part.startswith("mut self"):
            continue
        # `name : type`
        m = re.match(r"(?:mut\s+)?([A-Za-z_]\w*)\s*:\s*(.+)$", part)
        if m:
            out[m.group(1)] = m.group(2).strip()
    return out


def _numeric_param(ty: str) -> bool:
    core = ty.strip().lstrip("&").replace("mut ", "").strip()
    return bool(_NUMERIC_PRIM_RE.match(core))


def _bytes_param(ty: str) -> bool:
    t = ty.replace(" ", "")
    return bool(re.search(r"&(?:mut)?\[u8\]|Bytes(?:Mut)?|Vec<u8>", t))


def _build_lets(body: str):
    """var -> rhs_text for `let (mut)? VAR (: TY)? = RHS;` bindings in body."""
    lets = {}
    for m in re.finditer(
            r"\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::[^=;]+)?=\s*", body):
        var = m.group(1)
        # RHS runs to the statement-terminating ';' at brace/paren depth 0.
        i = m.end()
        depth = 0
        n = len(body)
        start = i
        while i < n:
            ch = body[i]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                if depth == 0:
                    break
                depth -= 1
            elif ch == ";" and depth == 0:
                break
            i += 1
        if var not in lets:  # keep first binding (dominating def)
            lets[var] = body[start:i]
    return lets


def _resolve_chain(expr: str, lets: dict, max_hops: int = 4):
    """Concatenate expr with the let-RHS of every var it (transitively) uses."""
    seen = set()
    frontier = [expr]
    chain = [expr]
    hops = 0
    while frontier and hops < max_hops:
        nxt = []
        for e in frontier:
            for tok in _ident_tokens(e):
                if tok in seen:
                    continue
                seen.add(tok)
                if tok in lets:
                    rhs = lets[tok]
                    chain.append(rhs)
                    nxt.append(rhs)
        frontier = nxt
        hops += 1
    return " ;; ".join(chain)


def _untrusted(chain: str, params: dict, is_pub: bool):
    """(tainted: bool, confidence: 'high'|'medium'|None, source_desc)."""
    if _DECODE_READ_RE.search(chain) or _DECODE_DECODE_RE.search(chain):
        m = _DECODE_READ_RE.search(chain) or _DECODE_DECODE_RE.search(chain)
        return True, "high", "decode/deserialize read (`%s`)" % (
            m.group(0).strip())
    # public-fn numeric parameter used in the chain.
    toks = _ident_tokens(chain)
    for pname, pty in params.items():
        if pname in toks and _numeric_param(pty):
            conf = "high" if is_pub else "medium"
            return True, conf, "%sfn numeric parameter `%s: %s`" % (
                "public " if is_pub else "", pname, pty)
    # message / packet field access.
    if _MSG_FIELD_RE.search(chain):
        return True, "medium", "message/packet field access (`%s`)" % (
            _MSG_FIELD_RE.search(chain).group(0).strip())
    return False, None, ""


def _wrap_op(chain: str):
    """(arith_op_label, matched_snippet) for an UNGUARDED wrap in the chain, or
    (None, None). Skips ops whose only operands are `.len()` / literals."""
    if _NARROW_CAST_RE.search(chain):
        return "narrowing-as", _NARROW_CAST_RE.search(chain).group(0)
    # bare arithmetic: require at least one non-.len()/non-literal operand.
    # strip `.len()` calls and numeric literals, then look for an operator whose
    # neighbourhood still has an identifier.
    for m in _BARE_ARITH_RE.finditer(chain):
        window = chain[max(0, m.start() - 40):m.end() + 40]
        stripped = _LEN_CALL_RE.sub(" LEN ", window)
        # remove pure numeric literals and the LEN sentinel and ALL_CAPS consts
        residual = re.sub(r"\b\d[\d_]*\b", " ", stripped)
        residual = re.sub(r"\bLEN\b", " ", residual)
        residual = re.sub(r"\b[A-Z][A-Z0-9_]{2,}\b", " ", residual)
        if re.search(r"[a-z_]\w*", residual):
            op = m.group(1)
            label = {"+": "add", "-": "sub", "*": "mul", "<<": "shl"}[op]
            return label, m.group(0)
    return None, None


def _guarded(chain: str) -> bool:
    return bool(_GUARD_RE.search(chain) or _RANGE_GUARD_RE.search(chain))


# ============================================================================
# memory-safety sinks
# ============================================================================
# call-style sinks: name -> (arg_index_for_size, sink_label)
_CALL_SINKS = [
    (re.compile(r"\bwith_capacity\s*\("), 0, "with_capacity"),
    (re.compile(r"\breserve(?:_exact)?\s*\("), 0, "reserve"),
    (re.compile(r"\bset_len\s*\("), 0, "set_len"),
    (re.compile(r"\bget_unchecked(?:_mut)?\s*\("), 0, "get_unchecked"),
    (re.compile(r"\bfrom_raw_parts(?:_mut)?\s*\("), 1, "from_raw_parts"),
    (re.compile(r"\bcopy_nonoverlapping\s*\("), 2, "copy_nonoverlapping"),
    (re.compile(r"(?:\bptr\s*::\s*add|\.\s*add|\bptr\s*::\s*offset|"
                r"\.\s*offset)\s*\("), 0, "ptr-add"),
]
# slice range index: IDENT[ A .. B ]  (masked text; ranges only, not [i]).
_SLICE_IDX_RE = re.compile(r"[A-Za-z_]\w*\s*\[")


def _sink_size_exprs(body: str):
    """Yield (sink_label, size_expr, off) for each memory-safety sink."""
    for rx, argi, label in _CALL_SINKS:
        for m in rx.finditer(body):
            popen = body.find("(", m.end() - 1)
            if popen == -1:
                continue
            inner, pclose = _balanced_parens(body, popen)
            if pclose == -1:
                continue
            args = _top_level_split(inner)
            if argi >= len(args):
                continue
            size = args[argi].strip()
            if not size:
                continue
            yield label, size, m.start()
    # slice range indexing s[a..b] / s[a..] / s[..b]
    for m in _SLICE_IDX_RE.finditer(body):
        bopen = body.find("[", m.end() - 1)
        if bopen == -1:
            continue
        inner, bclose = _balanced_bracket(body, bopen)
        if bclose == -1 or ".." not in inner:
            continue
        yield "slice-range", inner.strip(), m.start()


# ============================================================================
# scan a single Rust file
# ============================================================================
def _mk_row(rel, fn, line, sink, arith_op, untrusted_src, excerpt, severity,
            why):
    # Every _mk_row site is a FIRED survivor (untrusted-arith wraps into a
    # memory-safety sink, unguarded). A fired survivor is an OPEN obligation, NOT
    # advisory-green: advisory=False + proof_status='open' so a downstream
    # advisory filter counts it OPEN instead of draining silently to advisory
    # (vacuity-telltale fix). fires==False enumeration leads keep advisory=True.
    fires = True
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "id": _stable_id(rel, sink, fn + "|" + arith_op, line),
        "file": rel,
        "line": line,
        "function": fn,
        "lang": "rust",
        "arith_op": arith_op,
        "sink": sink,
        "untrusted_source": untrusted_src,
        "guard_absent": True,
        "excerpt": excerpt,
        "severity": severity,
        "why_severity_anchored": why,
        "fires": fires,
        "verdict": "needs-fuzz",
        "advisory": not fires,
        "proof_status": "open" if fires else "advisory",
        "auto_credit": False,
    }


def scan_file(path: Path, rel: str, file_text: str = None):
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    if not rel.lower().endswith(".rs"):
        return []
    text = _mask(raw)
    rows = []
    seen = set()

    for name, is_pub, sig, body, body_off in _iter_functions(text):
        params = _sig_params(sig)
        # a fn is a taint frontier only if it has a decode read OR an untrusted
        # param OR a message field access somewhere in scope; cheap pre-filter.
        has_source = bool(
            _DECODE_READ_RE.search(body) or _DECODE_DECODE_RE.search(body)
            or _MSG_FIELD_RE.search(body)
            or any(_numeric_param(t) or _bytes_param(t)
                   for t in params.values()))
        if not has_source:
            continue
        lets = _build_lets(body)
        for sink, size_expr, soff in _sink_size_exprs(body):
            # resolve the size expr through its let-defined variables.
            chain = _resolve_chain(size_expr, lets)
            # (b) an UNGUARDED wrap op on the chain.
            arith_op, _snip = _wrap_op(chain)
            if not arith_op:
                continue
            if _guarded(chain):
                continue
            # (a) untrusted taint on the chain.
            tainted, conf, src_desc = _untrusted(chain, params, is_pub)
            if not tainted:
                continue
            abs_off = body_off + soff
            line = _line_of_offset(text, abs_off)
            key = (line, sink, size_expr[:40])
            if key in seen:
                continue
            seen.add(key)
            # severity: high only when the wrap is a decode-read taint reaching
            # an alloc-size / set_len / raw-parts / copy sink (undersized-alloc
            # -> OOB write) OR a get_unchecked / ptr / slice (OOB index); the
            # param/field heuristics stay medium.
            hard_sink = sink in ("with_capacity", "reserve", "set_len",
                                 "from_raw_parts", "copy_nonoverlapping",
                                 "get_unchecked", "ptr-add", "slice-range")
            severity = "high" if (conf == "high" and hard_sink) else "medium"
            oob = ("an UNDERSIZED allocation -> a later out-of-bounds write"
                   if sink in ("with_capacity", "reserve", "set_len",
                               "from_raw_parts")
                   else "an out-of-bounds pointer/index read or write")
            why = (
                "release-mode `overflow-checks` is OFF by default, so the "
                "`%s` on an untrusted value (%s) WRAPS SILENTLY instead of "
                "panicking. The wrapped (wrong) length/offset reaches the "
                "memory-safety sink `%s`, producing %s. No `checked_`/"
                "`try_into`/range-guard dominates the arithmetic. "
                "(Inverse of rust-panic-reach's DEBUG panic; composes with "
                "GEN-EL6's profile-flag check.)"
            ) % (arith_op, src_desc, sink, oob)
            rows.append(_mk_row(
                rel, name, line, sink, arith_op, src_desc,
                _excerpt(text, abs_off), severity, why))

    return rows


# ============================================================================
# tree walk + sidecar
# ============================================================================
def _iter_source_files(root: Path, workspace: Path = None):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        norm = dp.replace(os.sep, "/")
        if _TEST_HINT.search(norm):
            continue
        for f in fn:
            low = f.lower()
            if not low.endswith(".rs"):
                continue
            if low.endswith("_test.rs") or low.startswith("test") \
                    or low.startswith("mock") or low == "tests.rs":
                continue
            if _TEST_HINT.search(f):
                continue
            p = Path(dp) / f
            rel = str(p)
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
    rows = []
    for p in _iter_source_files(root, workspace):
        try:
            rel = str(p.relative_to(root))
        except ValueError:
            rel = str(p)
        try:
            rows.extend(scan_file(p, rel))
        except Exception:
            continue
    return rows


def _emit_sidecar(ws: Path, rows, rust_present: bool = False):
    outdir = ws / ".auditooor"
    outdir.mkdir(parents=True, exist_ok=True)
    out = outdir / _SIDE_NAME
    with out.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
        # Capability-vacuity-telltale: screen RAN over a real Rust surface, 0 rows ->
        # PERSIST a cited-empty examined-record (FIRED_CLEAN, not silently VACUOUS).
        # Gated on Rust presence; absent Rust is governed by a surface-absent exemption.
        if not rows and rust_present:
            fh.write(json.dumps({
                "schema": HYP_SCHEMA,
                "note": ("cited-empty: release-mode silent-overflow screen ran over "
                         "the Rust surface, 0 profile-wrap/silent-overflow sites"),
                "survivors": [],
                "report": {"reasoner": "release-silent-overflow-screen",
                           "verdict": "clean-advisory", "totals": {"examined": 1}},
            }) + "\n")
    return out


def _count(rows, key):
    out = {}
    for r in rows:
        v = str(r.get(key, ""))
        out[v] = out.get(v, 0) + 1
    return out


def _summary(rows):
    fired = [r for r in rows if r.get("fires")]
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "sites": len(rows),
        "fired": len(fired),
        "by_sink": _count(rows, "sink"),
        "by_arith_op": _count(rows, "arith_op"),
        "by_severity": _count(rows, "severity"),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="GEN-R5 release-mode silent integer overflow -> alloc/index "
                    "screen (Rust, advisory)")
    ap.add_argument("--workspace", "--ws")
    ap.add_argument("--source")
    ap.add_argument("--file")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    strict = args.strict or os.environ.get(
        _STRICT_ENV, "").strip() not in ("", "0", "false")

    if args.file:
        p = Path(args.file)
        rows = scan_file(p, p.name)
        print(json.dumps(rows, indent=2))
        return 0

    if args.source:
        rows = scan_tree(Path(args.source))
        print(json.dumps(rows, indent=2))
        return 0

    if not args.workspace:
        ap.error("one of --workspace / --source / --file is required")

    ws = Path(args.workspace)
    if not ws.is_absolute():
        for base in ("/Users/wolf/audits", os.getcwd()):
            cand = Path(base) / args.workspace
            if cand.exists():
                ws = cand
                break
    side = ws / ".auditooor" / _SIDE_NAME

    if args.check:
        rows = []
        if side.exists():
            rows = [json.loads(line) for line in side.read_text().splitlines()
                    if line.strip()]
        summ = _summary(rows)
        summ["source"] = "sidecar"
        print(json.dumps(summ, indent=2))
        return 1 if (strict and summ["fired"]) else 0

    src = ws / "src"
    root = src if src.exists() else ws
    rows = scan_tree(root, workspace=ws)
    rust_present = any(
        "node_modules" not in p.parts for p in root.rglob("*.rs"))
    _emit_sidecar(ws, rows, rust_present=rust_present)
    summ = _summary(rows)
    print(json.dumps(summ, indent=2))
    return 1 if (strict and summ["fired"]) else 0


if __name__ == "__main__":
    sys.exit(main())
