#!/usr/bin/env python3
"""narrowing-lossy-cast-screen.py - the LOSSY FIXED-WIDTH NARROWING screen (MQ-B05).

GENERAL LOGIC / TRUST-ENFORCEMENT class (never a bug SHAPE). It instantiates the
north-star method ("a TRUSTED ENFORCEMENT is bypassable or its private invariant is
unsound") for one delegated-and-trusted safety property no existing screen reaches:
the value-representation fidelity of an integer as it crosses a lossy fixed-width /
sign conversion.

  DELEGATED-TRUSTED INVARIANT : downstream code that consumes a narrowed integer (a
    length, index, id, amount, decimals, chain-id, nonce, offset, height, shard) is
    trusted to receive the SAME mathematical value the untrusted producer supplied -
    the conversion is a no-op on the value, only the storage width changed.
  PRIVATE INVARIANT           : that trust holds ONLY if the value provably FITS the
    narrower target repr. The private invariant is a DOMINATING bounds check on the
    operand (`x > math.MaxUint32 -> reject`, `if x <= WASM_MAX_PAGES`, a `u32::try_from`
    checked conversion, a `1<<32` / `0xffffffff` mask compare) that executes BEFORE the
    narrowing so an out-of-range value can never reach the cast.
  ATTACK                      : an attacker who controls the operand at an untrusted
    boundary (a decoded field, a `len(input)`, a public-API / message / RPC parameter)
    supplies a value larger than the target repr. Without the dominating bound the cast
    SILENTLY TRUNCATES (Go `uint32(x)` drops the high bits; Rust `x as u16` wraps) or
    SIGN-FLIPS (`int32(bigUint)`), so a length/index/id/amount is silently rewritten to a
    different in-range value. Downstream sees a normal-looking number with no upstream
    visibility that it was mangled - length under-reads, index aliasing, id collision,
    amount/decimals corruption, chain-id confusion.

Enforcement points = each fixed-width / sign narrowing conversion whose operand
provenance reaches an untrusted-input boundary:
  Go   : `uint8(` / `uint16(` / `uint32(` / `int8(` / `int16(` / `int32(` / `byte(` /
         `rune(` / `int(` / `uint(` applied to a tainted operand.
  Rust : `<expr> as u8|u16|u32|i8|i16|i32` on a tainted operand (`usize`/`u64`/`i64`
         targets are word-width / widening and are NOT flagged).
Per point the screen answers {target_type, operand, provenance, dominating_bound?} and
flags (WARN, verdict=needs-fuzz) ONLY when the operand is untrusted-derived AND NO
dominating bounds check proves it fits the target repr.

It is ADVISORY-FIRST: every emitted row carries verdict='needs-fuzz', advisory=True,
auto_credit=False. It NEVER auto-credits and NEVER fail-closes in default mode. The
strict env AUDITOOOR_NARROWING_LOSSY_CAST_STRICT (opt-in, or --strict) only raises the
exit code; it still emits no credit. Language-general: Go (.go) and Rust (.rs), the two
fleet native languages with silent-truncating integer conversions; silent on other trees.

Usage:
  --workspace <ws>   scan <ws>/src (or <ws>) -> .auditooor/narrowing_lossy_cast_hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir (test / ad-hoc), print candidate rows as JSON
  --file <f>         scan a single .go/.rs file, print candidate rows as JSON
  --check            re-read the emitted sidecar, print cert verdict (advisory)
  --strict           (or env) elevate exit code when a un-bounded narrowing exists
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

HYP_SCHEMA = "auditooor.narrowing_lossy_cast_hypotheses.v1"
CAPABILITY = "MQ-B05-narrowing-lossy-cast"
_SIDE_NAME = "narrowing_lossy_cast_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_NARROWING_LOSSY_CAST_STRICT"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "lib", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmarks", "forge-std", "mocks", "testdata"}
# test / mock / example / bench trees are excluded: a narrowing there is not a
# production trust surface (harnesses feed synthetic, already-bounded values).
_TEST_HINT = re.compile(
    r"(^|/)(tests?|test_fixtures|mock|mocks|example|examples|script|scripts|"
    r"chimera_harnesses|poc-tests|benches|fuzz|testutil)(/|$)", re.IGNORECASE)
_TEST_FILE_HINT = re.compile(r"(_test\.go$|_tests?\.rs$|\btest_|Mock|Harness|PoC_)")

# --- narrowing target types ---------------------------------------------------
# Go: a fixed-width small int / byte / rune conversion, plus the platform-word
# `int(` / `uint(` (which truncate a uint64/int64). `uint64`/`int64` targets are
# NOT narrowing (widening or same-width) and are excluded by longest-match ordering.
# `(?<![\]\w.])` rejects `[32]byte(` / `[]byte(` array-or-slice type conversions and
# `pkg.int32(` qualified names - only a bare scalar narrowing conversion counts. Bare
# `int(` / `uint(` are the platform WORD width (64-bit on the fleet targets) so a cast
# INTO them is widening / same-width, not a lossy narrowing - they are deliberately
# EXCLUDED (they are the dominant false-positive source). The fixed-width targets below
# cover BOTH silent truncation (uint32/uint16/uint8) AND sign-flip (int32/int16/int8).
_GO_CAST = re.compile(
    r"(?<![\]\w.])(uint32|uint16|uint8|int32|int16|int8|byte|rune)\s*\(")
# Rust: `<expr> as u8|u16|u32|i8|i16|i32`. `as usize`/`u64`/`i64`/`u128`/`i128` are
# word-width / widening on the 64-bit fleet targets -> not a lossy narrowing.
_RS_CAST = re.compile(r"\bas\s+(u8|u16|u32|i8|i16|i32)\b")

# --- untrusted-INPUT boundary signals -----------------------------------------
# THE tool is a SCREEN, not an enumerator: a narrowing only matters when the value
# genuinely originates at an attacker-controlled boundary. Two seeds count as such a
# boundary (and NOTHING else - a bare `len()`, a plain function param, or a common
# noun like `value`/`count`/`num` does NOT, they are the enumerator false-positive
# engine):
#   (1) a DECODE / DESERIALIZE / WIRE-READ call (produces a value straight off the
#       wire / calldata / message bytes);
#   (2) a param that is a WIRE BUFFER - a `[]byte`/`&[u8]`/`Vec<u8>`/`Bytes` type, or a
#       name that reads as a raw input frame (`data`/`input`/`payload`/`msg`/`raw`/...).
#       These are the RPC-or-msg arg / attacker-settable field boundary.
_DECODE_CALL = re.compile(
    r"(Unmarshal|Deserialize|deserialize|Decode|decode|"
    r"try_from_slice|from_le_bytes|from_be_bytes|from_slice|ParseUint|ParseInt|"
    r"\.Parse\b|parse\s*::<|\.read_|ReadUint|ReadVarint|ReadUvarint|"
    r"binary\.(?:Big|Little)Endian\.Uint(?:16|32|64)|json\.)")
_LEN_CALL = re.compile(r"\blen\s*\(|\.len\s*\(\s*\)")
# wire-buffer param NAME segments (the raw-input-frame nouns)
_WIRE_NAME = frozenset({
    "data", "input", "buf", "buffer", "payload", "msg", "message", "req",
    "request", "raw", "packet", "body", "stream", "reader", "hashbuf",
    "encoded", "serialized", "wire", "blob", "calldata", "frame", "chunk",
    "bytes", "b",
})
# wire-buffer param TYPE signature (Go slice-of-byte / Rust byte slice or Vec<u8>)
_WIRE_TYPE = re.compile(
    r"\[\]byte|\[\]uint8|&?\s*\[u8\]|&?\s*\[\s*u8\s*;\s*\d+\s*\]|"
    r"Vec\s*<\s*u8\s*>|\bBytes\b")

# --- SECURITY-SENSITIVE sink segments -----------------------------------------
# a narrowed value only matters if it flows into a size / index / identity sink. A
# benign log / display / metric destination is NOT sensitive. Split from the (removed)
# broad provenance noun set: only the size/index/identity nouns count as a sink, and
# `value`/`num`/`val`/`total`/`log`/`block`/`weight`/`balance`/`timestamp` are dropped
# (they were the dominant enumerator noise).
_SINK_SEG = frozenset({
    "len", "length", "size", "sz", "idx", "index", "indices", "id", "ids",
    "amount", "amt", "nonce", "decimal", "decimals", "chain", "chainid",
    "count", "cnt", "offset", "height", "shard", "cap", "capacity",
    "pages", "gas", "slot", "epoch", "port", "ttl",
})
# The full set counts when it names the DESTINATION (an assignment LHS: `ilen := ...`).
# When it names the VALUE itself (the cast operand), only the identity / positional-index
# nouns count - a bare magnitude (`len`/`size`/`count`/`offset`) is a value, not a sink, so
# `uint32(len(data))` going to a log is NOT sensitive (that was an over-fire).
_SINK_MAGNITUDE = frozenset({
    "len", "length", "size", "sz", "count", "cnt", "offset", "cap",
    "capacity", "pages",
})
_SINK_OPERAND = _SINK_SEG - _SINK_MAGNITUDE
# structural sinks: an allocation size or a slice/array index / loop bound.
_STRUCT_SINK = re.compile(
    r"\bmake\s*\(|with_capacity|\balloc\b|\bVec::|reserve\s*\(")

# --- dominating bounds-check (the private-invariant guard) ---------------------
_CMP = re.compile(r"(<=|>=|==|!=|<|>)")
# repr-bound tokens: a numeric-type max/min, a bit-shift / hex mask, or a named
# CONST whose name signals an upper bound (Max/Min/Limit/Bound/Pages/Cap). Bare
# `Size`/`Len` alone are too common to count as a bound.
_BOUND_TOKEN = re.compile(
    r"(?:\bmath\.)?Max(?:U)?[Ii]nt(?:8|16|32|64)?\b"        # Go math.MaxUint32 ...
    r"|\bMax(?:U)?[Ii]nt(?:8|16|32|64)?\b"
    r"|\b[uUiI](?:8|16|32|64|128|size)::(?:MAX|MIN)\b"      # Rust u32::MAX
    r"|1\s*<<\s*\d+"                                         # 1<<32
    r"|0x[fF]{2,}\b"                                         # 0xffffffff mask
    r"|\b[A-Za-z_]*(?:MAX|Max|MIN|Min|LIMIT|Limit|BOUND|Bound|PAGES|Pages|CAP)"
    r"[A-Za-z0-9_]*\b")
# a checked / fallible conversion of the operand is itself a proof-of-fit
_CHECKED_CONV = re.compile(
    r"try_from|try_into|TryFrom|TryInto|checked_|saturating_|SafeCast|toUint|toInt")

# function starts (Go + Rust); Rust allows pub/async/const/unsafe/extern prefixes.
_GO_FN = re.compile(r"^\s*func\s+(?:\(([^)]*)\)\s*)?([A-Za-z_]\w*)\s*\(")
_RS_FN = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+|const\s+|unsafe\s+|"
    r"extern\s+\"[^\"]*\"\s+)*fn\s+([A-Za-z_]\w*)")


def _mask_comments(text: str, lang: str) -> str:
    """Replace `//` line and `/* */` block comments with spaces, preserving newlines
    and per-line length so offsets stay source-aligned. Both Go and Rust share the
    `//` + `/* */` comment syntax. Not string-literal aware (over-masks a `//` inside
    a string) - that errs toward SILENCE (can only drop a would-be token, never invent
    one). Without it a comment mentioning `as u32` / `MaxUint32` would be miscredited
    as a real cast or a real bound."""
    out = []
    i, n = 0, len(text)
    in_line = in_block = False
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


def _iter_source_files(root: Path):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        rp = dp.replace(os.sep, "/")
        if _TEST_HINT.search(rp):
            continue
        for f in fn:
            if not (f.endswith(".go") or f.endswith(".rs")):
                continue
            if _TEST_HINT.search(f) or _TEST_FILE_HINT.search(f):
                continue
            yield Path(dp) / f


def _split_segments(ident: str):
    """Split an identifier into lowercase segments across camelCase + `_` boundaries
    (`LogIndex` -> ['log','index'], `chain_id` -> ['chain','id'])."""
    parts = re.split(r"[_\W]+", ident)
    segs = []
    for p in parts:
        for s in re.findall(r"[A-Z]+(?![a-z])|[A-Z][a-z0-9]*|[a-z0-9]+", p):
            segs.append(s.lower())
    return segs


def _seg_hits(text: str, seg_set) -> bool:
    """True iff any camel/snake segment of `text` is in `seg_set`."""
    return any(s in seg_set for s in _split_segments(text or ""))


def _fn_units(lines, lang):
    """Yield (fn_name, start_idx, body_lines, param_names, recv_names) for each Go/Rust
    function, brace-matched. `param_names` excludes the receiver / `self` (internal
    state is not an untrusted boundary)."""
    fn_re = _GO_FN if lang == "go" else _RS_FN
    i, n = 0, len(lines)
    while i < n:
        m = fn_re.match(lines[i])
        if not m:
            i += 1
            continue
        # gather the signature text (start line .. first `{`) for param parsing
        sig = []
        j = i
        while j < n:
            sig.append(lines[j])
            if "{" in lines[j]:
                break
            j += 1
        sig_text = " ".join(sig)
        recv, params, untrusted = _parse_params(sig_text, lang, m)
        # brace-matched body
        depth, started, body = 0, False, []
        j = i
        while j < n:
            line = lines[j]
            depth += line.count("{") - line.count("}")
            body.append(line)
            if "{" in line:
                started = True
            if started and depth <= 0:
                break
            j += 1
        fn = m.group(2) if lang == "go" else m.group(1)
        yield fn, i, body, params, recv, untrusted
        i = max(j, i + 1)


def _balanced_group(s, open_idx):
    """Return the text inside a balanced `(...)` starting at s[open_idx] == '(' (exclusive
    of the outer parens), or None if unbalanced."""
    depth = 0
    for k in range(open_idx, len(s)):
        c = s[k]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return s[open_idx + 1:k], k
    return None, None


def _param_untrusted(name: str, type_text: str) -> bool:
    """A param is an UNTRUSTED-INPUT boundary iff it is a wire buffer - a byte-slice /
    Vec<u8> / Bytes TYPE, or a name that reads as a raw input frame. A plain scalar param
    (`amount u64`, `rhs: usize`, `n int`) is NOT a boundary - that was the enumerator."""
    if type_text and _WIRE_TYPE.search(type_text):
        return True
    return any(s in _WIRE_NAME for s in _split_segments(name))


def _parse_params(sig_text, lang, m):
    """Return (receiver_names, param_names, untrusted_param_names). Receiver / self
    excluded from params. `untrusted` = the subset of params that are wire buffers."""
    recv, params, untrusted = [], [], []
    if lang == "go":
        if m.group(1):  # receiver `id *Identifier`
            for part in m.group(1).split(","):
                tok = part.strip().split()
                if tok:
                    recv.append(tok[0])
        # param list = the first balanced (...) after the fn name
        idx = sig_text.find(m.group(2))
        popen = sig_text.find("(", idx + len(m.group(2)))
        if popen != -1:
            inner, _ = _balanced_group(sig_text, popen)
            if inner:
                for part in _top_commas(inner):
                    tok = part.strip().split()
                    if not tok:
                        continue
                    nm = tok[0]
                    params.append(nm)
                    type_text = " ".join(tok[1:])
                    if _param_untrusted(nm, type_text):
                        untrusted.append(nm)
    else:  # rust
        name = m.group(1)
        popen = sig_text.find("(", sig_text.find(name) + len(name))
        if popen != -1:
            inner, _ = _balanced_group(sig_text, popen)
            if inner:
                for part in _top_commas(inner):
                    p = part.strip()
                    if not p:
                        continue
                    # `&self` / `&mut self` / `self` -> receiver
                    base = p.replace("&", "").replace("mut ", "").strip()
                    nm = base.split(":")[0].strip()
                    if nm == "self":
                        recv.append("self")
                    elif nm:
                        params.append(nm)
                        type_text = p.split(":", 1)[1] if ":" in p else ""
                        if _param_untrusted(nm, type_text):
                            untrusted.append(nm)
    return recv, params, untrusted


def _top_commas(s):
    parts, depth, cur = [], 0, []
    for ch in s:
        if ch in "([{<":
            depth += 1
            cur.append(ch)
        elif ch in ")]}>":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return parts


_ASSIGN = re.compile(
    r"^\s*(?:let\s+(?:mut\s+)?)?([A-Za-z_]\w*)\s*(?::[^=]+)?:?=\s*(.+)$")


def _taint_set(body, params, recv, untrusted):
    """Fixpoint taint of local variables reachable from a GENUINE untrusted-input
    boundary. Seed ONLY with wire-buffer params + any var whose defining RHS is a
    decode/deserialize/wire-read call. Then propagate: a var is tainted iff its RHS
    references a tainted token OR performs a decode. A bare `len()`, a plain scalar
    param, and a common noun are NO LONGER seeds - that was the enumerator engine."""
    recv_set = set(recv)
    tainted = set(u for u in untrusted if u not in recv_set)
    # assignment map name -> rhs
    assigns = []
    for line in body:
        # decode-into-pointer idiom: `json.Unmarshal(input, &dec)` / `Decode(&v)` writes
        # the untrusted value INTO the pointee, so `dec` / `v` is untrusted even though it
        # is never an assignment RHS.
        if _DECODE_CALL.search(line):
            for pm in re.finditer(r"&\s*(?:mut\s+)?([A-Za-z_]\w*)", line):
                if pm.group(1) not in recv_set:
                    tainted.add(pm.group(1))
        mm = _ASSIGN.match(line)
        if not mm:
            continue
        name, rhs = mm.group(1), mm.group(2)
        if name in recv_set:
            continue
        if _DECODE_CALL.search(rhs):
            tainted.add(name)
        assigns.append((name, rhs))
    changed = True
    guard = 0
    while changed and guard < 8:
        changed = False
        guard += 1
        for name, rhs in assigns:
            if name in tainted:
                continue
            rhs_ids = re.findall(r"[A-Za-z_]\w*", rhs)
            if (any(t in tainted for t in rhs_ids)
                    or _DECODE_CALL.search(rhs)):
                tainted.add(name)
                changed = True
    return tainted, recv_set


def _operand_tainted(operand, tainted, recv_set):
    """True iff the cast operand's provenance reaches a GENUINE untrusted-input boundary:
    a decode/deserialize/wire-read call, a `len(<untrusted>)`, or a tainted local that
    traces back to a wire buffer / decode. A bare `len()` of internal state, a common
    provenance noun, a receiver/self field read, or a numeric literal is NOT untrusted -
    that indiscriminate join was the enumerator false-positive engine."""
    op = operand.strip()
    if not op:
        return False, None
    if re.fullmatch(r"[-+]?\s*(0x[0-9a-fA-F]+|\d+)", op):
        return False, None            # literal -> value already known-fits
    if _DECODE_CALL.search(op):
        return True, "decode-boundary"
    ids = re.findall(r"[A-Za-z_]\w*", op)
    # a bare receiver/self field read (`self.x`, `b[2]`) is internal state, not untrusted
    non_recv = [t for t in ids if t not in recv_set]
    # `len(<untrusted>)` is an untrusted length; `len(<internal>)` is NOT
    if _LEN_CALL.search(op) and any(t in tainted for t in non_recv):
        return True, "length"
    for t in non_recv:
        if t in tainted:
            return True, f"untrusted:{t}"
    return False, None


# target repr WIDTH in bits (the narrower storage the value must fit into)
_TARGET_BITS = {
    "uint8": 8, "int8": 8, "byte": 8, "u8": 8, "i8": 8,
    "uint16": 16, "int16": 16, "u16": 16, "i16": 16, "rune": 32,
    "uint32": 32, "int32": 32, "u32": 32, "i32": 32,
}
_MASK_RE = re.compile(r"&\s*(0x[0-9a-fA-F]+|\d+)")


def _bitmask_fits(operand, target):
    """(A)(b) A BITMASK guard whose mask width proves the value FITS the narrower target
    repr. `x & 0x7` / `1 << (h & 0x7)` -> the masked result never exceeds the mask, so if
    the mask's bit-width is <= the target width the narrowing is lossless (`& 0x7`, `& 0xff`
    for a byte; `& 0xffff` for a u16). Returns a guard-line string or None."""
    tbits = _TARGET_BITS.get(target)
    if not tbits:
        return None
    for m in _MASK_RE.finditer(operand):
        tok = m.group(1)
        try:
            val = int(tok, 16) if tok.lower().startswith("0x") else int(tok)
        except ValueError:
            continue
        if val > 0 and val.bit_length() <= tbits:
            return f"bitmask {m.group(0).strip()} fits {target} ({val.bit_length()}<={tbits} bits)"
    return None


def _aggregate_summand_bound(lines, operand):
    """(A)(a) A transitive AGGREGATE bound: a repr-bound comparison on an aggregate value
    (`total > math.MaxUint32 -> reject`) of which the operand is a proven NON-NEGATIVE
    SUMMAND (`total := uint64(a) + operand + c`). Since every summand is <= the (unsigned,
    subtraction-free) total and the total is bounded, each addend is itself bounded, so its
    narrowing is lossless. Returns a guard-line string or None."""
    op = operand.strip()
    if not re.fullmatch(r"[A-Za-z_]\w*", op):
        return None                       # only a simple identifier can be a summand
    for line in lines:
        mm = _ASSIGN.match(line)
        if not mm:
            continue
        lhs, rhs = mm.group(1), mm.group(2)
        if lhs == op or "+" not in rhs:
            continue
        if "-" in rhs:
            continue                      # subtraction -> a term may exceed the total
        terms = re.split(r"\+", rhs)
        if not any(re.search(r"\b" + re.escape(op) + r"\b", t) for t in terms):
            continue                      # operand is not an additive term of this sum
        # is the aggregate `lhs` itself repr-bound-compared anywhere in the prefix?
        for l2 in lines:
            if (re.search(r"\b" + re.escape(lhs) + r"\b", l2)
                    and _CMP.search(l2) and _BOUND_TOKEN.search(l2)):
                return f"aggregate-bound via `{lhs}`: {l2.strip()}"
    return None


def _dominating_bound(prefix_text, operand, target=None):
    """Is there a DOMINATING bounds check on the operand before the cast? True iff:
      - a direct comparison references an operand id AND a repr-bound token, or a
        checked/fallible conversion of the operand; OR
      - (A)(b) the operand carries a BITMASK that fits the target repr; OR
      - (A)(a) the operand is a proven non-negative SUMMAND of a repr-bounded aggregate.
    Linear-prefix dominance is a sound-toward-SILENCE approximation (advisory: errs toward
    not-firing)."""
    op_ids = [t for t in re.findall(r"[A-Za-z_]\w*", operand)
              if len(t) > 1 and t not in ("len",)]
    op_core = operand.strip()
    lines = prefix_text.split("\n")
    # (A)(b) bitmask fit is self-contained in the operand text
    mb = _bitmask_fits(operand, target)
    if mb:
        return True, mb
    for line in lines:
        refs_operand = (op_core and op_core in line) or any(
            re.search(r"\b" + re.escape(t) + r"\b", line) for t in op_ids)
        if not refs_operand:
            continue
        if _CHECKED_CONV.search(line):
            return True, line.strip()
        if _CMP.search(line) and _BOUND_TOKEN.search(line):
            return True, line.strip()
    # (A)(a) transitive aggregate-summand bound
    agg = _aggregate_summand_bound(lines, operand)
    if agg:
        return True, agg
    return False, None


def _stable_id(rel, fn, line, target):
    h = hashlib.sha1()
    h.update(f"{rel}|{fn}|{line}|{target}".encode())
    return h.hexdigest()[:16]


def _cast_sites(body_text, lang):
    """Yield (target_type, operand, char_offset_of_cast) for every narrowing cast."""
    if lang == "go":
        for m in _GO_CAST.finditer(body_text):
            target = m.group(1)
            inner, _ = _balanced_group(body_text, m.end() - 1)
            if inner is None:
                continue
            yield target, inner.strip(), m.start()
    else:
        for m in _RS_CAST.finditer(body_text):
            target = m.group(1)
            operand = _rust_left_operand(body_text, m.start())
            yield target, operand.strip(), m.start()


def _rust_left_operand(s, as_idx):
    """The expression immediately left of a Rust `as` at s[as_idx]. Walks left keeping
    `(...)`/`[...]` balanced and `.` method-chains intact, stopping at a top-level
    boundary (operator / unmatched open / separator / whitespace-before-operator)."""
    i = as_idx - 1
    while i >= 0 and s[i] == " ":
        i -= 1
    depth = 0
    end = i
    while i >= 0:
        c = s[i]
        if c in ")]":
            depth += 1
        elif c in "([":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and (c in "=;{}+*/%<>&|!?:," or c == " "):
            break
        i -= 1
    return s[i + 1:end + 1]


_LHS_OF = re.compile(
    r"^\s*(?:let\s+(?:mut\s+)?|var\s+)?([\w.\[\]]+)\s*(?::[^=;{]+)?\s*(?::=|=(?!=))")


def _line_at(body_text, off):
    """The source line containing char-offset `off`."""
    start = body_text.rfind("\n", 0, off) + 1
    end = body_text.find("\n", off)
    return body_text[start:] if end == -1 else body_text[start:end]


def _sink_is_sensitive(body_text, off, operand):
    """(B)(ii) Does the narrowed value feed a SECURITY-SENSITIVE sink? True iff:
      - the assignment LHS (var/field the cast result is bound to) names a size/index/
        identity noun (`id.LogIndex`, `ilen`, `chainId`), OR the operand itself is an
        identity value (`msg.chainId`, `amount`); OR
      - the cast's line is a structural sink (`make(n)`, `with_capacity`, a slice index,
        a loop bound); OR
      - the bound LHS var is later used as an index / allocation size / loop bound.
    A benign log / display / metric destination returns False. Returns (bool, why)."""
    line = _line_at(body_text, off)
    lm = _LHS_OF.match(line)
    lhs = lm.group(1) if lm else None
    # a size/index/identity noun NAMING the destination (assignment LHS)
    if lhs and _seg_hits(lhs, _SINK_SEG):
        return True, "sink-noun:lhs"
    # an identity / positional-index noun naming the VALUE itself (the operand). A bare
    # magnitude (`len`/`size`/`count`) on the operand does NOT count - it needs a sink.
    if operand and _seg_hits(operand, _SINK_OPERAND):
        return True, "sink-noun:operand"
    # structural sink on the cast's own line (alloc size / index expression / loop bound)
    if _STRUCT_SINK.search(line):
        return True, "sink-alloc"
    if re.search(r"\[[^\]]*(?:uint\d+|int\d+|byte|rune|as\s+[ui]\d+)", line):
        return True, "sink-index"           # cast used inside a `[...]` index
    if re.match(r"\s*for\b", line):
        return True, "sink-loop-bound"
    # transitive: the bound var is later used as an index / alloc size / loop bound
    if lhs and re.fullmatch(r"\w+", lhs):
        after = body_text[off + len(line):]
        pat = re.escape(lhs)
        if (re.search(r"\[[^\]]*\b" + pat + r"\b", after)
                or re.search(r"(?:make|with_capacity|reserve|alloc)\s*\([^)]*\b" + pat + r"\b", after)
                or re.search(r"\bfor\b[^\n]*\b" + pat + r"\b", after)):
            return True, "sink-transitive"
    return False, None


def scan_file(path: Path, rel: str, file_text: str = None):
    """Return candidate narrowing-cast rows (tainted operand + narrowing target) for one
    .go/.rs file, each with a `fires` bool. A row FIRES iff its untrusted operand has NO
    dominating bound AND the narrowed value feeds a security-sensitive sink."""
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    lang = "go" if rel.endswith(".go") else "rust"
    text = _mask_comments(raw, lang)
    lines = text.split("\n")
    rows = []
    for fn, start_idx, body, params, recv, untrusted in _fn_units(lines, lang):
        body_text = "\n".join(body)
        tainted, recv_set = _taint_set(body, params, recv, untrusted)
        for target, operand, off in _cast_sites(body_text, lang):
            ok, prov = _operand_tainted(operand, tainted, recv_set)
            if not ok:
                continue
            prefix = body_text[:off]
            bounded, guard_line = _dominating_bound(prefix, operand, target)
            sink_sensitive, sink = _sink_is_sensitive(body_text, off, operand)
            fires = (not bounded) and sink_sensitive
            line_no = start_idx + body_text[:off].count("\n") + 1
            rows.append({
                "schema": HYP_SCHEMA,
                "capability": CAPABILITY,
                "id": _stable_id(rel, fn, line_no, target),
                "file": rel,
                "function": fn,
                "line": line_no,
                "lang": lang,
                "target_type": target,
                "operand": operand[:120],
                "provenance": prov,
                "dominating_bound": bounded,
                "guard_line": guard_line,
                "sink_sensitive": sink_sensitive,
                "sink": sink,
                "fires": fires,
                # advisory-first contract (never auto-credit, never fail-close)
                "verdict": "needs-fuzz",
                "advisory": True,
                "auto_credit": False,
                "question": (
                    f"`{fn}` narrows `{operand[:60]}` to `{target}` (provenance: {prov}). "
                    f"Is the operand proven to FIT `{target}` by a dominating bounds check "
                    f"before the cast, or can an attacker at the untrusted boundary supply a "
                    f"value that silently truncates / sign-flips the "
                    f"length/index/id/amount/chain-id?"),
            })
    return rows


def scan_tree(root: Path):
    rows = []
    for p in _iter_source_files(root):
        try:
            rel = str(p.relative_to(root))
        except ValueError:
            rel = str(p)
        try:
            rows.extend(scan_file(p, rel))
        except Exception:
            continue
    return rows


def _emit_sidecar(ws: Path, rows):
    """Emit ONLY the firing hypotheses (needs-fuzz rows) to the sidecar."""
    outdir = ws / ".auditooor"
    outdir.mkdir(parents=True, exist_ok=True)
    out = outdir / _SIDE_NAME
    fired = [r for r in rows if r.get("fires")]
    with out.open("w") as fh:
        for r in fired:
            fh.write(json.dumps(r) + "\n")
    return out, fired


def _summary(rows):
    fired = [r for r in rows if r.get("fires")]
    return {
        "schema": HYP_SCHEMA,
        "capability": CAPABILITY,
        "candidates": len(rows),
        "fired": len(fired),
        "bounded_silent": sum(1 for r in rows if r.get("dominating_bound")),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def _resolve_ws(arg):
    ws = Path(arg)
    if not ws.is_absolute():
        cand = Path("/Users/wolf/audits") / arg
        if cand.exists():
            ws = cand
    return ws


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="MQ-B05 lossy fixed-width narrowing-cast screen (advisory)")
    ap.add_argument("--workspace", "--ws")
    ap.add_argument("--source")
    ap.add_argument("--file")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    strict = args.strict or os.environ.get(_STRICT_ENV, "").strip() not in ("", "0", "false")

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

    ws = _resolve_ws(args.workspace)
    side = ws / ".auditooor" / _SIDE_NAME

    if args.check:
        rows = []
        if side.exists():
            rows = [json.loads(l) for l in side.read_text().splitlines() if l.strip()]
        summ = {
            "schema": HYP_SCHEMA, "capability": CAPABILITY,
            "fired": len(rows), "source": "sidecar",
            "verdict": "needs-fuzz" if rows else "clean-advisory",
            "advisory": True, "auto_credit": False,
        }
        print(json.dumps(summ, indent=2))
        return 1 if (strict and rows) else 0

    src = ws / "src"
    root = src if src.exists() else ws
    rows = scan_tree(root)
    _emit_sidecar(ws, rows)
    summ = _summary(rows)
    print(json.dumps(summ, indent=2))
    # ADVISORY-FIRST: default exit 0; strict elevates only when an un-bounded narrowing exists
    return 1 if (strict and summ["fired"]) else 0


if __name__ == "__main__":
    sys.exit(main())
