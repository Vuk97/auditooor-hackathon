#!/usr/bin/env python3
"""guard-predicate-soundness-screen.py - the UNSOUND-HAND-ROLLED-GUARD-PREDICATE
screen (EXT08). The Cetus (May 2025, ~$223M) class.

GENERAL LOGIC / TRUST-ENFORCEMENT class (never a bug SHAPE). It instantiates the
north-star method ("A TRUSTED ENFORCEMENT is itself unsound") for the one delegated
safety property that no missing-guard detector owns: a hand-rolled safety guard
that IS PRESENT but whose PREDICATE does not match the dangerous operation it wraps.

  DELEGATED-TRUSTED INVARIANT : a hand-rolled "checked_"/"safe_" arithmetic-or-cast
    guard - checked_shlw/shl/mul/add, require(x <= type(uintN).max), a custom
    overflow mask (`if n > 0xffff...`), a bounds-check that gates a downcast/shift -
    is trusted to make the dangerous width-sensitive operation it wraps SOUND.
  PRIVATE INVARIANT           : the guard's predicate is the EXACT negation of the
    operation's failure condition - the mask/threshold's bit-width equals the type's
    real overflow point, and the guard DOMINATES the op on the path taken.
  ATTACK                      : the predicate is a LOOK-ALIKE bound - the mask/shift
    width != the type width, or the type-max threshold is WIDER than the cast/shift
    it protects - so an input exists that overflows/underflows/truncates the guarded
    operation while the predicate still evaluates as SAFE. Cetus: the integer-mate
    `checked_shlw` overflow guard used a wrong bound/mask, so a shift that DID
    overflow passed the check; a ~200-tick position + a 1-token deposit minted
    ~1e34 units of liquidity. The math library was OUT of audit scope.

This is NOT the "missing SafeMath / integer-overflow" detector, which assumes the
check is ABSENT; here the check is PRESENT but wrong, so scanners that look for a
missing guard see a guarded op and PASS. The enforcement itself is the bug: a
SOUNDNESS audit of the guard predicate.

Enforcement points = every width-sensitive dangerous op (a downcast `uintW(x)` /
`x as uW`, or a literal left-shift `x << s`) that carries a same-operand BIT-WIDTH
boundary guard (`type(uintB).max`, `uB::MAX`, an all-F hex mask, `1<<k`). The screen
answers per point:
  {op_kind, op_width, guard_bound_width, boundary_kind, comparator, operand,
   dominance, in_math_library}
and flags (WARN, verdict=needs-fuzz) ONLY when the guard DOMINATES the op on the same
operand AND the guard's boundary bit-width is STRICTLY WIDER than the op's real
overflow width (B > W_op) - i.e. the guard is too permissive and admits an input
that overflows/truncates the operation (the Cetus signature). A guard that is
sound (B <= W_op) is emitted as a documented enforcement point with fires=False;
a guard that exists but does NOT dominate the op on its path is a dominance-gap
advisory (fires=False). Because the mismatch is computed from BIT-WIDTHS of type-max
/ pow-2 / all-F boundary constants, an ordinary business cap (`require(x <= 1e24)`)
carries no bit-width boundary and is never a row - no FP-spray.

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False. It NEVER auto-credits and NEVER fail-closes in default mode; the
opt-in env AUDITOOOR_GUARD_PREDICATE_STRICT (or --strict) only raises the exit code
when a fired (B>W) point exists.

Language-general: Solidity (.sol), Go (.go), Rust (.rs), Move (.move). Silent on
other trees.

Usage:
  --workspace <ws>   scan <ws>/src -> .auditooor/guard_predicate_soundness_hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON (NO sidecar)
  --file <f>         scan a single file, print rows as JSON
  --check            re-read the emitted sidecar, print cert verdict (advisory)
  --strict           (or env) elevate exit code when a B>W mismatch fired
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

HYP_SCHEMA = "auditooor.guard_predicate_soundness_hypotheses.v1"
_SIDE_NAME = "guard_predicate_soundness_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_GUARD_PREDICATE_STRICT"
_CAPABILITY = "EXT08"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmarks", "script", "scripts", "deployments",
              "prior_audits", "reference", "audits", "docs"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|test_fixtures|mock|mocks|benches|benchmarks?|examples|fixtures)(/|$)")

# a source path whose LAST directory segment looks like a shared math / fixed-point
# library. Marks a guard as "owned by a trusted math library" (the Cetus residue:
# integer-mate was EXCLUDED from audit scope) - a metadata amplifier, never a
# fire-gate on its own.
_MATH_LIB_HINT = re.compile(
    r"(math|fixed[_-]?point|full[_-]?math|integer[_-]?mate|safe[_-]?cast|"
    r"wad|ray|q64|fixedpoint|u256|bit[_-]?math|tick[_-]?math|sqrt[_-]?price)",
    re.I)

# --- machine-generated exclusion (copied from declared-control-mutator-completeness-screen.py) ---
_GENERATED_SUFFIXES = (
    ".pb.go", ".pulsar.go", ".pb.gw.go", "_gen.go", ".gen.go", "_generated.go",
)
_GENERATED_SENTINEL = re.compile(r"Code generated .{0,80}?DO NOT EDIT", re.I)


def _is_generated_source(path: Path) -> bool:
    if path.name.lower().endswith(_GENERATED_SUFFIXES):
        return True
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096)
    except (OSError, UnicodeError):
        return False
    return bool(_GENERATED_SENTINEL.search(head))


_SRC_EXT = (".sol", ".go", ".rs", ".move")


def _iter_source_files(root: Path):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        if _TEST_HINT.search(dp.replace(os.sep, "/")):
            continue
        for f in fn:
            low = f.lower()
            if not low.endswith(_SRC_EXT):
                continue
            if low.endswith("_test.go") or low.endswith(".t.sol") \
                    or low.endswith("_test.rs") or low.endswith("_tests.rs"):
                continue
            if _TEST_HINT.search(f):
                continue
            p = Path(dp) / f
            if _is_generated_source(p):
                continue
            yield p


# --- comment / string masking (preserves line offsets) ----------------------
def _mask_comments(text: str) -> str:
    out = []
    i, n = 0, len(text)
    in_line = in_block = in_str = False
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


# --- function extraction (brace-matched; Solidity/Go/Rust/Move) -------------
_FN_DECL_RE = re.compile(
    r"^\s*(?:"
    r"(?:pub\s+|pub\([^)]*\)\s+)?(?:async\s+|unsafe\s+|const\s+)*fn\s+([A-Za-z_]\w*)"  # Rust fn
    r"|(?:public\s+|entry\s+|native\s+)*fun\s+([A-Za-z_]\w*)"          # Move fun
    r"|function\s+([A-Za-z_]\w*)"                                      # Solidity function
    r"|(constructor)\b"                                                # Solidity constructor
    r"|(fallback|receive)\s*\("                                       # Solidity fallback/receive
    r"|func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)"                        # Go func (recv) Foo
    r")")


def _fn_name(m):
    return (m.group(1) or m.group(2) or m.group(3) or m.group(4)
            or m.group(5) or m.group(6))


def _functions(lines):
    """Yield (name, decl_idx, sig_text, [(abs_idx, line), ...]) for each fn body."""
    i, n = 0, len(lines)
    while i < n:
        m = _FN_DECL_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = _fn_name(m) or "<anon>"
        depth = 0
        started = False
        body = []
        sig_parts = []
        j = i
        seen_brace = False
        while j < n:
            line = lines[j]
            if not seen_brace:
                sig_parts.append(line)
                if "{" in line:
                    seen_brace = True
            depth += line.count("{") - line.count("}")
            body.append((j, line))
            if "{" in line:
                started = True
            if started and depth <= 0:
                break
            j += 1
        yield name, i, "\n".join(sig_parts), body
        i = max(j, i + 1)


# --- bit-width boundary constant parsing (CORE #1) --------------------------
# Each returns an int bit-width B: the smallest number of bits that holds every
# value the boundary admits, i.e. the type width a SOUND downstream op must have.

_TYPE_MAX_RE = re.compile(r"type\s*\(\s*(u?int)(\d*)\s*\)\s*\.\s*max", re.I)
_RUST_MAX_RE = re.compile(r"\b(u|i)(\d+)::MAX\b")
_GO_MAX_RE = re.compile(r"\b(?:math\s*\.\s*)?Max(Uint|Int)(\d+)\b")
_HEXF_RE = re.compile(r"0x([fF]{2,})(?:\s*<<\s*(\d+))?")
_POW2_RE = re.compile(r"\b(?:1|2)\s*(?:<<|\*\*)\s*(\d+)\b")


def _boundary_bits(expr: str):
    """Given one side of a comparison, return (bits, kind) for a BIT-WIDTH boundary
    constant, else None. `bits` = # of bits a value satisfying the boundary can
    occupy (the width a sound op guarding against it must carry)."""
    m = _TYPE_MAX_RE.search(expr)
    if m:
        width = int(m.group(2)) if m.group(2) else 256
        if m.group(1).lower() == "int":       # signed max = 2^(w-1)-1
            return width - 1, "type_max"
        return width, "type_max"
    m = _RUST_MAX_RE.search(expr)
    if m:
        width = int(m.group(2))
        return (width - 1 if m.group(1) == "i" else width), "rust_max"
    m = _GO_MAX_RE.search(expr)
    if m:
        width = int(m.group(2))
        return (width - 1 if m.group(1) == "Int" else width), "go_max"
    m = _HEXF_RE.search(expr)
    if m:
        bits = 4 * len(m.group(1))
        if m.group(2):
            bits += int(m.group(2))   # `0xffff... << k` raises the top bit
        return bits, "hex_mask"
    m = _POW2_RE.search(expr)
    if m:
        # `x < (1 << k)` / `x <= 2**k - 1` admits values that fit in k bits.
        return int(m.group(1)), "pow2"
    return None


# --- guard extraction (CORE #2) ---------------------------------------------
_GUARD_CTX_RE = re.compile(
    r"\b(require|assert|assert_eq|ensure|abort|revert|if|debug_assert)\b")
_RELOP_RE = re.compile(r"(<=|>=|==|!=|<|>)")
_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_KEYWORDS = {"require", "assert", "if", "for", "while", "return", "revert",
             "true", "false", "type", "max", "min", "uint256", "int256",
             "uint128", "uint", "int", "let", "mut", "self", "math", "abort",
             "ensure", "u256", "u128", "u64", "u32", "u16", "u8", "i256",
             "i128", "i64", "i32", "as", "MAX", "MIN"}


def _primary_operand(expr: str) -> str:
    """The primary guarded operand on the non-constant side of a comparison: the
    final segment of the longest member/index chain, else the last non-keyword
    identifier."""
    chains = re.findall(r"[A-Za-z_]\w*(?:\s*[.\[][\w\]]*)*", expr)
    best = ""
    for ch in chains:
        base = re.sub(r"\[[^\]]*\]", "", ch).split(".")[-1].strip()
        if base and base.lower() not in _KEYWORDS and not base.isdigit():
            best = base
    return best


# a local assignment of a bit-width boundary literal to a variable, so a guard that
# compares against the VARIABLE (`let mask = 0xffff..; require(n <= mask)`, the real
# Cetus shape) is still recognised.
_LOCAL_ASSIGN_RE = re.compile(
    r"(?:^|[;{])\s*(?:let\s+(?:mut\s+)?|var\s+|const\s+|uint\d*\s+|int\d*\s+)?"
    r"([A-Za-z_]\w*)\s*(?::\s*[\w<>]+\s*)?=\s*([^;{}]+)")


def _local_boundaries(body):
    """Map a local variable -> (bits, kind) when it is assigned a bit-width boundary
    literal in this function body (constant propagation for the guard side)."""
    out = {}
    for _idx, line in body:
        if _GUARD_CTX_RE.search(line):
            continue  # an assignment, not a comparison
        for m in _LOCAL_ASSIGN_RE.finditer(line):
            name, rhs = m.group(1), m.group(2)
            b = _boundary_bits(rhs)
            if b:
                out[name] = b
    return out


def _side_boundary(expr: str, local_bounds):
    """Effective boundary bits/kind for one side of a comparison: an inline
    constant, else a bare variable resolved via local_bounds."""
    b = _boundary_bits(expr)
    if b:
        return b
    ids = [i.group(0) for i in _IDENT_RE.finditer(expr)]
    if len(ids) == 1 and ids[0] in local_bounds:
        return local_bounds[ids[0]]
    return None


def _guards_in_body(body, local_bounds=None):
    """Yield (abs_idx, operand, bound_bits, boundary_kind, comparator) for every
    bit-width boundary guard on a line that sits in a require/assert/if/revert
    context."""
    local_bounds = local_bounds or {}
    for abs_idx, line in body:
        if not _GUARD_CTX_RE.search(line):
            continue
        parts = _RELOP_RE.split(line)
        k = 1
        while k < len(parts) - 1:
            left = parts[k - 1]
            comp = parts[k]
            right = parts[k + 1]
            lb = _side_boundary(left, local_bounds)
            rb = _side_boundary(right, local_bounds)
            if bool(lb) ^ bool(rb):       # exactly one side is a bit-width boundary
                if lb:
                    bits, kind = lb
                    operand = _primary_operand(right)
                else:
                    bits, kind = rb
                    operand = _primary_operand(left)
                if operand:
                    yield abs_idx, operand, bits, kind, comp
            k += 2


# --- width-sensitive op extraction (CORE #3) --------------------------------
# a downcast: Solidity/Go `uintW(inner)` / `intW(inner)`; Rust/Move `expr as uW`.
_SOL_CAST_RE = re.compile(r"\b(u?int)(\d+)\s*\(")
_RUST_CAST_RE = re.compile(r"([A-Za-z_][\w.\[\]]*)\s+as\s+(u|i)(\d+)\b")
# a literal left-shift: `operand << s`
_SHIFT_RE = re.compile(r"([A-Za-z_][\w.\[\]]*)\s*<<\s*(\d+)\b")


def _balanced_paren(text: str, open_idx: int):
    """Return the substring inside the parens starting at open_idx ('('),
    balanced. open_idx must point at '('."""
    depth = 0
    for k in range(open_idx, len(text)):
        if text[k] == "(":
            depth += 1
        elif text[k] == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:k]
    return text[open_idx + 1:]


def _cast_ops_in_line(line: str):
    """Yield (op_kind, op_width, operands:set, inner_text) for each downcast on a line.
    inner_text is the EXACT expression fed to the cast (the balanced-paren body for a
    Solidity/Go `uintW(...)`, the base expr for a Rust/Move `expr as uW`) so a
    value-narrowing op applied to the operand INSIDE the cast can be inspected."""
    # Solidity / Go numeric casts uintW(...) / intW(...)
    for m in _SOL_CAST_RE.finditer(line):
        width = int(m.group(2))
        inner = _balanced_paren(line, m.end() - 1)
        operands = {i.group(0) for i in _IDENT_RE.finditer(inner)}
        yield "cast", width, operands, inner
    # Rust / Move `expr as uW`
    for m in _RUST_CAST_RE.finditer(line):
        width = int(m.group(3))
        raw = m.group(1)
        base = re.sub(r"\[[^\]]*\]", "", raw).split(".")[-1]
        yield "cast", width, {base}, raw


def _shift_ops_in_line(line: str, result_width_default: int):
    """Yield (op_kind, op_overflow_width, operands:set, context_text) for each literal
    left-shift. op_overflow_width = W_result - s: the max bit-width the operand may
    hold before `operand << s` overflows the W_result-bit result. Result width = an
    enclosing numeric cast if present, else the language default. context_text = the
    line so a narrowing op applied to the shift operand can be inspected."""
    for m in _SHIFT_RE.finditer(line):
        base = re.sub(r"\[[^\]]*\]", "", m.group(1)).split(".")[-1]
        s = int(m.group(2))
        w_result = result_width_default
        # an enclosing cast `uintW( ... << s ... )` pins the true result width.
        prefix = line[:m.start()]
        cm = None
        for c in _SOL_CAST_RE.finditer(prefix):
            cm = c
        if cm:
            w_result = int(cm.group(2))
        w_op = w_result - s
        if w_op <= 0:
            continue
        yield "shift", w_op, {base}, line


# --- inner-narrowing suppression (precision fix for EXT08) -------------------
# The op<->guard match is by BARE operand identity; a value-narrowing op applied to
# the operand INSIDE the cast (or before the shift) - `x & MASK`, `x >> k`, `x % n` -
# provably caps the value below the guard's admitted width, so a WIDER guard is still
# SOUND (`uint128(x & type(uint128).max)`, `uint128(x >> 128)`,
# `uint64(amount & 0xffff...ff)`). Without this, those common sub-field-extract /
# storage-packing idioms fire falsely.
def _modulus_bits(rhs: str):
    """Bit-width an `x % rhs` result can occupy: `2**k` / `1<<k` -> k bits; an all-F
    hex mask -> its width; a plain literal n -> n's bit-width (result < n)."""
    b = _boundary_bits(rhs)
    if b:
        return b[0]
    m = re.match(r"\s*(\d+)", rhs)
    if m:
        n = int(m.group(1))
        return 0 if n <= 1 else (n - 1).bit_length()
    return None


def _narrowed_effective_width(context, operand, input_bits, local_bounds=None):
    """Effective max bit-width of `operand` after a value-narrowing op applied to it
    within `context`, or None if no narrowing op targets the operand.
      `operand & <mask>` / `<mask> & operand` -> min(input_bits, mask bit-width)
      `operand >> k`                          -> input_bits - k
      `operand % <n>`                         -> n's bit-width
    `input_bits` = the operand's pre-narrow width (the dominating guard's bound width).
    A narrowed width <= the op width makes the guarded downcast/shift SOUND -> no fire.
    """
    local_bounds = local_bounds or {}
    op = re.escape(operand)
    best = None

    def _consider(w):
        nonlocal best
        if w is None:
            return
        w = max(int(w), 0)
        best = w if best is None else min(best, w)

    # x & <mask>  or  <mask> & x  -> capped at the mask's bit-width
    if re.search(rf"\b{op}\b\s*&", context) or re.search(rf"&\s*\b{op}\b", context):
        mb = _side_boundary(context, local_bounds)
        if mb:
            _consider(min(input_bits, mb[0]))
    # x >> k  -> right-shift zeroes the top k bits: value fits in input_bits - k bits
    for m in re.finditer(rf"\b{op}\b\s*>>\s*(\d+)", context):
        _consider(input_bits - int(m.group(1)))
    # x % <n> -> result < n, fits in n's bit-width
    for m in re.finditer(rf"\b{op}\b\s*%\s*([^\s,;)]+)", context):
        _consider(_modulus_bits(m.group(1)))
    return best


# --- CORE PREDICATE (load-bearing; monkeypatched in the non-vacuity test) ----
def _is_permissive_mismatch(guard_bound_width: int, op_width: int) -> bool:
    """SOUND iff the guard's admitted values (bound_width bits) all fit in the op's
    real overflow width. UNSOUND (fires) iff the guard is STRICTLY WIDER than the op
    - it admits an input that overflows/truncates the operation (the Cetus
    signature). A stricter guard (bound_width <= op_width) is safe and never fires."""
    return guard_bound_width > op_width


def _lang_of(rel: str) -> str:
    low = rel.lower()
    if low.endswith(".go"):
        return "go"
    if low.endswith(".rs"):
        return "rust"
    if low.endswith(".move"):
        return "move"
    return "solidity"


def _default_result_width(lang: str) -> int:
    # Solidity/Move default machine word is 256; Rust/Go shifts default to 64 unless
    # an enclosing cast pins a wider result (handled in _shift_ops_in_line).
    return 256 if lang in ("solidity", "move") else 64


def _stable_id(rel, fn, operand, line, kind):
    h = hashlib.sha1()
    h.update(f"{rel}|{fn}|{operand}|{line}|{kind}".encode())
    return h.hexdigest()[:16]


def scan_file(path: Path, rel: str, file_text: str = None):
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    text = _mask_comments(raw)
    lang = _lang_of(rel)
    in_math_lib = bool(_MATH_LIB_HINT.search(Path(rel).stem)) \
        or bool(_MATH_LIB_HINT.search(str(Path(rel).parent)))
    result_default = _default_result_width(lang)
    lines = text.split("\n")
    rows = []

    for name, _decl, _sig, body in _functions(lines):
        # per-operand list of dominating guards: operand -> [(idx, bits, kind, comp)]
        local_bounds = _local_boundaries(body)
        guards = {}
        for gidx, operand, bits, kind, comp in _guards_in_body(body, local_bounds):
            guards.setdefault(operand, []).append((gidx, bits, kind, comp))
        if not guards:
            continue  # no bit-width boundary guard -> not this class (present-but-wrong)

        seen = set()
        for abs_idx, line in body:
            ops = list(_cast_ops_in_line(line)) + \
                list(_shift_ops_in_line(line, result_default))
            for op_kind, op_width, operands, op_context in ops:
                # match the op to a same-operand bit-width guard
                matched_operand = None
                for cand in operands:
                    if cand in guards:
                        matched_operand = cand
                        break
                if not matched_operand:
                    continue
                key = (op_kind, matched_operand, abs_idx, op_width)
                if key in seen:
                    continue
                seen.add(key)
                gl = guards[matched_operand]
                # nearest guard that DOMINATES the op (earlier line, same fn body)
                dominating = [g for g in gl if g[0] <= abs_idx]
                if dominating:
                    gidx, gbits, gkind, gcomp = max(dominating, key=lambda g: g[0])
                    dominance = "dominates"
                else:
                    # a guard exists for this operand but only AFTER / on a sibling
                    # path -> path-incompleteness (does not dominate the op).
                    gidx, gbits, gkind, gcomp = min(gl, key=lambda g: g[0])
                    dominance = "gap"
                fires = (dominance == "dominates"
                         and _is_permissive_mismatch(gbits, op_width))
                # a value-narrowing op (mask / shift / modulus) applied to the operand
                # INSIDE the op provably caps it below the guard's admitted width, so a
                # WIDER guard is still sound - do not fire (Cetus requires a RAW op).
                narrowed_sound = False
                if fires:
                    eff = _narrowed_effective_width(
                        op_context, matched_operand, gbits, local_bounds)
                    if eff is not None and eff <= op_width:
                        fires = False
                        narrowed_sound = True
                rows.append(_row(
                    rel, name, matched_operand, abs_idx, gidx, lang, op_kind,
                    op_width, gbits, gkind, gcomp, dominance, in_math_lib, fires,
                    narrowed_sound=narrowed_sound))
    return rows


def _row(rel, name, operand, op_idx, guard_idx, lang, op_kind, op_width,
         bound_width, boundary_kind, comparator, dominance, in_math_lib, fires,
         narrowed_sound=False):
    if fires:
        q = (f"guard for `{operand}` bounds it to {bound_width} bits "
             f"(`{boundary_kind}`) but the {op_kind} at line {op_idx + 1} only "
             f"tolerates {op_width} bits - the predicate is WIDER than the operation "
             f"it protects, so an input with {op_width + 1}..{bound_width} significant "
             f"bits passes the check yet overflows/truncates the {op_kind}. Fuzz "
             f"`{operand}` at the 2^{op_width} boundary "
             f"{'(math-library-owned guard - may be OUT of audit scope, Cetus residue)' if in_math_lib else ''}.")
    elif dominance == "gap":
        q = (f"`{operand}` has a {bound_width}-bit boundary guard but it does NOT "
             f"dominate the {op_kind} at line {op_idx + 1} on this path - can the op "
             f"be reached on a branch the guard skips (guard does not dominate)?")
    elif narrowed_sound:
        q = (f"enforcement point: the {bound_width}-bit guard on `{operand}` is WIDER "
             f"than the {op_width}-bit {op_kind}, but a value-narrowing op (mask/shift/"
             f"modulus) applied to `{operand}` INSIDE the {op_kind} caps it to <= "
             f"{op_width} bits, so the downcast/shift is sound. Documented for "
             f"completeness (narrowed-sound).")
    else:
        q = (f"enforcement point: {bound_width}-bit `{boundary_kind}` guard dominates "
             f"a {op_width}-bit {op_kind} of `{operand}` - predicate matches the op "
             f"(sound). Documented for completeness.")
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "id": _stable_id(rel, name, operand, op_idx, op_kind),
        "file": rel,
        "line": op_idx + 1,
        "function": name,
        "lang": lang,
        "op_kind": op_kind,
        "op_width": op_width,
        "guard_line": guard_idx + 1,
        "guard_bound_width": bound_width,
        "boundary_kind": boundary_kind,
        "comparator": comparator,
        "operand": operand,
        "dominance": dominance,
        "in_math_library": in_math_lib,
        "narrowed_sound": narrowed_sound,
        "fires": fires,
        "verdict": "needs-fuzz",
        "advisory": True,
        "auto_credit": False,
        "question": q,
    }


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
    outdir = ws / ".auditooor"
    outdir.mkdir(parents=True, exist_ok=True)
    out = outdir / _SIDE_NAME
    with out.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    return out


def _summary(rows):
    fired = [r for r in rows if r.get("fires")]
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "enforcement_points": len(rows),
        "fired": len(fired),
        "cast_points": sum(1 for r in rows if r.get("op_kind") == "cast"),
        "shift_points": sum(1 for r in rows if r.get("op_kind") == "shift"),
        "dominance_gaps": sum(1 for r in rows if r.get("dominance") == "gap"),
        "math_library_points": sum(1 for r in rows if r.get("in_math_library")),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="EXT08 unsound-hand-rolled-guard-predicate screen (advisory)")
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
        return 1 if (strict and any(r["fires"] for r in rows)) else 0

    if args.source:
        rows = scan_tree(Path(args.source))
        print(json.dumps(rows, indent=2))
        return 1 if (strict and any(r["fires"] for r in rows)) else 0

    if not args.workspace:
        ap.error("one of --workspace / --source / --file is required")

    ws = Path(args.workspace)
    if not ws.is_absolute():
        cand = Path("/Users/wolf/audits") / args.workspace
        if cand.exists():
            ws = cand
    side = ws / ".auditooor" / _SIDE_NAME

    if args.check:
        rows = []
        if side.exists():
            rows = [json.loads(l) for l in side.read_text().splitlines() if l.strip()]
        summ = _summary(rows)
        summ["source"] = "sidecar"
        print(json.dumps(summ, indent=2))
        return 1 if (strict and summ["fired"]) else 0

    src = ws / "src"
    root = src if src.exists() else ws
    rows = scan_tree(root)
    _emit_sidecar(ws, rows)
    summ = _summary(rows)
    print(json.dumps(summ, indent=2))
    return 1 if (strict and summ["fired"]) else 0


if __name__ == "__main__":
    sys.exit(main())
