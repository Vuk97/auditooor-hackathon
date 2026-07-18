#!/usr/bin/env python3
"""width-narrowing-cast-screen.py - GEN-4C, the WIDTH-NARROWING CAST ON A
VALUE-BEARING OPERAND screen (layer = pattern-lift).

CROSS-LANG: Solidity (.sol), Rust (.rs), Go (.go), Move (.move). A GENERAL
advisory screen (never a specific bug-shape). This is the CROSS-LANGUAGE LIFT of
the EVM/Solidity-only Glider gap #2 (type-lattice / unsafe-downcast) oracle.

GENERAL LOGIC. A NARROWING integer cast (a WIDER repr -> a NARROWER repr) applied
to a VALUE-BEARING operand SILENTLY TRUNCATES the high bits. A large logical
amount / id / index / nonce / length wraps to a small in-range value with no
upstream visibility - VALUE CONFUSION (not a memory-safety bug): amount
under-transfer, id / nonce collision, index aliasing, length under-read. The cast
compiles and runs; the mathematical value is silently rewritten.

FIRES when a narrowing cast whose TARGET is provably narrower than the (default /
inferred) SOURCE repr is applied to an operand that carries a value-bearing hint
(amount / id / index / len / nonce / offset / decimals / chain-id / shares /
assets / balance / height / epoch / slot), OR the enclosing statement / fn does.

  Solidity : `uint64(x)` / `uint32(x)` / `uint128(x)` / `uint96(x)` / `int64(x)`
             ... any `uintN(` / `intN(` with N < 256 (the default width). The
             OZ `SafeCast.toUintN(x)` / `x.toUintN()` guarded form uses a `.toUint`
             /capital-`U` spelling and is NOT matched (case-sensitive) - it stays
             SILENT.
  Rust     : `x as u8|u16|u32|i8|i16|i32` (narrower than the word-width
             usize/u64/u128 source). `as usize` / `as u64` / `as u128` are
             word-width / widening on 64-bit fleet targets and are NOT flagged.
             A `x.try_into()` / `u32::try_from(x)` checked narrowing stays SILENT.
  Go       : `int32(x)` / `uint32(x)` / `uint16(x)` / `uint8(x)` / `int16(x)` /
             `int8(x)` / `byte(x)` / `rune(x)` (narrower than an int64/uint64
             source). Bare `int(` / `uint(` are the platform WORD width -> NOT
             narrowing, excluded.
  Move     : `(x as u8|u16|u32|u64|u128)` from a wider u128/u256 source.

FP-CONTROL (critical - a narrowing cast is common; sound forms stay SILENT):
  * The operand (or enclosing statement / fn) MUST carry a value-bearing hint;
    a bare loop index `i`, a display cast, a cast with no amount/id/len/nonce
    hint anywhere -> SILENT.
  * A MASKED operand (`x & 0xff` then cast) whose mask bit-width FITS the target
    repr -> SILENT (the value provably fits).
  * A CHECKED / fallible / safe conversion on the operand (`try_into` / `try_from`
    / `TryFrom` / `checked_` / `SafeCast` / `.toUint` / `.min(`) -> SILENT.
  * A DOMINATING bound check on the operand before the cast (a comparison against
    a repr-bound token - `type(uintN).max` / `math.MaxUint32` / `u32::MAX` /
    `1<<N` / a `0xff..` mask / a named MAX/LIMIT const) -> SILENT.
  * The SOURCE must be WIDER than the TARGET; a target at (or above) the default
    width (uint256 / usize / u64 / int / u256) is a widening or same-width cast and
    is NEVER matched.
  * Severity HIGH only when the value hint is IN THE OPERAND (the narrowed value
    is itself a logical amount/id); when the hint is only in the statement / fn
    name (value-bearingness UNCERTAIN) -> MEDIUM.

DEDUP (tool-duplication preflight, do-NOT #10 - cite):
  * Glider gap #2 `type-lattice / unsafe-downcast` (task_2c..b62 EVM oracle) is
    SINGLE-LANG (Solidity uint downcast only). GEN-4C LIFTS the concept to
    Rust / Go / Move and keys on a VALUE-BEARING hint cross-lang.
  * `narrowing-lossy-cast-screen` (MQ-B05) is the near-sibling: it fires ONLY when
    a Go/Rust narrowing operand traces to an UNTRUSTED WIRE BOUNDARY (a decode /
    `[]byte` param) reaching a size/index/identity sink, and covers ONLY <=32-bit
    targets in two langs. GEN-4C is DISTINCT: it fires on ANY value-bearing operand
    (a storage-read amount, a plain param) WITHOUT requiring wire provenance, adds
    the Solidity `uintN(` and Move `(x as uN)` arms MQ-B05 has no reach into, and
    covers the Solidity u64/u128 targets MQ-B05 excludes. A site that reduces to
    an MQ-B05 wire-taint Go/Rust narrowing is left to MQ-B05; GEN-4C's net-new is
    the Solidity/Move arms + the value-hint (non-wire) Go/Rust arm.
  * Distinct from GEN-R5 `release-silent-overflow-screen`: GEN-R5 flags a narrowing
    that WRAPS INTO A MEMORY-SAFETY sink (Vec::with_capacity / get_unchecked /
    ptr::add) = MEMORY unsafety. GEN-4C flags truncation of a LOGICAL VALUE (the
    amount/id itself is wrong) = value confusion, no memory sink required.

nuva has BOTH Go (cosmos) and EVM (Solidity) surface -> nuva-verify is IN SCOPE.

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False; exit 0 by default. The opt-in env
AUDITOOOR_WIDTH_NARROWING_CAST_STRICT (or --strict) raises the exit code when a
fired row exists. Excludes test / vendor / codegen via the shared exclusion libs.

Usage:
  --workspace <ws>   scan <ws>/src (or <ws>) -> .auditooor/
                     width_narrowing_cast_hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON (NO sidecar)
  --file <f>         scan a single .sol/.rs/.go/.move file, print rows as JSON
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

HYP_SCHEMA = "auditooor.width_narrowing_cast_hypotheses.v1"
_SIDE_NAME = "width_narrowing_cast_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_WIDTH_NARROWING_CAST_STRICT"
_CAPABILITY = "GEN_4C"

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
              "lib", "libs", "third_party", "node-modules",
              "chimera_harnesses"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|testutil|testonly|testhelper|test_fixtures|mock|mocks|"
    r"benches|benchmarks?|examples?|fixtures|simulation|testdata|poc|pocs|"
    r"chimera_harnesses)(/|$)")
_CODEGEN_SENTINEL = re.compile(r"Code generated .{0,80}?DO NOT EDIT", re.I)
_CODEGEN_SUFFIX = (".pb.go", ".pulsar.go", ".pb.gw.go", "_gen.go", ".gen.go",
                   "_generated.go", ".pb.validate.go")
_EXT_TO_LANG = {".sol": "solidity", ".rs": "rust", ".go": "go",
                ".move": "move"}


# ============================================================================
# Comment / string masking (length-preserving). Handles // and /* */ and
# "..." / '...' / `...` strings. Move/Sol/Go/Rust all fit this shape; Rust '
# lifetimes are handled by only treating ' as a string when it closes shortly.
# ============================================================================
def _mask(text: str) -> str:
    out = []
    i, n = 0, len(text)
    in_line = in_block = False
    in_str = False
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
            out.append("\n" if c == "\n" else " ")
            if c == "\\":
                out.append(" ")
                i += 2
                continue
            if c == quote:
                in_str = False
            i += 1
        elif c == '"' or c == "`":
            in_str = True
            quote = c
            out.append(" ")
            i += 1
        elif c == "'":
            close = text.find("'", i + 1, i + 5)
            if close != -1 and (close - i) <= 4:
                in_str = True
                quote = "'"
                out.append(" ")
                i += 1
            else:
                out.append(c)
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


def _excerpt(raw: str, off: int) -> str:
    ls = raw.rfind("\n", 0, off) + 1
    le = raw.find("\n", off)
    if le == -1:
        le = len(raw)
    return raw[ls:le].strip()[:200]


def _line_span(masked: str, off: int):
    ls = masked.rfind("\n", 0, off) + 1
    le = masked.find("\n", off)
    if le == -1:
        le = len(masked)
    return ls, le


def _stable_id(rel, subject, line):
    h = hashlib.sha1()
    h.update(f"{rel}|{subject}|{line}".encode())
    return h.hexdigest()[:16]


# ============================================================================
# balanced extraction
# ============================================================================
def _balanced(text: str, open_idx: int, opener="(", closer=")"):
    depth = 0
    n = len(text)
    i = open_idx
    while i < n:
        ch = text[i]
        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


# ============================================================================
# cross-lang function span index -> attribute a hit offset to its enclosing fn
# ============================================================================
_FN_DECL_RE = re.compile(
    r"(?:"
    r"function\s+(?P<sol>[A-Za-z_]\w*)"                     # Solidity
    r"|func\s+(?:\([^)]*\)\s*)?(?P<go>[A-Za-z_]\w*)"        # Go
    r"|(?:pub\s+)?(?:async\s+)?(?:unsafe\s+)?(?:const\s+)?fn\s+(?P<rs>[A-Za-z_]\w*)"  # Rust
    r"|(?:public\s+|entry\s+|native\s+)*fun\s+(?P<mv>[A-Za-z_]\w*)"  # Move
    r")")


def _fn_spans(masked: str):
    spans = []
    for m in _FN_DECL_RE.finditer(masked):
        name = (m.group("sol") or m.group("go") or m.group("rs")
                or m.group("mv") or "<anon>")
        bopen = masked.find("{", m.end())
        if bopen == -1:
            continue
        semi = masked.find(";", m.end())
        if semi != -1 and semi < bopen:
            continue
        bclose = _balanced(masked, bopen, "{", "}")
        if bclose == -1:
            continue
        spans.append((bopen, bclose, name))
    spans.sort()
    return spans


def _fn_of(spans, off):
    best = "<file-scope>"
    best_start = -1
    for bstart, bend, name in spans:
        if bstart <= off <= bend and bstart > best_start:
            best = name
            best_start = bstart
    return best


def _fn_body_start(spans, off):
    """Enclosing fn body-open offset for `off`, or 0 (file scope)."""
    best_start = 0
    for bstart, bend, _name in spans:
        if bstart <= off <= bend and bstart > best_start:
            best_start = bstart
    return best_start


# ============================================================================
# value-bearing hint (the operand / statement carries a logical amount/id/...)
# ============================================================================
_VALUE_HINT_RE = re.compile(
    r"(amount|amt|shares?|assets?|balance|nonce|\bids?\b|index|indices|\bidx\b|"
    r"length|\blen\b|\bsize\b|\bsz\b|count|\bcnt\b|offset|height|decimals?|"
    r"chain[_]?id|shard|epoch|slot|deadline|timestamp|\bts\b|supply|quantity|"
    r"\bqty\b|token[_]?id|amountin|amountout|shares?out|shares?in|principal|"
    r"collateral|\bdebt\b|reward|stake|deposit|withdraw|redeem|\bcap\b|capacity)",
    re.I)


def _value_strength(operand: str, statement: str, fn_name: str):
    """('strong'|'weak'|None, hint_token). Strong = hint in the operand."""
    m = _VALUE_HINT_RE.search(operand)
    if m:
        return "strong", m.group(0)
    m = _VALUE_HINT_RE.search(statement) or _VALUE_HINT_RE.search(fn_name)
    if m:
        return "weak", m.group(0)
    return None, ""


# ============================================================================
# narrowing target widths (bits). Anything at/above the default width is a
# widening / same-width cast and is NOT a narrowing.
# ============================================================================
_RUST_TARGETS = {"u8": 8, "u16": 16, "u32": 32, "i8": 8, "i16": 16, "i32": 32}
_GO_TARGETS = {"uint8": 8, "uint16": 16, "uint32": 32, "int8": 8, "int16": 16,
               "int32": 32, "byte": 8, "rune": 32}
# Move: u8/u16/u32/u64/u128 are all narrower than the widest u256 source; a bare
# `as u256` is always a widening and is excluded.
_MOVE_TARGETS = {"u8": 8, "u16": 16, "u32": 32, "u64": 64, "u128": 128}

_RUST_CAST_RE = re.compile(r"\bas\s+(u8|u16|u32|i8|i16|i32)\b")
_MOVE_CAST_RE = re.compile(r"\bas\s+(u8|u16|u32|u64|u128)\b")
# Go: `(?<![\]\w.])` rejects `[]byte(` / `pkg.int32(` / `xint32(`; only a bare
# scalar narrowing conversion counts. Bare `int(`/`uint(` (word width) excluded.
_GO_CAST_RE = re.compile(
    r"(?<![\]\w.])(uint32|uint16|uint8|int32|int16|int8|byte|rune)\s*\(")
# Solidity: `uintN(` / `intN(` with N captured; N<256 is a narrowing. `.toUint64(`
# (capital U) is the OZ SafeCast guarded form and is NOT matched (case-sensitive).
_SOL_CAST_RE = re.compile(r"(?<![\w.])(uint|int)(\d{1,3})\s*\(")


def _sol_target_bits(kind: str, width: int):
    if width % 8 != 0 or width < 8 or width >= 256:
        return None
    return width


# ============================================================================
# guard / dominating-bound (the value provably fits -> SILENT)
# ============================================================================
_CHECKED_CONV_RE = re.compile(
    r"try_from|try_into|TryFrom|TryInto|checked_|saturating_|SafeCast|"
    r"\.toUint|\.toInt|\.min\s*\(")
_CMP_RE = re.compile(r"(<=|>=|==|!=|<|>)")
_BOUND_TOKEN_RE = re.compile(
    r"type\s*\(\s*(?:u?int)\d+\s*\)\s*\.\s*max"                 # Solidity type(uintN).max
    r"|(?:\bmath\.)?Max(?:U)?[Ii]nt(?:8|16|32|64)?\b"          # Go math.MaxUint32
    r"|\b[uUiI](?:8|16|32|64|128|size)::(?:MAX|MIN)\b"          # Rust u32::MAX
    r"|1\s*<<\s*\d+"                                            # 1<<32
    r"|0x[fF]{2,}\b"                                            # 0xffff.. mask
    r"|\b[A-Za-z_]*(?:MAX|Max|MIN|Min|LIMIT|Limit|BOUND|Bound)[A-Za-z0-9_]*\b")
_MASK_RE = re.compile(r"&\s*(0x[0-9a-fA-F]+|\d+)")


def _bitmask_fits(operand: str, target_bits: int):
    """A `x & 0xff` mask whose bit-width <= the target repr -> the value provably
    fits, so the narrowing is lossless. Returns a guard-desc or None."""
    for m in _MASK_RE.finditer(operand):
        tok = m.group(1)
        try:
            val = int(tok, 16) if tok.lower().startswith("0x") else int(tok)
        except ValueError:
            continue
        if val > 0 and val.bit_length() <= target_bits:
            return "bitmask %s fits %d-bit target" % (m.group(0).strip(),
                                                      target_bits)
    return None


def _dominating_bound(prefix: str, operand: str, target_bits: int):
    """Is the operand proven to FIT the target before the cast? True iff a
    checked/safe conversion or a mask, or a dominating comparison against a
    repr-bound token references an operand id. Linear-prefix dominance is a
    sound-toward-SILENCE approximation. Returns (bool, desc)."""
    mb = _bitmask_fits(operand, target_bits)
    if mb:
        return True, mb
    if _CHECKED_CONV_RE.search(operand):
        return True, "checked/safe conversion on operand"
    op_ids = [t for t in re.findall(r"[A-Za-z_]\w*", operand)
              if len(t) > 1 and t not in ("len", "uint", "int")]
    if not op_ids:
        return False, None
    for line in prefix.split("\n"):
        refs = any(re.search(r"\b" + re.escape(t) + r"\b", line) for t in op_ids)
        if not refs:
            continue
        if _CHECKED_CONV_RE.search(line):
            return True, line.strip()[:120]
        if _CMP_RE.search(line) and _BOUND_TOKEN_RE.search(line):
            return True, line.strip()[:120]
    return False, None


# ============================================================================
# per-lang cast-site enumeration -> (target_type, target_bits, operand, offset)
# ============================================================================
_IDENT_CH = re.compile(r"[A-Za-z0-9_]")


def _rust_left_operand(s: str, as_idx: int):
    """The expression immediately left of a Rust/Move `as` at s[as_idx]."""
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


def _cast_sites(masked: str, lang: str):
    if lang == "solidity":
        for m in _SOL_CAST_RE.finditer(masked):
            width = int(m.group(2))
            tb = _sol_target_bits(m.group(1), width)
            if tb is None:
                continue
            popen = masked.find("(", m.end() - 1)
            if popen == -1:
                continue
            close = _balanced(masked, popen, "(", ")")
            if close == -1:
                continue
            operand = masked[popen + 1:close].strip()
            yield m.group(1) + m.group(2), tb, operand, m.start()
    elif lang == "go":
        for m in _GO_CAST_RE.finditer(masked):
            target = m.group(1)
            tb = _GO_TARGETS[target]
            popen = masked.find("(", m.end() - 1)
            if popen == -1:
                continue
            close = _balanced(masked, popen, "(", ")")
            if close == -1:
                continue
            operand = masked[popen + 1:close].strip()
            yield target, tb, operand, m.start()
    elif lang == "rust":
        for m in _RUST_CAST_RE.finditer(masked):
            target = m.group(1)
            tb = _RUST_TARGETS[target]
            operand = _rust_left_operand(masked, m.start()).strip()
            yield target, tb, operand, m.start()
    elif lang == "move":
        for m in _MOVE_CAST_RE.finditer(masked):
            target = m.group(1)
            tb = _MOVE_TARGETS[target]
            operand = _rust_left_operand(masked, m.start()).strip()
            yield target, tb, operand, m.start()


# ============================================================================
# row construction
# ============================================================================
def _mk_row(rel, fn, line, lang, target, operand, value_hint, dominating_bound,
            excerpt, severity, why):
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "id": _stable_id(rel, fn + "|" + target + "|" + operand[:32], line),
        "file": rel,
        "line": line,
        "function": fn,
        "lang": lang,
        "target_type": target,
        "operand": operand[:120],
        "value_hint": value_hint,
        "guard_absent": True,
        "dominating_bound": dominating_bound,
        "excerpt": excerpt,
        "severity": severity,
        "why_severity_anchored": why,
        "fires": True,
        "verdict": "needs-fuzz",
        "advisory": True,
        "auto_credit": False,
    }


def _is_literal(operand: str) -> bool:
    return bool(re.fullmatch(r"[-+]?\s*(0x[0-9a-fA-F]+|\d[\d_]*)", operand.strip()))


# ============================================================================
# scan a single file
# ============================================================================
def scan_file(path: Path, rel: str, file_text: str = None):
    ext = "." + rel.lower().rsplit(".", 1)[-1] if "." in rel else ""
    lang = _EXT_TO_LANG.get(ext)
    if lang is None:
        return []
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    masked = _mask(raw)
    spans = _fn_spans(masked)
    rows = []
    seen = set()

    for target, tb, operand, off in _cast_sites(masked, lang):
        if not operand or _is_literal(operand):
            continue  # empty / literal operand -> value already known-fits
        line = _line_of_offset(masked, off)
        fn = _fn_of(spans, off)
        ls, le = _line_span(masked, off)
        statement = masked[ls:le]
        # (a) value-bearing hint required.
        strength, hint = _value_strength(operand, statement, fn)
        if strength is None:
            continue  # FP-control: not a logical amount/id/... -> SILENT
        # (b) guard / dominating-bound -> SILENT.
        body_start = _fn_body_start(spans, off)
        prefix = masked[body_start:off]
        bounded, guard_desc = _dominating_bound(prefix, operand, tb)
        if bounded:
            continue
        key = (line, target, operand[:40])
        if key in seen:
            continue
        seen.add(key)
        severity = "high" if strength == "strong" else "medium"
        why = (
            "narrowing cast `%s(...)` truncates a value-bearing operand "
            "(hint=`%s`, %s): the WIDER source is silently reduced to a "
            "%d-bit target, so a large logical amount/id/index/nonce WRAPS to "
            "a small in-range value (value confusion - amount under-transfer / "
            "id-nonce collision / index aliasing / length under-read). No "
            "`try_into`/`SafeCast`/mask/range-guard dominates the cast. "
            "%s (cross-lang lift of Glider gap #2 unsafe-downcast; distinct "
            "from GEN-R5's memory-sink narrowing.)"
        ) % (target, hint,
             "in-operand=strong" if strength == "strong"
             else "operand-uncertain=weak (value-bearingness inferred from "
                  "statement/fn -> medium)",
             tb,
             "Mutation = replace the guarded/safe narrowing with a bare cast "
             "and re-run the value-conservation fuzz.")
        rows.append(_mk_row(rel, fn, line, lang, target, operand, hint,
                            bounded, _excerpt(raw, off), severity, why))

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
            ext = "." + low.rsplit(".", 1)[-1] if "." in low else ""
            if ext not in _EXT_TO_LANG:
                continue
            if low.endswith(_CODEGEN_SUFFIX):
                continue
            if low.startswith("test") or low.startswith("mock") \
                    or "_test." in low or ".t.sol" in low or low == "tests.rs":
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


def _emit_sidecar(ws: Path, rows):
    outdir = ws / ".auditooor"
    outdir.mkdir(parents=True, exist_ok=True)
    out = outdir / _SIDE_NAME
    with out.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
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
        "by_lang": _count(rows, "lang"),
        "by_target": _count(rows, "target_type"),
        "by_severity": _count(rows, "severity"),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="GEN-4C width-narrowing cast on a value-bearing operand "
                    "screen (cross-lang, advisory)")
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
    _emit_sidecar(ws, rows)
    summ = _summary(rows)
    print(json.dumps(summ, indent=2))
    return 1 if (strict and summ["fired"]) else 0


if __name__ == "__main__":
    sys.exit(main())
