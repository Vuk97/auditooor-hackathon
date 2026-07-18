#!/usr/bin/env python3
"""rust-unsafe-soundness-obligation.py  (R13) - Rust unsafe soundness-obligation
screen.

WHAT THIS TOOL IS
=================
A GENERAL, target-agnostic INVARIANT / TRUST-ENFORCEMENT screen for Rust code.
It is NOT a specific bug-shape detector and it never encodes a particular
vulnerable function, protocol, or impact string. It enumerates a FIXED class of
UNSAFE ENFORCEMENT POINTS and, per point, states the private SOUNDNESS OBLIGATION
that the surrounding SAFE abstraction DELEGATES to that point and asks whether the
obligation is actually discharged - i.e. it applies the north-star method:

  "A TRUSTED ENFORCEMENT is bypassable or its private invariant is unsound."

THE DELEGATED-AND-TRUSTED INVARIANT (per the north-star)
-------------------------------------------------------
Rust's safe/unsafe split is a TRUST BOUNDARY: safe code delegates a memory-safety
obligation to each `unsafe` construct and then TRUSTS it. Every enumerated point
carries a private obligation the compiler does NOT check:

  (a) UNSAFE-BLOCK        `unsafe { ... }`            obligation: the wrapped
      operation's memory-safety precondition holds (valid+aligned pointer,
      initialised memory, aliasing-XOR-mutability preserved) on EVERY reachable
      path. If unsound, a purely-safe caller drives UB / memory corruption.

  (b) UNSAFE-SEND/SYNC    `unsafe impl Send/Sync`     obligation: no cross-thread
      capability escape - the type is actually safe to move/share across threads.
      If unsound, safe multi-threaded code data-races the interior.

  (c) TRANSMUTE           `transmute(_copy)`          obligation: source & target
      have identical size/alignment and the source bit-pattern is valid for the
      target type. If unsound, an invalid value is materialised from safe input.

  (d) RAW-PTR-REINTERPRET `from_raw_parts(_mut)`, `Box::from_raw`, `ptr::read/
      write/copy`                                     obligation: the pointer is
      valid, aligned, non-aliasing and the length is in-bounds. If unsound, an
      attacker-chosen length/offset yields an out-of-bounds read/write.

  (e) ASSUME-INIT         `MaybeUninit::assume_init`  obligation: every byte is
      initialised to a valid bit pattern. If unsound, uninitialised memory is
      read as a valid value.

  (f) UNCHECKED-STR       `str::from_utf8_unchecked`  obligation: the bytes are
      valid UTF-8. If unsound, a `str` with invalid UTF-8 corrupts downstream.

  (g) UNCHECKED-INDEX     `get_unchecked(_mut)`       obligation: the index is
      in-bounds. If unsound, attacker-chosen index reads/writes out of bounds.

THE ATTACK (why this is a security census, not a lint)
------------------------------------------------------
The screen is scoped, by default, to points whose enclosing item is SAFE-CALLER
REACHABLE (a `pub`/`pub(crate)` fn, or a trait-impl method invocable through its
trait, or a type-level `unsafe impl`). That is exactly where an external, purely
SAFE caller can DRIVE the type into a state that falsifies the delegated
obligation - the RUSTSEC memory-safety UB pattern (smallvec insert_many overflow
RUSTSEC-2021-0003, nano_arena aliasing &mut RUSTSEC-2021-0031, http Drain
RUSTSEC-2019-0034, cyfs-base misaligned deref RUSTSEC-2023-0046): all were
safe-API-reachable UB from an UN-DISCHARGED unsafe obligation.

THE OBLIGATION-SLOT / DISCHARGE PREDICATE (the core, load-bearing check)
-----------------------------------------------------------------------
Per Rust discipline (clippy::undocumented_unsafe_blocks), every unsafe point must
carry an EXPLICIT obligation slot - a `// SAFETY:` justification - or an in-code
validating guard (assert / bounds-check / checked-arith) that establishes the
precondition before the unsafe op. A point is treated as DISCHARGED (silent) iff
such a slot/guard is present; otherwise its obligation was never even stated and
the point is a HYPOTHESIS. This is the single load-bearing predicate
(`obligation_discharged`); neutralising it makes every hypothesis vanish.

GENERALITY (this is a class, not a shape)
-----------------------------------------
The enforcement-point sets and their obligations are fixed and target-independent,
instantiated per target from whatever Rust source is in scope. It promotes the
unbuilt backlog RU1 (base-rust-swival flags unsafe PRESENCE only) into an
obligation-slot + safe-caller-reachability JOIN.

ADVISORY-FIRST / NO-AUTO-CREDIT (hard contract)
-----------------------------------------------
Every emitted row carries verdict="needs-fuzz" and no_auto_credit=true. This tool
NEVER flips a gate, NEVER resolves a unit, and NEVER fail-closes: it always exits
0. Static reachability + missing-obligation is a HYPOTHESIS; a MIRI /
cargo-careful run over the safe-API path is the confirmation lane (emitted per
row as confirm_lane). Hang the rows on the completeness-matrix MEMORY-SAFETY axis;
do not silo them.

Usage:
  python3 tools/rust-unsafe-soundness-obligation.py --workspace <ws> [--json]
  python3 tools/rust-unsafe-soundness-obligation.py --file <a.rs> [--all] [--json]
  python3 tools/rust-unsafe-soundness-obligation.py --file <a.rs> --arm transmute

Flags:
  --workspace DIR  scan every *.rs (non-test) under DIR.
  --file FILE      scan a single Rust file (used by tests / fleet-FP checks).
  --all            do NOT require safe-caller reachability (emit every point).
  --arm NAME       restrict to one arm (repeatable). Default: all arms.
  --out PATH       override the hypotheses jsonl output path.
  --json           print accounting + rows as JSON to stdout.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys

TOOL = "rust-unsafe-soundness-obligation"
OUT_REL = os.path.join(".auditooor",
                       "rust_unsafe_soundness_obligation_hypotheses.jsonl")
ACC_REL = os.path.join(".auditooor",
                       "rust_unsafe_soundness_obligation_accounting.json")

ARMS = (
    "unsafe_block",
    "unsafe_send_sync",
    "transmute",
    "raw_ptr_reinterpret",
    "assume_init",
    "unchecked_str",
    "unchecked_index",
)

# --------------------------------------------------------------------------- #
# Comment / string stripping (length-preserving so byte offsets still map to   #
# original line numbers). Blanks // and /* */ comments and the CONTENTS of     #
# "", '', r#""# / b"" literals, so keywords/braces inside them cannot perturb   #
# structural parsing OR create false enforcement-point matches (e.g. the word   #
# `unsafe` inside a doc comment). The raw source is retained separately for the #
# `// SAFETY:` obligation-slot signal.                                          #
# --------------------------------------------------------------------------- #
def strip_comments_strings(src: str) -> str:
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        # line comment
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                out.append(" ")
                i += 1
            continue
        # block comment (Rust nests, but a flat scan is enough for our purposes)
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            depth = 1
            out.append("  ")
            i += 2
            while i < n and depth > 0:
                if src[i] == "/" and i + 1 < n and src[i + 1] == "*":
                    depth += 1
                    out.append("  ")
                    i += 2
                    continue
                if src[i] == "*" and i + 1 < n and src[i + 1] == "/":
                    depth -= 1
                    out.append("  ")
                    i += 2
                    continue
                out.append("\n" if src[i] == "\n" else " ")
                i += 1
            continue
        # lifetime / label (`'static`, `'a`, `'label:`) is NOT a char literal.
        # A char literal is `'x'` or `'\n'` (closer `'` within 1-2 chars); a
        # lifetime is `'` + ident with no closing `'`. Misreading `'static` as a
        # char literal would blank the rest of the line (incl. real unsafe ops).
        if c == "'" and i + 1 < n and (src[i + 1].isalpha() or src[i + 1] == "_") \
                and (i + 2 >= n or src[i + 2] != "'"):
            out.append(c)
            i += 1
            continue
        # char / string literal (best-effort; handles \-escapes in "" '')
        if c in ('"', "'"):
            quote = c
            out.append(" ")
            i += 1
            while i < n and src[i] != quote:
                if src[i] == "\\" and i + 1 < n:
                    out.append("  ")
                    i += 2
                    continue
                out.append("\n" if src[i] == "\n" else " ")
                i += 1
            if i < n:
                out.append(" ")
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _brace_match(text: str, open_idx: int) -> int:
    depth = 0
    for k in range(open_idx, len(text)):
        if text[k] == "{":
            depth += 1
        elif text[k] == "}":
            depth -= 1
            if depth == 0:
                return k
    return -1


def _paren_match(text: str, open_idx: int) -> int:
    depth = 0
    for k in range(open_idx, len(text)):
        if text[k] == "(":
            depth += 1
        elif text[k] == ")":
            depth -= 1
            if depth == 0:
                return k
    return -1


def _line_of(text: str, offset: int) -> int:
    """1-based line number of a byte offset."""
    return text.count("\n", 0, offset) + 1


# --------------------------------------------------------------------------- #
# Item parsing: fn spans (for safe-caller reachability + guard scope) and       #
# trait-impl spans (a trait method is publicly invocable through its trait).    #
# --------------------------------------------------------------------------- #
_FN = re.compile(r"\bfn\s+([A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*\(")
_IMPL = re.compile(r"\bimpl\b")


def parse_fns(stripped: str):
    """Return [(name, sig_prefix, body_start, body_end, decl_off)] over stripped.
    body_start/body_end are byte offsets of the fn body { ... } (exclusive of the
    braces); sig_prefix is the same-line text preceding `fn` (holds pub/unsafe).
    """
    fns = []
    for m in _FN.finditer(stripped):
        popen = m.end() - 1
        pclose = _paren_match(stripped, popen)
        if pclose < 0:
            continue
        # body { is the first brace after the param list at this nesting.
        bopen = stripped.find("{", pclose)
        # skip a `-> ...` return type / where-clause that contains no braces;
        # a `{` before a `;`/`}` that would end a decl is the body opener.
        semi = stripped.find(";", pclose)
        if bopen < 0 or (semi != -1 and semi < bopen):
            continue  # trait-method decl w/o body (`fn f();`)
        bclose = _brace_match(stripped, bopen)
        if bclose < 0:
            continue
        line_start = stripped.rfind("\n", 0, m.start()) + 1
        sig_prefix = stripped[line_start:m.start()]
        fns.append((m.group(1), sig_prefix, bopen + 1, bclose, m.start()))
    return fns


def parse_trait_impl_spans(stripped: str):
    """Return [(start, end)] byte spans of `impl <Trait> for <Ty> { ... }` blocks
    (headers containing ` for `). A method inside such a span is reachable through
    the trait even if the method itself is not `pub`."""
    spans = []
    for m in _IMPL.finditer(stripped):
        bopen = stripped.find("{", m.end())
        semi = stripped.find(";", m.end())
        if bopen < 0:
            continue
        if semi != -1 and semi < bopen:
            continue
        header = stripped[m.start():bopen]
        # ignore a `for` that is a loop keyword: require it to be surrounded by
        # type context (no `{`/`;` between impl and header end already ensured).
        if re.search(r"\bfor\b", header):
            bclose = _brace_match(stripped, bopen)
            if bclose > 0:
                spans.append((m.start(), bclose))
    return spans


# --------------------------------------------------------------------------- #
# Enforcement-point enumeration (over the STRIPPED source).                     #
# Ordered by specificity: a specific intrinsic on a line wins over the generic  #
# `unsafe {` block that wraps it (dedup by line, keep most specific).           #
# --------------------------------------------------------------------------- #
_POINT_RX = [
    ("unsafe_send_sync",
     re.compile(r"\bunsafe\s+impl\b[^{;]*\b(?:Send|Sync)\b"), 0),
    ("transmute", re.compile(r"\btransmute(?:_copy)?\s*(?:::\s*<[^>]*>)?\s*\("), 1),
    ("assume_init", re.compile(r"\bassume_init(?:_read|_mut|_ref)?\s*\("), 1),
    ("unchecked_str", re.compile(r"\bfrom_utf8_unchecked(?:_mut)?\s*\("), 1),
    ("unchecked_index", re.compile(r"\bget_unchecked(?:_mut)?\s*\("), 1),
    ("raw_ptr_reinterpret",
     re.compile(r"\bfrom_raw_parts(?:_mut)?\s*\("
                r"|\bBox\s*::\s*from_raw\s*\("
                r"|\b(?:std|core)?\s*::?\s*ptr\s*::\s*(?:read|write|copy|"
                r"replace|swap)(?:_unaligned|_volatile|_nonoverlapping)?\s*\("
                r"|\bfrom_raw\s*\("), 1),
    # generic unsafe block - lowest specificity (2); anchors bare raw-ptr derefs,
    # unions, static-mut access, etc. that have no dedicated intrinsic token.
    ("unsafe_block", re.compile(r"\bunsafe\s*\{"), 2),
]


def enumerate_points(stripped: str):
    """Yield (arm, offset) for each enforcement point, deduped by LINE keeping
    the most specific arm on that line."""
    by_line = {}
    for arm, rx, spec in _POINT_RX:
        for m in rx.finditer(stripped):
            off = m.start()
            ln = _line_of(stripped, off)
            cur = by_line.get(ln)
            if cur is None or spec < cur[0]:
                by_line[ln] = (spec, arm, off)
    return [(v[1], v[2]) for _, v in sorted(by_line.items())]


# --------------------------------------------------------------------------- #
# Safe-caller reachability (the trust-boundary gate).                          #
# --------------------------------------------------------------------------- #
_PUB = re.compile(r"\bpub\b")


def enclosing_fn(fns, off):
    """Innermost fn whose body span contains off, or None."""
    best = None
    for name, sig, bstart, bend, decl in fns:
        if bstart <= off <= bend:
            if best is None or (bstart >= best[2]):
                best = (name, sig, bstart, bend, decl)
    return best


def is_safe_caller_reachable(arm, fn, off, trait_spans):
    """A point is safe-caller reachable if: it is a type-level `unsafe impl`
    (always public API), OR its enclosing fn is `pub`/`pub(...)`, OR the point
    lies inside a trait-impl block (method invocable through the trait)."""
    if arm == "unsafe_send_sync":
        return True
    if fn is not None and _PUB.search(fn[1]):
        return True
    for s, e in trait_spans:
        if s <= off <= e:
            return True
    return False


# --------------------------------------------------------------------------- #
# Obligation-slot / discharge predicate (THE core, load-bearing check).        #
# --------------------------------------------------------------------------- #
# A documented obligation slot: `// SAFETY:` / `//! SAFETY` / `/// SAFETY` or a
# `// SAFE:` justification, immediately above (or on) the point.
_SAFETY_COMMENT = re.compile(r"//[/!]{0,2}\s*SAFE(?:TY)?\b", re.IGNORECASE)
# A pure line-comment line (`//`, `///`, `//!`) - used to walk the contiguous
# comment block that immediately precedes an unsafe point.
_COMMENT_LINE = re.compile(r"^\s*//")
# An in-code validating guard that establishes a precondition before the point.
_GUARD_TOKEN = re.compile(
    r"\bassert(?:_eq|_ne)?\s*!"
    r"|\bdebug_assert(?:_eq|_ne)?\s*!"
    r"|\bensure\s*!"
    r"|\brequire\s*[!(]"
    r"|\bchecked_[a-z_]+\s*\("
    r"|\btry_into\s*\("
    r"|\btry_from\s*\("
    r"|\.len\s*\(\s*\)\s*[<>=!]"
    r"|[<>]=?\s*[\w.]*\.len\s*\(\s*\)"
    r"|\bis_empty\s*\("
    r"|\bis_null\s*\("
    r"|\bis_aligned\s*\("
)
def obligation_discharged(raw_lines, point_line, fn_body_before_point):
    """CORE PREDICATE. True iff the unsafe point's soundness obligation is
    discharged - either a documented `// SAFETY:` obligation slot anywhere in the
    contiguous line-comment block that immediately precedes the point (or on the
    point line itself), or an in-code validating guard earlier in the enclosing
    fn body. False => the obligation was never stated -> HYPOTHESIS.

    The comment block is walked line-by-line upward while each line is a pure
    line-comment (`//`, `///`, `//!`), so a MULTI-LINE `// SAFETY:` justification
    - the idiomatic form that satisfies clippy::undocumented_unsafe_blocks, where
    the `SAFETY` keyword sits on the FIRST comment line and several continuation
    comment lines follow before the `unsafe` op - is recognised regardless of how
    many continuation lines separate the keyword from the point. The walk stops
    at the first non-comment line, so the slot must be genuinely attached to this
    point (no crediting a distant unrelated comment)."""
    idx = point_line - 1  # 0-based index of the point line itself
    # the point line may itself carry an inline `// SAFETY:` (e.g. trailing).
    if 0 <= idx < len(raw_lines) and _SAFETY_COMMENT.search(raw_lines[idx]):
        return True
    j = idx - 1
    while j >= 0 and _COMMENT_LINE.match(raw_lines[j]):
        if _SAFETY_COMMENT.search(raw_lines[j]):
            return True
        j -= 1
    if fn_body_before_point and _GUARD_TOKEN.search(fn_body_before_point):
        return True
    return False


# --------------------------------------------------------------------------- #
# Per-arm obligation text + exploit class.                                      #
# --------------------------------------------------------------------------- #
_OBLIGATION = {
    "unsafe_block":
        "the wrapped operation's memory-safety precondition holds on every "
        "reachable path (valid+aligned pointer, initialised memory, "
        "aliasing-XOR-mutability preserved)",
    "unsafe_send_sync":
        "no cross-thread capability escape - the type is genuinely safe to "
        "move/share across threads",
    "transmute":
        "source and target have identical size/alignment and the source "
        "bit-pattern is valid for the target type",
    "raw_ptr_reinterpret":
        "the raw pointer is valid, aligned, non-aliasing and any length/offset "
        "is in-bounds",
    "assume_init":
        "every byte of the value is initialised to a valid bit pattern",
    "unchecked_str":
        "the byte slice is valid UTF-8",
    "unchecked_index":
        "the index/range is in-bounds for the target container",
}
_EXPLOIT = {
    "unsafe_block": "memory-corruption",
    "unsafe_send_sync": "data-race",
    "transmute": "invalid-value-materialisation",
    "raw_ptr_reinterpret": "out-of-bounds-read-write",
    "assume_init": "uninitialised-memory-read",
    "unchecked_str": "invalid-utf8-corruption",
    "unchecked_index": "out-of-bounds-read-write",
}


def _row(arm, filename, fn_name, line, reachable):
    return {
        "tool": TOOL,
        "capability": "R13-rust-unsafe-soundness-obligation",
        "arm": arm,
        "file": filename,
        "line": line,
        "function": fn_name,
        "enforcement_point": arm,
        "soundness_obligation": _OBLIGATION[arm],
        "obligation_slot": "undischarged",
        "safe_caller_reachable": reachable,
        "attack_class": "rust-unsafe-soundness",
        "exploit_class": _EXPLOIT[arm],
        "verdict": "needs-fuzz",
        "no_auto_credit": True,
        "confirm_lane": ("cargo +nightly miri test / cargo-careful over the "
                         "safe-API path that reaches this point"),
    }


# --------------------------------------------------------------------------- #
# Analysis                                                                     #
# --------------------------------------------------------------------------- #
def analyze_source(src, filename, all_scopes=False, arms=None):
    """Return the list of hypothesis rows for one Rust source string."""
    want = set(arms) if arms else set(ARMS)
    stripped = strip_comments_strings(src)
    raw_lines = src.split("\n")
    fns = parse_fns(stripped)
    trait_spans = parse_trait_impl_spans(stripped)

    rows = []
    for arm, off in enumerate_points(stripped):
        if arm not in want:
            continue
        fn = enclosing_fn(fns, off)
        reachable = is_safe_caller_reachable(arm, fn, off, trait_spans)
        if not all_scopes and not reachable:
            continue
        point_line = _line_of(stripped, off)
        fn_name = fn[0] if fn is not None else "<module>"
        # enclosing-fn body text from body start up to the point (for the guard).
        body_before = stripped[fn[2]:off] if fn is not None else ""
        if obligation_discharged(raw_lines, point_line, body_before):
            continue  # obligation slot present -> silent (benign / guarded)
        rows.append(_row(arm, filename, fn_name, point_line, reachable))
    return rows


def analyze_file(path, all_scopes=False, arms=None):
    try:
        src = pathlib.Path(path).read_text(errors="replace")
    except Exception:
        return []
    return analyze_source(src, str(path), all_scopes=all_scopes, arms=arms)


def _iter_rust_files(ws: pathlib.Path):
    for p in ws.rglob("*.rs"):
        s = str(p).replace(os.sep, "/")
        if p.name.endswith("_test.rs") or p.name == "tests.rs":
            continue
        if "/target/" in s or "/.auditooor/" in s or "/tests/" in s:
            continue
        if "/.engage_scratch/" in s or "/benches/" in s or "/examples/" in s:
            continue
        yield p


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--workspace")
    g.add_argument("--file")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--arm", action="append", choices=list(ARMS))
    ap.add_argument("--out", default=None)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    rows = []
    files_scanned = 0
    if args.file:
        p = pathlib.Path(args.file)
        if not p.is_file():
            print(f"[err] file not found: {p}", file=sys.stderr)
            sys.exit(1)
        rows = analyze_file(p, all_scopes=args.all, arms=args.arm)
        files_scanned = 1
        out_default = None
    else:
        ws = pathlib.Path(args.workspace)
        if not ws.is_dir():
            print(f"[err] workspace not found: {ws}", file=sys.stderr)
            sys.exit(1)
        for p in _iter_rust_files(ws):
            files_scanned += 1
            rows.extend(analyze_file(p, all_scopes=args.all, arms=args.arm))
        out_default = ws / OUT_REL

    per_arm = {a: sum(1 for r in rows if r["arm"] == a) for a in ARMS}
    acc = {
        "tool": TOOL,
        "capability": "R13-rust-unsafe-soundness-obligation",
        "status": "ok",
        "advisory_first": True,
        "files_scanned": files_scanned,
        "reachability_gate": (not args.all),
        "hypotheses": len(rows),
        "per_arm": per_arm,
    }

    out_path = pathlib.Path(args.out) if args.out else out_default
    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        acc_path = out_path.parent / pathlib.Path(ACC_REL).name
        with open(acc_path, "w") as f:
            json.dump(acc, f, indent=2)

    if args.json:
        print(json.dumps({"accounting": acc, "hypotheses": rows}, indent=2))
    else:
        print(f"[ok] {TOOL}: files={files_scanned} "
              f"hypotheses(needs-fuzz)={len(rows)} per_arm={per_arm} "
              f"reachability_gate={not args.all}")

    # Advisory-first: NEVER fail-close.
    sys.exit(0)


if __name__ == "__main__":
    main()
