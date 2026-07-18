#!/usr/bin/env python3
"""panic-during-drop-screen.py - GEN-R1, the PANIC-DURING-DROP double-drop / UAF
exception-safety screen (lang-intrinsic layer = rust-soundness).

RUST-ONLY. A GENERAL advisory screen (never a specific bug-shape). When unsafe
code MANUALLY drops owned values out of a still-live container / buffer, and an
element `Drop` can PANIC, the unwind must NOT re-observe a slot that was already
dropped. The safe discipline is CONSUME-BEFORE-DROP: mark the slot(s) consumed
(set the Vec `len` to 0, advance a progress drop-guard index, `forget`, or
overwrite with a fresh value) BEFORE running the drops that may panic. If the
element drop unwinds after the slot was hand-dropped but the container still
reports it as initialized, the container's own `Drop` re-reads and RE-DROPS it -
a double-free / use-after-free reachable from safe code.

This screen FIRES the four DROP-BEFORE-CONSUME forms:

  (1) drop-in-place-loop      : a loop of `ptr::drop_in_place` over a raw buffer
      where the container still reports the elements initialized - NO `set_len(0)`
      / per-iteration guard advance / `forget` BEFORE the drop loop;
  (2) ptr-read-double-drop    : `ptr::read(slot)` producing an OWNED value that
      will `Drop`, while the SAME slot remains logically owned by the container
      (no `forget` / `set_len` / consume of the slot) - the classic
      `ptr::read` + panic double-free;
  (3) manuallydrop-seq        : `ManuallyDrop::drop(A)` followed by MORE work that
      can panic (`?`, `.unwrap()`, `panic!`, an index, a user call), where A can
      be re-dropped by an outer cleanup;
  (4) rebuild-drop-then-write : `drop_in_place(slot)` then a write of the new
      element to the SAME slot, with the panic window between the drop and the
      write while `len` still counts the slot.

FP-CONTROL (consume-before-drop is exception-safe -> STAY SILENT):
  * the function sets `len` to 0 (or `forget()`s / `mem::take`s / `mem::replace`s
    / advances a documented drop-guard index) BEFORE the panicking drop -> skip;
  * a `drop_in_place` whose element type is a plain `Copy` / POD scalar (its
    `Drop` is a no-op that cannot panic) -> low / skip;
  * a `ptr::read` whose result is a `Copy` scalar (`.cast::<u32>()`, reading a
    primitive) -> skip;
  * a single `ManuallyDrop::drop` at the very END of a function with no
    subsequent fallible work -> low / skip;
  * a single non-loop `drop_in_place` at the end of a `Drop` impl (no re-droppable
    container slot, no subsequent write) -> not the double-drop shape -> skip.
  The signal is the DROP-BEFORE-CONSUME ordering (a re-droppable slot across a
  panic window). When the ordering cannot be seen, the row is `medium`, not
  `high`.

DEDUP (per dispatch brief):
  * raii-drop-glue-bypass screens a SKIP of cleanup on an error / `?` path (a
    LEAK / missing cleanup), NOT panic-mid-cleanup RE-ENTRANCY (double-drop).
  * RU7 screens lock-poison-while-holding (a poisoned `Mutex`, CONCURRENCY), NOT
    drop-unwind re-drop.
  GEN-R1 = the manual-drop-BEFORE-consume exception-safety screen (double-drop /
  UAF across a panic window). A site that reduces to one of the above is dropped
  as overlap.

nuva has NO Rust surface -> nuva-verify is correctly N/A for this capability.

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False; exit 0 by default. The opt-in env
AUDITOOOR_PANIC_DURING_DROP_STRICT (or --strict) raises the exit code when a fired
row exists.

Excludes test / vendor / codegen via the shared exclusion libs.

Usage:
  --workspace <ws>   scan <ws>/src (or <ws>) -> .auditooor/
                     panic_during_drop_hypotheses.jsonl + summary
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

HYP_SCHEMA = "auditooor.panic_during_drop_hypotheses.v1"
_SIDE_NAME = "panic_during_drop_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_PANIC_DURING_DROP_STRICT"
_CAPABILITY = "GEN_R1"

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
# Rust-aware comment / string masking. We do NOT mask ' because it is a
# lifetime marker, not a char-literal delimiter, in the code we care about.
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


def _stable_id(rel, form, subject, line):
    h = hashlib.sha1()
    h.update(f"{rel}|{form}|{subject}|{line}".encode())
    return h.hexdigest()[:16]


# ============================================================================
# enclosing-function attribution + body-span extraction.
# ============================================================================
_FN_DECL_RE = re.compile(r"(?:^|\n)\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?"
                         r"(?:unsafe\s+)?(?:const\s+)?"
                         r"(?:extern\s+\"[^\"]*\"\s+)?fn\s+([A-Za-z_]\w*)")


def _enclosing_function(text: str, off: int) -> str:
    best = "<file>"
    for m in _FN_DECL_RE.finditer(text):
        if m.start() > off:
            break
        best = m.group(1)
    return best


def _match_block(text: str, brace_idx: int):
    """Return the index just past the matching '}' for '{' at brace_idx, or -1."""
    depth = 0
    n = len(text)
    i = brace_idx
    while i < n:
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def _enclosing_fn_body(text: str, off: int):
    """(body_start, body_end) of the innermost fn whose body encloses off, or
    (None, None). body_start is the offset just AFTER the fn's opening '{'."""
    best = (None, None)
    for m in _FN_DECL_RE.finditer(text):
        if m.start() > off:
            break
        brace = text.find("{", m.end())
        if brace == -1:
            continue
        end = _match_block(text, brace)
        if end == -1:
            continue
        if brace < off < end:
            # innermost wins (later, tighter span replaces an earlier outer).
            if best[0] is None or brace + 1 >= best[0]:
                best = (brace + 1, end)
    return best


# ============================================================================
# consume-before-drop markers and panic-window / element-type helpers.
# ============================================================================
# a marker that CONSUMES the slot(s) so the container will not re-drop them.
_CONSUME_RE = re.compile(
    r"\bset_len\s*\(\s*0\s*\)"                       # Vec::set_len(0) - full
    r"|\.set_len\s*\("                               # partial truncate before tail
    r"|\bset_len\s*\("
    r"|\b(?:std::|core::)?mem::forget\b"
    r"|\.forget\s*\("
    r"|\b(?:std::|core::)?mem::take\b"
    r"|\b(?:std::|core::)?mem::replace\b"
    r"|\bManuallyDrop::new\b"
)
# a token that can PANIC / unwind (opens a re-drop window).
_PANIC_TOK_RE = re.compile(
    r"\?\s*[;,)\n]"                                  # `?` operator
    r"|\.unwrap\s*\(|\.expect\s*\("
    r"|\bpanic!\s*\(|\bunreachable!\s*\(|\bassert!|\bassert_eq!|\btodo!\s*\("
    r"|\[[^\]]*\]"                                   # indexing (may panic)
)
# a user callback / closure invocation inside a loop body (panic can originate).
_CALLBACK_RE = re.compile(r"\b(?:f|g|cb|callback|func|closure|visit|apply)\s*\("
                          r"|\|\s*[A-Za-z_]")
# element type / read result that is a plain Copy scalar (drop is a no-op).
_COPY_SCALAR_RE = re.compile(
    r"\b(?:u8|u16|u32|u64|u128|usize|i8|i16|i32|i64|i128|isize|f32|f64|bool|"
    r"char)\b")
_COPY_CAST_RE = re.compile(
    r"\.cast\s*::\s*<\s*(?:u8|u16|u32|u64|u128|usize|i8|i16|i32|i64|i128|isize|"
    r"f32|f64|bool|char)\b")


# ============================================================================
# firing forms.
# ============================================================================
_LOOP_HDR_RE = re.compile(r"\b(for|while|loop)\b")
_DROP_IN_PLACE_RE = re.compile(r"\b(?:std::|core::)?ptr::drop_in_place\s*\(")
_PTR_READ_RE = re.compile(r"\b(?:std::|core::)?ptr::read\s*\(")
_MANUALLYDROP_DROP_RE = re.compile(r"\bManuallyDrop::drop\s*\(")
_PTR_WRITE_RE = re.compile(r"\b(?:std::|core::)?ptr::write\s*\(")


def _has_consume_before(text: str, body_start, site_off) -> bool:
    if body_start is None:
        body_start = max(0, site_off - 600)
    window = text[body_start:site_off]
    return bool(_CONSUME_RE.search(window))


def _mk_row(rel, fn, line, form, consume_present, panic_window, excerpt,
            severity, why):
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "id": _stable_id(rel, form, fn, line),
        "file": rel,
        "line": line,
        "function": fn,
        "lang": "rust",
        "unsafe_form": form,
        "consume_marker_present": bool(consume_present),
        "panic_window": panic_window,
        "excerpt": excerpt,
        "severity": severity,
        "why_severity_anchored": why,
        "fires": True,
        "verdict": "needs-fuzz",
        "advisory": True,
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

    # --- helper to test whether an offset sits inside a loop body -----------
    def _loop_body_containing(off):
        """Return (loop_start, body_start, body_end) of the innermost loop whose
        body contains off, else None."""
        best = None
        for lm in _LOOP_HDR_RE.finditer(text):
            if lm.start() > off:
                break
            kw = lm.group(1)
            brace = text.find("{", lm.end())
            if brace == -1:
                continue
            between = text[lm.end():brace]
            # a ';' before the block means this is not the loop's own block
            # (guards against `let x = while_cond;`-style false anchors).
            if ";" in between:
                continue
            # `for` is AMBIGUOUS: a trait-impl `impl Trait for Type {` and an
            # HRTB `for<'a> ...` are NOT loops. A loop-`for` is `for PAT in EXPR
            # {` - require an ` in ` binder and reject `for<`.
            if kw == "for":
                if between.lstrip().startswith("<") or \
                        not re.search(r"\bin\b", between):
                    continue
            end = _match_block(text, brace)
            if end == -1:
                continue
            if brace < off < end:
                if best is None or brace >= best[1]:
                    best = (lm.start(), brace + 1, end)
        return best

    # ------------------------------------------------- (1) drop-in-place-loop
    for m in _DROP_IN_PLACE_RE.finditer(text):
        off = m.start()
        loopinfo = _loop_body_containing(off)
        if loopinfo is None:
            continue  # single non-loop drop_in_place handled below (form 4).
        loop_start, _bstart, _bend = loopinfo
        body_start, _body_end = _enclosing_fn_body(text, off)
        # exception-safe iff a consume marker appears BEFORE the loop header.
        consume = _has_consume_before(text, body_start, loop_start)
        # element-type Copy skip: `drop_in_place(p as *mut u32)` etc.
        seg = text[off:text.find("\n", off) if text.find("\n", off) != -1
                   else off + 120]
        if _COPY_CAST_RE.search(seg) or re.search(
                r"\*\s*(?:const|mut)\s+(?:u8|u16|u32|u64|u128|usize|i8|i16|i32|"
                r"i64|i128|isize|f32|f64|bool|char)\b", seg):
            continue
        line = _line_of_offset(text, off)
        key = ("dilp", line)
        if key in seen:
            continue
        seen.add(key)
        if consume:
            continue  # consume-before-drop -> exception-safe -> silent.
        fn = _enclosing_function(text, off)
        loop_body = text[_bstart:_body_end]
        pw = "user-callback" if _CALLBACK_RE.search(loop_body) else "element-drop"
        rows.append(_mk_row(
            rel, fn, line, "drop-in-place-loop", False, pw,
            _excerpt(text, off), "high",
            "a loop hand-drops elements with `ptr::drop_in_place` over a raw "
            "buffer, but NO `set_len(0)` / progress drop-guard advance / "
            "`forget` marks the slots consumed BEFORE the loop. If an element "
            "`Drop` panics mid-loop, the unwind lets the container's own `Drop` "
            "re-read the still-'initialized' slots and RE-DROP them - a "
            "double-free / use-after-free reachable from safe code. HIGH: the "
            "drop-before-consume ordering is visible (no consume marker precedes "
            "the loop)."))

    # -------------------------------------------------- (2) ptr-read-double-drop
    for m in _PTR_READ_RE.finditer(text):
        off = m.start()
        line = _line_of_offset(text, off)
        # the statement / following ~160 chars.
        stmt_end = text.find(";", off)
        stmt = text[off:stmt_end if stmt_end != -1 else off + 160]
        # Copy-scalar read -> Drop is a no-op -> skip.
        if _COPY_CAST_RE.search(stmt):
            continue
        # the produced value must be BOUND to a `let` (held as an owned binding
        # across the panic window). A read consumed INLINE by an operator /
        # comparison (`if old == ptr::read(x)`) is never a re-droppable binding.
        # Look back a bounded window; the current statement is the text after the
        # last `;` / `}` (tolerating an intervening `unsafe {` block opener).
        win = text[max(0, off - 240):off]
        cut = max(win.rfind(";"), win.rfind("}"))
        cur_stmt = win[cut + 1:] if cut != -1 else win
        if not re.search(r"\blet\s+(?:mut\s+)?[A-Za-z_]\w*\b[^;]*=", cur_stmt):
            continue
        body_start, body_end = _enclosing_fn_body(text, off)
        # consume of the slot anywhere in the function (forget/set_len/take) ->
        # the container will not re-read -> exception-safe -> silent.
        fn_region = text[body_start:body_end] if body_start is not None else \
            text[max(0, off - 400):off + 400]
        if _CONSUME_RE.search(fn_region):
            continue
        # the read must produce an OWNED value that is bound (will Drop). Skip a
        # read immediately consumed by forget/ManuallyDrop on the same line.
        if re.search(r"ManuallyDrop::new|mem::forget|\.forget\s*\(", stmt):
            continue
        # require a subsequent panic window in the remainder of the function
        # (else the read is the last act and cannot re-observe on unwind).
        after = text[stmt_end if stmt_end != -1 else off:body_end] \
            if body_end is not None else text[off:off + 400]
        if not _PANIC_TOK_RE.search(after):
            continue
        key = ("pread", line)
        if key in seen:
            continue
        seen.add(key)
        fn = _enclosing_function(text, off)
        rows.append(_mk_row(
            rel, fn, line, "ptr-read-double-drop", False, "element-drop",
            _excerpt(text, off), "medium",
            "`ptr::read(slot)` produces an OWNED value that will `Drop`, while "
            "the SAME slot is still logically owned by the container (no "
            "`forget` / `set_len` / consume of the source) and fallible work "
            "follows. If that fallible work panics, the container's `Drop` "
            "re-reads the slot -> the classic `ptr::read` + panic DOUBLE-FREE. "
            "MEDIUM: the exact ownership of the read slot is not fully "
            "resolvable statically (tag medium not high per the ordering rule)."))

    # ---------------------------------------------------- (3) manuallydrop-seq
    for m in _MANUALLYDROP_DROP_RE.finditer(text):
        off = m.start()
        line = _line_of_offset(text, off)
        body_start, body_end = _enclosing_fn_body(text, off)
        if body_end is None:
            continue
        stmt_end = text.find(";", off)
        after = text[stmt_end + 1:body_end - 1] if stmt_end != -1 else ""
        # a single ManuallyDrop::drop at the very END (no fallible work after) ->
        # low / skip.
        if not after.strip() or not _PANIC_TOK_RE.search(after):
            continue
        key = ("mdrop", line)
        if key in seen:
            continue
        seen.add(key)
        fn = _enclosing_function(text, off)
        rows.append(_mk_row(
            rel, fn, line, "manuallydrop-seq", False, "element-drop",
            _excerpt(text, off), "medium",
            "`ManuallyDrop::drop` runs a manual drop of a field, then MORE work "
            "that can panic (`?` / `.unwrap()` / index / user call) follows in "
            "the same function. If that work unwinds, an outer cleanup / the "
            "struct `Drop` can re-drop the already-dropped field - a double-free "
            "across the panic window. MEDIUM: whether an outer path re-drops the "
            "field is not fully resolvable statically."))

    # ------------------------------------------------- (4) rebuild-drop-then-write
    for m in _DROP_IN_PLACE_RE.finditer(text):
        off = m.start()
        line = _line_of_offset(text, off)
        if _loop_body_containing(off) is not None:
            continue  # loop form handled above.
        body_start, body_end = _enclosing_fn_body(text, off)
        stmt_end = text.find(";", off)
        if stmt_end == -1:
            continue
        # look for a write to the same slot within the next ~240 chars.
        after = text[stmt_end + 1:stmt_end + 1 + 240]
        wr = _PTR_WRITE_RE.search(after) or re.search(
            r"\*\s*[A-Za-z_][\w.]*\s*=", after)
        if not wr:
            continue
        # exception-safe if a consume marker sits between the drop and the write.
        gap = after[:wr.start()]
        if _CONSUME_RE.search(gap):
            continue
        key = ("rebuild", line)
        if key in seen:
            continue
        seen.add(key)
        fn = _enclosing_function(text, off)
        rows.append(_mk_row(
            rel, fn, line, "rebuild-drop-then-write", False, "element-drop",
            _excerpt(text, off), "high",
            "a slot is `drop_in_place`-d and then OVERWRITTEN with a new element, "
            "with a panic window between the drop and the write while `len` still "
            "counts the slot. If constructing the replacement (or any work "
            "before the write) panics, the container `Drop` re-reads the "
            "already-dropped slot -> double-free / UAF. HIGH: drop precedes the "
            "write with no consume marker in between."))

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
        "by_unsafe_form": _count(rows, "unsafe_form"),
        "by_panic_window": _count(rows, "panic_window"),
        "by_severity": _count(rows, "severity"),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="GEN-R1 panic-during-drop double-drop / UAF exception-safety "
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
    _emit_sidecar(ws, rows)
    summ = _summary(rows)
    print(json.dumps(summ, indent=2))
    return 1 if (strict and summ["fired"]) else 0


if __name__ == "__main__":
    sys.exit(main())
