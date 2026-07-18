#!/usr/bin/env python3
"""raii-drop-glue-bypass-on-error-path-screen.py - the RAII / DROP-GLUE-BYPASS ->
MULTI-PATH-OVERWRITE screen (EXT07). A GENERAL, impact-agnostic detector for a
Rust language-intrinsic resource-safety class: a hand-written RAW memory write
into a slot that holds (or may hold) an OWNED value bypasses Rust's automatic
drop glue, and a SECOND path (a later exception, a metering trap, an early error
return) overwrites the same slot with another raw write - so the first value's
destructor never runs (leak; or, where the slot is later read/freed, double-free
/ use-after-free).

GENERAL LOGIC / TRUST-ENFORCEMENT class (never a bug SHAPE). It instantiates the
north-star method ("A TRUSTED ENFORCEMENT is bypassable or its private invariant
is unsound") for the language's automatic RAII:

  DELEGATED-TRUSTED INVARIANT : Rust's drop glue is trusted to run every owned
    value's destructor exactly once when its slot is overwritten or goes out of
    scope. Manual resource code (`ptr::write`, a raw `*mut T = _` store, a
    `.write()` through a raw pointer, a `mem::transmute`, a union field store)
    into a slot typed to OWN heap data (`String`, `Box<_>`, `Vec<_>`, a boxed
    error / `Result<_,E>`, an owned VM `Instance`) BYPASSES that drop glue.
  PRIVATE INVARIANT           : every raw overwrite of such a slot is preceded by
    an explicit `drop` / `mem::replace` / `mem::take` / `ptr::drop_in_place` /
    `.take()` (or the write is single-shot into freshly-allocated / uninitialised
    memory). The manual write is only sound if the prior owned value is disposed
    on EVERY path that can reach the overwrite.
  ATTACK                      : the sequence of writes is ASSUMED atomic / single-
    shot while actually being SEQUENTIAL and attacker-influenceable - a first path
    stores an owned heap allocation into the slot, a SECOND path (a later error /
    metering trap / early return the attacker can steer) raw-overwrites the slot
    WITHOUT an intervening drop, so the first value's destructor is silently
    skipped. NORTH-STAR "must-move-together set partial-updated": the slot and its
    owned allocation desync exactly on the error path.

Anchor (real incident): Solana sBPF JIT - `OptRetValPtr` holds a pointer to a
`ProgramResult<E>` in the host VM struct, filled via raw writes that "bypass
Rust's drop glue"; an unresolved-symbol error heap-allocates a `String`, then a
subsequent instruction-meter exception overwrites the result slot without running
the destructor - a leak, because exception handling is sequential, not atomic.
(https://www.zellic.io/blog/solana-sbpf)

Enforcement points = every hand-written raw drop-glue-bypassing write. The screen
answers per point:
  {write_kind, slot, slot_is_field, slot_owns_heap, multi_write_same_slot,
   intervening_drop, error_path_context, overwrite_plausible}
and flags (WARN, verdict=needs-fuzz) ONLY when the raw write is into a slot that
MAY OWN heap data, there is NO intervening drop/replace/take, AND the overwrite is
plausible on a second path - either:
  - Arm A (sequential): >=2 raw writes to the SAME slot in the enclosing fn (the
    slot is raw-overwritten without a drop between the writes), OR
  - Arm B (persistent field, error path): the slot is a struct FIELD (self.<f>,
    a long-lived result/return pointer) raw-written while the enclosing fn has
    error/trap/return-path context - a second error path can overwrite the slot
    across calls (the sBPF `OptRetValPtr` shape).
Single-shot writes into a fresh local out-pointer / uninitialised memory stay
SILENT (nothing owned is being clobbered) - this is NOT a "contains-unsafe" or a
Send/Sync detector.

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False. It NEVER auto-credits and NEVER fail-closes in default mode; the
opt-in env AUDITOOOR_RAII_DROP_GLUE_STRICT (or --strict) only raises the exit code
when a fired point exists.

Language: Rust (.rs). Silent on other trees.

Usage:
  --workspace <ws>   scan <ws>/src -> .auditooor/raii_drop_glue_bypass_hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON (NO sidecar write)
  --file <f>         scan a single .rs file, print rows as JSON
  --check            re-read the emitted sidecar, print cert verdict (advisory)
  --strict           (or env) elevate exit code when a fired point exists
  --json             machine summary to stdout
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

HYP_SCHEMA = "auditooor.raii_drop_glue_bypass_hypotheses.v1"
_SIDE_NAME = "raii_drop_glue_bypass_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_RAII_DROP_GLUE_STRICT"
_CAPABILITY = "EXT07"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmarks", "script", "scripts", "deployments",
              "prior_audits", "reference", "reports", "fuzz_runs", "cost_runs",
              "mining_rounds", "deep_counterexamples", "agent_outputs",
              "symbolic_runs", "poc-tests", "chimera_harnesses"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|test_fixtures|mock|mocks|benches|benchmarks?|examples|fixtures|"
    r"test-api|poc[-_]?tests?)(/|$)")

# --- generated-source exclusion (copied from declared-control-mutator-...) ---
_GENERATED_SUFFIXES = (
    ".pb.go", ".pulsar.go", "_gen.go", ".gen.go", ".pb.rs", ".gen.rs")
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


def _iter_source_files(root: Path):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        if _TEST_HINT.search(dp.replace(os.sep, "/")):
            continue
        for f in fn:
            low = f.lower()
            if not low.endswith(".rs"):
                continue
            if low.endswith("_test.rs") or low.endswith(".t.sol"):
                continue
            if _TEST_HINT.search(f):
                continue
            p = Path(dp) / f
            if _is_generated_source(p):
                continue
            yield p


# --- raw drop-glue-bypassing write lexicon ----------------------------------
# ptr::write / ptr::write_unaligned / ptr::write_volatile  (qualified). NOTE:
# write_bytes (memset) and copy/copy_nonoverlapping are deliberately EXCLUDED -
# they fill primitive bytes / move buffers, not clobber-an-owned-value.
_PTR_WRITE_RE = re.compile(
    r"(?<![.\w])(?:std::|core::)?ptr::(write_unaligned|write_volatile|write)\s*\(")
# method-form raw-pointer write:  <raw ptr expr>.write[_unaligned|_volatile](...)
# gated on the receiver looking like a RAW POINTER (as_ptr / as_mut_ptr / cast /
# add / offset / NonNull / an *_ptr identifier) so io::Write / RwLock::write /
# File::write / serialize `.write(w)` never match.
_METHOD_WRITE_RE = re.compile(
    r"([A-Za-z_][\w:]*(?:\s*\.\s*(?:as_ptr|as_mut_ptr|cast|add|offset|"
    r"get_unchecked_mut|get_unchecked)\s*(?:::<[^>]*>)?\s*\([^()]*\)|_ptr))"
    r"\s*\.\s*(write_unaligned|write_volatile|write)\s*\(")
# transmute (a re-type that can move-without-drop) - lower confidence, advisory.
_TRANSMUTE_RE = re.compile(
    r"(?<![.\w])(?:std::|core::)?mem::transmute(?:_copy)?\s*(?:::<[^>]*>)?\s*\(")
# raw deref-store  *<ptrish> = <val>   (requires enclosing unsafe; LHS pointerish)
_DEREF_STORE_RE = re.compile(
    r"(?<![\w)\]])\*\s*([A-Za-z_][\w.]*)\s*=\s*(?![=])")

# a LHS/slot identifier that names a RAW pointer / owned-result slot.
_PTRISH_SLOT_RE = re.compile(
    r"(?:^|[._])(?:ptr|out|ret|retval|ret_val|result|slot|dst|dest|p)$",
    re.I)

# --- owned-heap value / slot lexicons ---------------------------------------
# the WRITTEN VALUE constructs / owns heap (the RAII-relevant condition).
_OWNED_VALUE_RE = re.compile(
    r"(?:\bString\b|\bBox\b|\bVec\b|\bRc\b|\bArc\b|\bCString\b|\bBTreeMap\b|"
    r"\bHashMap\b|\bBox::from_raw|format!\s*\(|\.clone\s*\(\)|\.to_string\s*\(\)|"
    r"\.to_owned\s*\(\)|\.to_vec\s*\(\)|\.into\s*\(\)|::from\s*\(|::new\s*\(|"
    r"::with_capacity\s*\(|Err\s*\(|Ok\s*\(|Some\s*\()")
# a SLOT whose NAME denotes an owned-heap / result / error container (the anchor's
# OptRetValPtr / ProgramResult family, plus owned VM structs).
_OWNED_SLOT_TOKENS = (
    "ret", "retval", "ret_val", "result", "program_result", "opt_ret",
    "optret", "error", "err", "exception", "string", "boxed", "box", "vec",
    "buf", "buffer", "output", "instance", "handle", "owned", "alloc", "value",
    "val", "slot", "payload", "env")

# owned-slot token must appear as a whole underscore/dot segment (so `values` /
# `valid` do not match `val`, `errors`-plural is still err-rooted -> counted).
_OWNED_SLOT_SEG_RE = re.compile(
    r"(?:^|[._])(" + "|".join(re.escape(t) for t in _OWNED_SLOT_TOKENS) + r")(?:[._]|$)",
    re.I)

# intervening drop / replace / take management of the prior owned value.
_DROP_MGMT_TOKENS = (
    "drop", "mem::replace", "mem::take", "mem::swap", "drop_in_place",
    "ManuallyDrop", "mem::forget", ".take()", "into_inner", "assume_init",
    "read(", "ptr::read")

# error / trap / early-return context in the enclosing fn (the "second path").
_ERR_CTX_RE = re.compile(
    r"(?:\bErr\s*\(|\breturn\s+Err|\?\s*;|\btrap\b|\bexception\b|\bunwind\b|"
    r"\bpanic\b|\bbail\b|\babort\b|\bmeter\b|\bmetering\b|\bthrow\b|"
    r"\bearly[_ ]?return\b|\bResult<|\bcatch_unwind\b)",
    re.I)


# --- Rust function extraction (brace-matched) -------------------------------
_FN_DECL_RE = re.compile(
    r"(?:^|\n)([ \t]*)(?:pub(?:\s*\([^)]*\))?\s+)?"
    r"(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+\"[^\"]*\"\s+)?"
    r"fn\s+([A-Za-z_]\w*)")


def _line_starts(text: str):
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def _off_to_line(starts, off):
    # binary-ish search; lists are small enough per file
    lo, hi = 0, len(starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if starts[mid] <= off:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1


def _match_block(text, open_idx):
    """Given the index of a `{`, return the index just past the matching `}`.
    Skips string / char / line- and block-comments crudely."""
    depth = 0
    i = open_idx
    n = len(text)
    in_str = None  # '"' or "'"
    while i < n:
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
            i += 1
            continue
        if ch == '"' or ch == "'":
            in_str = ch
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def _iter_functions(text):
    """Yield (fn_name, body_start_off, body_end_off, body_text)."""
    for m in _FN_DECL_RE.finditer(text):
        name = m.group(2)
        brace = text.find("{", m.end())
        if brace < 0:
            continue
        semi = text.find(";", m.end())
        if 0 <= semi < brace:
            continue  # trait method decl / fn pointer type, no body
        end = _match_block(text, brace)
        yield name, brace, end, text[brace:end]


def _balanced_args(text, open_paren_idx):
    """From the index of `(`, return (args_str, end_idx_past_close)."""
    depth = 0
    i = open_paren_idx
    n = len(text)
    in_str = None
    start = open_paren_idx + 1
    while i < n:
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
            i += 1
            continue
        if ch == '"' or ch == "'":
            in_str = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[start:i], i + 1
        i += 1
    return text[start:], n


def _split_top_commas(s):
    out = []
    depth = 0
    cur = []
    in_str = None
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if in_str:
            if ch == "\\":
                cur.append(ch)
                if i + 1 < n:
                    cur.append(s[i + 1])
                i += 2
                continue
            if ch == in_str:
                in_str = None
            cur.append(ch)
            i += 1
            continue
        if ch == '"' or ch == "'":
            in_str = ch
        elif ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth -= 1
        elif ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    out.append("".join(cur))
    return [a.strip() for a in out if a.strip() != ""]


def _normalize_slot(expr):
    """Strip pointer-projection suffixes to the core slot identity."""
    e = expr.strip()
    # strip a leading & / &mut
    e = re.sub(r"^&\s*(mut\s+)?", "", e).strip()
    # strip trailing pointer projections repeatedly
    prev = None
    while prev != e:
        prev = e
        e = re.sub(
            r"\s*\.\s*(as_ptr|as_mut_ptr|cast|add|offset|get_unchecked_mut|"
            r"get_unchecked|as_mut|as_ref)\s*(?:::<[^>]*>)?\s*\([^()]*\)\s*$",
            "", e)
        e = re.sub(r"\s+as\s+\*\s*(?:mut|const)\s+[\w:<>]+\s*$", "", e)
        e = e.strip()
    # drop an index / call tail
    e = re.sub(r"\s*\([^()]*\)\s*$", "", e).strip()
    return e


def _slot_core_ident(slot):
    """A grep-able core identifier for drop-management correlation."""
    m = re.search(r"([A-Za-z_][\w.]*)\s*$", slot)
    core = m.group(1) if m else slot
    # last dotted segment, e.g. self.instance_ptr -> instance_ptr
    return core.split(".")[-1] if "." in core else core


def _slot_may_own_heap(slot, value):
    """LOAD-BEARING sub-predicate: does the slot hold / receive an OWNED heap
    value (the RAII-relevant condition)? True if the written value constructs /
    clones owned heap, OR the slot NAME denotes a result/error/owned container."""
    if value and _OWNED_VALUE_RE.search(value):
        return True
    if _OWNED_SLOT_SEG_RE.search(slot or ""):
        return True
    return False


def _overwrite_plausible(total_writes, seq_writes, slot_is_field, error_path_context):
    """LOAD-BEARING core predicate: is a SECOND-path raw overwrite of this slot
    plausible while the first owned value may still be live?
      Arm A - the slot is raw-written >=2x in the same fn AND at least one of the
              writes is a PLAIN SEQUENTIAL statement (not a mutually-exclusive
              match-arm / if-else branch body), so one write can overwrite a slot
              the other already filled;
      Arm B - the slot is a persistent struct field filled on an error/return
              path (a second error path can overwrite it across calls).
    Purely branch-exclusive sibling writes (every write is a match-arm / if-else
    body, e.g. `Pat => ptr::write(p, v)` into a fresh out-pointer) are NOT a
    sequential overwrite and stay SILENT (seq_writes==0)."""
    arm = ""
    if total_writes >= 2 and seq_writes >= 1:
        arm = "A-sequential-double-write"
    elif slot_is_field and error_path_context:
        arm = "B-persistent-field-error-path"
    return (arm != ""), arm


_IFELSE_BEFORE_BRACE_RE = re.compile(r"\b(if|else|else\s+if)\b[^{};]*$")


def _is_branch_body(body, off):
    """Is the write at `off` the body of a mutually-exclusive branch - a match arm
    (`Pat => write(...)`) or an if/else block body? Such sibling writes are NOT a
    sequential overwrite of each other."""
    pre = body[max(0, off - 400):off]
    # nearest governing separator among ; { } =>
    idx_arrow = pre.rfind("=>")
    idx_semi = pre.rfind(";")
    idx_open = pre.rfind("{")
    idx_close = pre.rfind("}")
    last = max(idx_arrow, idx_semi, idx_open, idx_close)
    if last < 0:
        return False
    if last == idx_arrow:
        return True  # match-arm body
    if last == idx_open:
        # block body: was the `{` opened by an if / else?
        before_brace = pre[:idx_open]
        if _IFELSE_BEFORE_BRACE_RE.search(before_brace):
            return True
    return False


def _find_raw_writes(body):
    """Return list of dicts {kind, slot, value, off, branch_body} per raw write."""
    writes = []
    in_unsafe = ("unsafe" in body)  # coarse; deref-store gated on this

    # ptr::write family
    for m in _PTR_WRITE_RE.finditer(body):
        kind = "ptr_" + m.group(1)
        open_paren = body.find("(", m.end() - 1)
        args, _ = _balanced_args(body, open_paren)
        parts = _split_top_commas(args)
        slot_expr = parts[0] if parts else ""
        value = parts[1] if len(parts) > 1 else ""
        writes.append({"kind": kind, "slot": _normalize_slot(slot_expr),
                       "value": value, "off": m.start()})

    # method-form raw-pointer write
    for m in _METHOD_WRITE_RE.finditer(body):
        recv = m.group(1)
        meth = m.group(2)
        open_paren = body.find("(", m.end() - 1)
        args, _ = _balanced_args(body, open_paren)
        value = args.strip()
        writes.append({"kind": "method_" + meth, "slot": _normalize_slot(recv),
                       "value": value, "off": m.start()})

    # transmute (advisory)
    for m in _TRANSMUTE_RE.finditer(body):
        # slot = LHS if this transmute is on the RHS of an assignment
        line_start = body.rfind("\n", 0, m.start()) + 1
        prefix = body[line_start:m.start()]
        lhs = ""
        am = re.search(r"([A-Za-z_][\w.\[\]]*)\s*=\s*$", prefix)
        if am:
            lhs = am.group(1)
        writes.append({"kind": "transmute", "slot": _normalize_slot(lhs) or "<transmute>",
                       "value": "transmute", "off": m.start()})

    # raw deref-store *ptrish = value   (requires unsafe context + pointerish LHS)
    if in_unsafe:
        for m in _DEREF_STORE_RE.finditer(body):
            lhs = m.group(1)
            core = lhs.split(".")[-1]
            if not _PTRISH_SLOT_RE.search(core):
                continue
            # skip compound-assign forms already excluded by regex; capture value
            eq = body.find("=", m.start())
            eol = body.find("\n", eq)
            value = body[eq + 1: eol if eol >= 0 else len(body)].strip()
            writes.append({"kind": "raw_deref_store",
                           "slot": _normalize_slot(lhs), "value": value,
                           "off": m.start()})
    for w in writes:
        w["branch_body"] = _is_branch_body(body, w["off"])
    return writes


def _intervening_drop_for(body, slot_core):
    """Is the prior owned value of `slot_core` disposed (drop/replace/take/...)
    somewhere in the fn body? Coarse but advisory - presence of drop-management
    referencing the slot core, or a slot-agnostic drop_in_place / ManuallyDrop
    over the same identifier."""
    if not slot_core:
        return False
    esc = re.escape(slot_core)
    patterns = [
        r"\bdrop\s*\(\s*[^)]*" + esc,
        r"mem::replace\s*\(\s*[^,]*" + esc,
        r"mem::take\s*\(\s*[^)]*" + esc,
        r"mem::swap\s*\([^)]*" + esc,
        r"drop_in_place\s*\(\s*[^)]*" + esc,
        r"mem::forget\s*\(\s*[^)]*" + esc,
        esc + r"\s*\.\s*take\s*\(\s*\)",
        esc + r"\s*\.\s*assume_init",
        r"ManuallyDrop::new\s*\(\s*[^)]*" + esc,
        # the prior owned value is moved OUT via ptr::read (then dropped) - the
        # canonical "take the old value before overwriting" disposition.
        r"(?:std::|core::)?ptr::read(?:_unaligned|_volatile)?\s*\(\s*[^)]*" + esc,
    ]
    for pat in patterns:
        if re.search(pat, body):
            return True
    return False


def scan_file(path: Path, rel: str, file_text: str = None):
    if file_text is None:
        try:
            file_text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            return []
    if "ptr::write" not in file_text and ".write" not in file_text \
            and "transmute" not in file_text and "*" not in file_text:
        return []
    starts = _line_starts(file_text)
    rows = []
    for fn_name, bstart, bend, body in _iter_functions(file_text):
        writes = _find_raw_writes(body)
        if not writes:
            continue
        error_ctx = bool(_ERR_CTX_RE.search(body))
        # per-slot total + sequential (non-branch-body) write counts
        slot_total = {}
        slot_seq = {}
        for w in writes:
            slot_total[w["slot"]] = slot_total.get(w["slot"], 0) + 1
            if not w.get("branch_body"):
                slot_seq[w["slot"]] = slot_seq.get(w["slot"], 0) + 1
        for w in writes:
            slot = w["slot"]
            value = w["value"]
            abs_off = bstart + w["off"]
            line = _off_to_line(starts, abs_off)
            slot_is_field = bool(re.match(r"(self|this)\s*\.", slot)) or \
                ("." in slot and not slot.startswith("("))
            slot_core = _slot_core_ident(slot)
            owns_heap = _slot_may_own_heap(slot, value)
            total = slot_total.get(slot, 1)
            seq = slot_seq.get(slot, 0)
            intervening = _intervening_drop_for(body, slot_core)
            plausible, arm = _overwrite_plausible(total, seq, slot_is_field, error_ctx)
            fires = bool(owns_heap and (not intervening) and plausible)
            if not fires:
                arm = ""
            reason = (
                "raw drop-glue-bypassing {} into owned slot '{}' "
                "({}; intervening_drop={})".format(
                    w["kind"], slot or "<?>", arm or "not-plausible",
                    intervening))
            rows.append({
                "capability": _CAPABILITY,
                "schema": HYP_SCHEMA,
                "fires": fires,
                "file": rel,
                "line": line,
                "function": fn_name,
                "advisory": True,
                "auto_credit": False,
                "verdict": "needs-fuzz",
                "write_kind": w["kind"],
                "slot": slot,
                "slot_is_field": slot_is_field,
                "slot_owns_heap": owns_heap,
                "written_value": value[:120],
                "multi_write_same_slot": total,
                "seq_write_same_slot": seq,
                "intervening_drop": intervening,
                "error_path_context": error_ctx,
                "overwrite_plausible": plausible,
                "arm": arm,
                "reason": reason,
                "recommendation": (
                    "wrap the slot in an owned type or use mem::replace + explicit "
                    "drop before the raw overwrite; verify the prior value's "
                    "destructor runs on EVERY error/return path that reaches the "
                    "write (leak / double-free / UAF otherwise)"),
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
        "arm_A": sum(1 for r in fired if r.get("arm", "").startswith("A")),
        "arm_B": sum(1 for r in fired if r.get("arm", "").startswith("B")),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="EXT07 RAII/drop-glue-bypass -> multi-path-overwrite screen (advisory)")
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
        return 1 if (strict and any(r.get("fires") for r in rows)) else 0

    if args.source:
        rows = scan_tree(Path(args.source))
        print(json.dumps(rows, indent=2))
        return 1 if (strict and any(r.get("fires") for r in rows)) else 0

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
