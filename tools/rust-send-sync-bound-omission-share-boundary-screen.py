#!/usr/bin/env python3
"""rust-send-sync-bound-omission-share-boundary-screen.py - the AUTO-TRAIT
(Send/Sync/'static) BOUND-OMISSION AT A SHARE BOUNDARY screen (EXT06).

GENERAL LOGIC / TYPE-SIGNATURE-SOUNDNESS class (never a bug SHAPE). It
instantiates one language-intrinsic Rust soundness property that no per-function
data-race detector owns:

  THE ENFORCEMENT POINT : every API (pub fn / impl method / manual `unsafe impl
    Send|Sync`) that STORES, REGISTERS, SPAWNS, or HANDS ACROSS a
    thread/executor/FFI-runtime boundary a value of a GENERIC or TYPE-ERASED
    callable type - a closure (`F: Fn/FnMut/FnOnce`), an `impl Fn*`, a
    `Box<dyn Fn*>` / `Arc<dyn Fn*>`, or a `Future` (`F: Future`, `impl Future`,
    `Pin<Box<dyn Future>>`).
  THE PRIVATE INVARIANT : the trait bound declared on that type carries
    `Send`/`Sync`/`'static` to the exact DEGREE the value is actually used at the
    boundary:
      - MOVED to a spawned thread / executor task  -> the value must be `Send`
        + `'static`.
      - SHARED behind `&` and INVOKED-REPEATEDLY by a foreign runtime / stored in
        a Sync container (a callback registry, `PyCFunction::new_closure`, an
        `Arc<dyn Fn>` handed to another thread) -> a repeatably-callable `Fn` /
        `FnMut` must additionally be `Sync` (a once-consumed `FnOnce` / a moved
        `Future` needs only `Send` + `'static`).
  THE ATTACK           : the declared bound is WEAKER than the sharing the API
    performs. Because a type-ERASED container (`Box<dyn Fn + Send>`, an FFI object
    manually marked `Send + Sync`) BREAKS auto-trait propagation, the compiler
    cannot re-derive the missing bound, and neither type-check nor clippy flags
    it. A downstream SAFE caller then inserts a non-Send / non-Sync payload
    (`Rc`, `Cell`, `RefCell`, a thread-affine handle, a raw pointer) that the API
    shares or moves across threads - a data race with NO `unsafe` written by the
    user.

Anchor: pyo3 RUSTSEC-2026-0177 - `PyCFunction::new_closure` bounds its closure
`F: Fn(...) + Send + 'static` but OMITS `Sync`, then registers it with the Python
runtime where the resulting callable is shared across threads; a `!Sync` closure
becomes concurrently reachable -> data race.

WHY NET-NEW: this is NOT a call-site data-race detector. The defect is the ABSENCE
of a bound in an API CONTRACT, weaponized later by a safe downstream user - not
any single racy statement in the crate. Standard detectors do not audit auto-trait
propagation / bound-sufficiency across API/FFI boundaries.

  NET-NEW value is scoped to the REGISTER (foreign-runtime / FFI) and
  UNSAFE-AUTO-IMPL arms: those sinks BREAK auto-trait propagation (a manual
  `unsafe impl Send|Sync`, or a runtime that stores the value behind an opaque
  handle), so a missing bound is genuinely compiler-MISSED - it slips through
  both `rustc` and `clippy` (the pyo3 RUSTSEC-2026-0177 anchor).

  The SPAWN arm is COMPILER-REDUNDANT whenever the value is handed to a
  well-known spawn primitive (`std::thread::spawn`, `tokio::spawn`,
  `rayon::spawn`, a scoped `scope.spawn`, or a `.boxed()` -> `BoxFuture`
  hand-off): the primitive's own signature bounds `Send` (+ `'static`), so
  `rustc` already rejects a missing bound with E0277. Such rows are down-ranked
  (`compiler_redundant=True`, `fires=False`) via `_compiler_covered_bounds`;
  the spawn arm only fires when the sink is a USER-DEFINED `spawn`-named method
  that does NOT enforce the bound at its own signature.

Enforcement points = every (fn, callable type-param, boundary-kind) where the value
crosses a share/send/register boundary, plus every manual `unsafe impl Send|Sync`
over a type-erased-callable-holding type. The screen answers per point:
  {boundary_kind, callable_kind, required_bounds, declared_bounds, missing_bounds}
and flags (fires=True, verdict='needs-fuzz') ONLY when `missing_bounds` is
non-empty - a required auto-trait / lifetime bound is not declared to the degree
the boundary demands.

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False. It NEVER auto-credits and NEVER fail-closes in default mode; the
opt-in env AUDITOOOR_SEND_SYNC_BOUND_STRICT (or --strict) only raises the exit code
when a fired point exists.

Language: Rust (.rs). Silent on other trees.

Usage:
  --workspace/--ws <ws>  scan <ws>/src (or <ws>) -> .auditooor/<sidecar>.jsonl + summary
  --source <dir>         scan an arbitrary dir, print rows as JSON (NO sidecar)
  --file <f>             scan a single .rs file, print rows as JSON
  --check                re-read the emitted sidecar, print cert verdict (advisory)
  --strict               (or env) elevate exit code when a fired point exists
  --json                 machine summary to stdout
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

HYP_SCHEMA = "auditooor.send_sync_bound_omission_hypotheses.v1"
_SIDE_NAME = "send_sync_bound_omission_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_SEND_SYNC_BOUND_STRICT"
_CAPABILITY = "EXT06"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmark", "benchmarks", "fuzz", "examples",
              "prior_audits", "reference", "docs"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|test_fixtures|mock|mocks|benches|benchmarks?|examples|"
    r"fixtures|fuzz)(/|$)")

# ---------------------------------------------------------------------------
# Machine-generated source exclusion (copied from
# tools/declared-control-mutator-completeness-screen.py). abigen / prost / tonic /
# bindgen output is NOT the audited attack surface.
# ---------------------------------------------------------------------------
_GENERATED_SUFFIXES = (
    ".pb.go", ".pulsar.go", ".pb.gw.go", "_gen.go", ".gen.go", "_generated.go",
    ".pb.rs", "_gen.rs", ".gen.rs", "_generated.rs",
)
_GENERATED_SENTINEL = re.compile(r"Code generated .{0,80}?DO NOT EDIT", re.I)
# Rust codegen sentinels: prost/tonic ("Generated ... [prost/tonic]"),
# bindgen ("Automatically generated ...  DO NOT EDIT"), and a bare
# "@generated" marker.
_RUST_GENERATED_SENTINEL = re.compile(
    r"(@generated|Automatically generated|This file (is|was) (auto[- ]?)?generated|"
    r"Generated (by|from) .{0,60}?(prost|tonic|bindgen|protoc))", re.I)


def _is_generated_source(path: Path) -> bool:
    if path.name.lower().endswith(_GENERATED_SUFFIXES):
        return True
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096)
    except (OSError, UnicodeError):
        return False
    return bool(_GENERATED_SENTINEL.search(head)
                or _RUST_GENERATED_SENTINEL.search(head))


def _iter_source_files(root: Path):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        if _TEST_HINT.search(dp.replace(os.sep, "/")):
            continue
        for f in fn:
            low = f.lower()
            if not low.endswith(".rs"):
                continue
            if low.endswith("_test.rs") or low.endswith("_tests.rs"):
                continue
            if _TEST_HINT.search(f):
                continue
            p = Path(dp) / f
            if _is_generated_source(p):
                continue
            yield p


# ---------------------------------------------------------------------------
# Rust-aware comment / string masker.
#
# CRITICAL: it must NOT eat a `'static` lifetime (needed by the detector). Char
# literals ('a', '\n', '{') ARE masked (so a stray brace/quote inside one cannot
# derail brace-matching), but a lifetime `'ident` (no closing quote) is left
# intact. Handles // line comments, /* */ block comments (Rust-nestable),
# "..." strings (with \-escapes), and raw strings r"...", r#"..."#, r##"..."##.
# Errs toward SILENCE: a masked span can only DROP a would-be token, never invent
# one. Newlines are preserved so line indices stay source-accurate.
# ---------------------------------------------------------------------------
_CHAR_LIT_RE = re.compile(r"'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f]+\}|.)|[^'\\\n])'")


def _mask_rust(text: str) -> str:
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        # line comment
        if c == "/" and nxt == "/":
            j = text.find("\n", i)
            if j == -1:
                out.append(" " * (n - i))
                break
            out.append("  " + " " * (j - i - 2))
            i = j
            continue
        # block comment (nestable)
        if c == "/" and nxt == "*":
            depth = 1
            out.append("  ")
            i += 2
            while i < n and depth > 0:
                if text[i] == "/" and i + 1 < n and text[i + 1] == "*":
                    depth += 1
                    out.append("  ")
                    i += 2
                elif text[i] == "*" and i + 1 < n and text[i + 1] == "/":
                    depth -= 1
                    out.append("  ")
                    i += 2
                else:
                    out.append("\n" if text[i] == "\n" else " ")
                    i += 1
            continue
        # raw string  r"..."  / r#"..."#  / br"..." ...
        if c in ("r", "b") and _is_raw_string_start(text, i):
            i, masked = _consume_raw_string(text, i)
            out.append(masked)
            continue
        # normal string "..."
        if c == '"':
            out.append(" ")
            i += 1
            while i < n:
                if text[i] == "\\":
                    out.append("  " if i + 1 < n else " ")
                    i += 2
                    continue
                if text[i] == '"':
                    out.append(" ")
                    i += 1
                    break
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            continue
        # char literal (but NOT a lifetime)
        if c == "'":
            m = _CHAR_LIT_RE.match(text, i)
            if m:
                out.append(" " * (m.end() - m.start()))
                i = m.end()
                continue
            # lifetime - leave intact
            out.append(c)
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _is_raw_string_start(text: str, i: int) -> bool:
    # r"  r#"  r##"  br"  br#"
    j = i
    if text[j] == "b":
        j += 1
    if j >= len(text) or text[j] != "r":
        return False
    j += 1
    while j < len(text) and text[j] == "#":
        j += 1
    return j < len(text) and text[j] == '"'


def _consume_raw_string(text: str, i: int):
    n = len(text)
    j = i
    if text[j] == "b":
        j += 1
    j += 1  # skip 'r'
    hashes = 0
    while j < n and text[j] == "#":
        hashes += 1
        j += 1
    # text[j] == '"'
    j += 1
    close = '"' + ("#" * hashes)
    end = text.find(close, j)
    if end == -1:
        end = n
        stop = n
    else:
        stop = end + len(close)
    span = text[i:stop]
    masked = "".join("\n" if ch == "\n" else " " for ch in span)
    return stop, masked


# ---------------------------------------------------------------------------
# Callable-trait / bound lexicon
# ---------------------------------------------------------------------------
_FN_TRAITS = ("FnOnce", "FnMut", "Fn")           # order = specificity
_FUTURE_TRAIT_RE = re.compile(r"\bFuture\b")
_FNONCE_RE = re.compile(r"\bFnOnce\b")
_FNMUT_RE = re.compile(r"\bFnMut\b")
_FN_RE = re.compile(r"\bFn\b")
_SEND_RE = re.compile(r"\bSend\b")
_SYNC_RE = re.compile(r"\bSync\b")
_STATIC_RE = re.compile(r"'static\b")

# Spawn sinks (require Send + 'static): a closed, high-confidence identifier set
# so a domain method that merely embeds "spawn" as a substring (respawn / despawn
# / spawn_local - the last needs NO Send) does not FP.
_SPAWN_IDENTS = {
    "spawn", "spawn_boxed", "spawn_blocking", "spawn_fifo", "spawn_pinned",
    "spawn_task", "spawn_named", "spawn_ok", "spawn_obj", "spawn_async",
    "spawn_with_handle", "spawn_boxed_future",
}
# Register / foreign-runtime sinks (require Send + 'static; + Sync for a
# repeatably-callable Fn/FnMut). FFI-shaped, keeps the pyo3 `new_closure` anchor.
_REGISTER_EXACT = {
    "new_closure", "add_hook", "set_handler", "install_handler", "store_callback",
    "set_hook",
}
_REGISTER_PREFIX = ("register", "subscribe")
_REGISTER_SUBSTR = ("callback", "listener", "observer")


def _callable_kind(bound_text: str):
    """Return 'FnOnce'|'FnMut'|'Fn'|'Future' if bound_text names a callable/future
    trait, else None."""
    if _FNONCE_RE.search(bound_text):
        return "FnOnce"
    if _FNMUT_RE.search(bound_text):
        return "FnMut"
    if _FN_RE.search(bound_text):
        return "Fn"
    if _FUTURE_TRAIT_RE.search(bound_text):
        return "Future"
    return None


# A lifetime used AS A BOUND (`+ 'a`), excluding `'static`. Argument-position
# lifetimes (`&'a X`) and HRTB (`for<'a>`) are NOT object-lifetime bounds and must
# not be read as "non-'static".
_NAMED_LT_BOUND_RE = re.compile(r"\+\s*'(?!static\b)[a-z_]\w*")


def _declared_bounds(bound_text: str, is_type_erased: bool = False):
    """Effective auto-trait / lifetime bounds a caller can rely on.

    Rust's DEFAULT OBJECT LIFETIME rule: a boxed/ref-counted trait object
    (`Box<dyn Trait>`, `Arc<dyn Trait>`) with NO explicit lifetime bound elides to
    `+ 'static`. So a type-erased callable is `'static` unless it carries an
    EXPLICIT non-'static lifetime bound (`Box<dyn Fn + 'a>`). Generic / APIT
    (`impl Fn`) params get NO such default - their `'static` must be written."""
    d = set()
    if _SEND_RE.search(bound_text):
        d.add("Send")
    if _SYNC_RE.search(bound_text):
        d.add("Sync")
    if _STATIC_RE.search(bound_text):
        d.add("'static")
    elif is_type_erased and not _NAMED_LT_BOUND_RE.search(bound_text):
        # implicit default object lifetime == 'static
        d.add("'static")
    return d


def _is_spawn_ident(ident: str) -> bool:
    return ident in _SPAWN_IDENTS


def _is_register_ident(ident: str) -> bool:
    il = ident.lower()
    if il in _REGISTER_EXACT:
        return True
    if any(il.startswith(p) for p in _REGISTER_PREFIX):
        return True
    if any(s in il for s in _REGISTER_SUBSTR):
        return True
    return False


# ---------------------------------------------------------------------------
# Balanced-delimiter helpers
# ---------------------------------------------------------------------------
def _match_close(text: str, open_idx: int, open_ch: str, close_ch: str):
    """Return index just PAST the delimiter matching text[open_idx]==open_ch."""
    depth = 0
    i, n = open_idx, len(text)
    while i < n:
        c = text[i]
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def _split_top(text: str):
    """Split on top-level commas (respecting <> () [] {} depth)."""
    parts, depth, buf = [], 0, []
    pairs = {"<": ">", "(": ")", "[": "]", "{": "}"}
    closers = set(pairs.values())
    stack = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        # treat -> as an atom so the '>' is not read as an angle close
        if c == "-" and i + 1 < n and text[i + 1] == ">":
            buf.append("->")
            i += 2
            continue
        if c in pairs:
            stack.append(pairs[c])
            buf.append(c)
        elif c in closers:
            if stack and stack[-1] == c:
                stack.pop()
            buf.append(c)
        elif c == "," and not stack:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(c)
        i += 1
    if buf:
        parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


def _find_top_level(text: str, needle: str):
    """Index of `needle` (a keyword like 'where') at angle/paren/bracket depth 0,
    or -1."""
    depth = 0
    i, n = 0, len(text)
    nl = len(needle)
    while i < n:
        c = text[i]
        if c == "-" and i + 1 < n and text[i + 1] == ">":
            i += 2
            continue
        if c in "<([":
            depth += 1
        elif c in ">)]":
            if depth > 0:
                depth -= 1
        elif depth == 0 and text.startswith(needle, i):
            before = text[i - 1] if i > 0 else " "
            after = text[i + nl] if i + nl < n else " "
            if not (before.isalnum() or before == "_") and \
               not (after.isalnum() or after == "_"):
                return i
        i += 1
    return -1


# ---------------------------------------------------------------------------
# Function iteration (masked text)
# ---------------------------------------------------------------------------
_FN_RE_DECL = re.compile(
    r"(?P<pfx>(?:\bpub\b(?:\s*\([^)]*\))?\s+)?(?:\basync\b\s+)?(?:\bunsafe\b\s+)?"
    r"(?:\bextern\b\s+\"[^\"]*\"\s+)?)fn\s+(?P<name>[A-Za-z_]\w*)")


def _iter_fns(text: str):
    """Yield (name, is_pub, sig_text, body_text, decl_offset) for each fn.
    sig_text spans `fn` .. the body '{' (exclusive) or the trailing ';'.
    body_text is '' for a bodyless (trait) declaration."""
    for m in _FN_RE_DECL.finditer(text):
        name = m.group("name")
        is_pub = "pub" in m.group("pfx")
        # locate signature end: first top-level '{' (body) or ';' (decl)
        i, n = m.end(), len(text)
        adepth = pdepth = bdepth = 0
        sig_end = -1
        body_brace = -1
        while i < n:
            c = text[i]
            if c == "-" and i + 1 < n and text[i + 1] == ">":
                i += 2
                continue
            if c == "<":
                adepth += 1
            elif c == ">":
                if adepth > 0:
                    adepth -= 1
            elif c == "(":
                pdepth += 1
            elif c == ")":
                if pdepth > 0:
                    pdepth -= 1
            elif c == "[":
                bdepth += 1
            elif c == "]":
                if bdepth > 0:
                    bdepth -= 1
            elif c == "{" and adepth == pdepth == bdepth == 0:
                body_brace = i
                sig_end = i
                break
            elif c == ";" and adepth == pdepth == bdepth == 0:
                sig_end = i
                break
            i += 1
        if sig_end == -1:
            continue
        sig_text = text[m.start():sig_end]
        if body_brace == -1:
            yield name, is_pub, sig_text, "", m.start()
            continue
        body_end = _match_close(text, body_brace, "{", "}")
        body_text = text[body_brace:body_end]
        yield name, is_pub, sig_text, body_text, m.start()


def _parse_sig(sig_text: str):
    """Return (generic_bounds{name->bound_text}, value_params[(name,type)]).
    Merges `<...>` bounds with `where` predicate bounds per type-param."""
    # strip leading `... fn NAME`
    mm = re.search(r"\bfn\s+[A-Za-z_]\w*", sig_text)
    rest = sig_text[mm.end():] if mm else sig_text

    generic_bounds = {}
    # generic list <...>
    lt = rest.find("<")
    paren = rest.find("(")
    if lt != -1 and (paren == -1 or lt < paren):
        gclose = _match_close(rest, lt, "<", ">")
        ginner = rest[lt + 1:gclose - 1]
        for item in _split_top(ginner):
            if item.startswith("'"):        # lifetime param
                continue
            citem = item
            if citem.startswith("const "):
                continue
            if ":" in citem:
                nm, _, bnd = citem.partition(":")
            else:
                nm, bnd = citem, ""
            ids = re.findall(r"[A-Za-z_]\w*", nm)
            if ids:
                generic_bounds.setdefault(ids[-1], "")
                if bnd.strip():
                    generic_bounds[ids[-1]] += " + " + bnd.strip()
        after_generics = rest[gclose:]
    else:
        after_generics = rest

    # value params (...)
    value_params = []
    p_open = after_generics.find("(")
    if p_open != -1:
        p_close = _match_close(after_generics, p_open, "(", ")")
        pinner = after_generics[p_open + 1:p_close - 1]
        for item in _split_top(pinner):
            low = item.strip()
            # skip self receivers
            if re.match(r"^(&\s*)?(mut\s+)?self\b", low):
                continue
            if ":" not in item:
                continue
            nm, _, ty = item.partition(":")
            ids = re.findall(r"[A-Za-z_]\w*", nm)
            if not ids:
                continue
            value_params.append((ids[-1], ty.strip()))
        after_params = after_generics[p_close:]
    else:
        after_params = after_generics

    # where clause
    w = _find_top_level(after_params, "where")
    if w != -1:
        wtext = after_params[w + len("where"):]
        for pred in _split_top(wtext):
            if ":" not in pred:
                continue
            ty, _, bnd = pred.partition(":")
            tid = ty.strip()
            if tid in generic_bounds:
                generic_bounds[tid] += " + " + bnd.strip()

    return generic_bounds, value_params


def _callable_params(sig_text: str):
    """Yield (param_name, callable_kind, bound_text, is_type_erased) for each
    value param whose type is a generic-callable / impl-callable / dyn-callable."""
    generic_bounds, value_params = _parse_sig(sig_text)
    for pname, ptype in value_params:
        pt = ptype.strip()
        # (a) generic callable: type is exactly a bounded generic name
        gid = pt.rstrip("+ ").strip()
        if gid in generic_bounds:
            bt = generic_bounds[gid]
            k = _callable_kind(bt)
            if k:
                yield pname, k, bt, False
                continue
        # (b) impl-trait callable
        if re.search(r"\bimpl\b", pt):
            k = _callable_kind(pt)
            if k:
                yield pname, k, pt, False
                continue
        # (c) dyn / boxed / arc'd callable (type-erased)
        if re.search(r"\bdyn\b", pt):
            k = _callable_kind(pt)
            if k:
                yield pname, k, pt, True
                continue


# ---------------------------------------------------------------------------
# Sink detection
# ---------------------------------------------------------------------------
_CALL_RE = re.compile(r"([A-Za-z_]\w*)\s*\(")


def _sinks_for_param(body_text: str, param: str):
    """Yield ('spawn'|'register', callee_ident) for each call in body_text that
    references `param` as a whole word inside its argument list."""
    word = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(param) + r"(?![A-Za-z0-9_])")
    for m in _CALL_RE.finditer(body_text):
        ident = m.group(1)
        is_spawn = _is_spawn_ident(ident)
        is_reg = _is_register_ident(ident)
        if not (is_spawn or is_reg):
            continue
        # arg region
        popen = m.end() - 1
        pclose = _match_close(body_text, popen, "(", ")")
        args = body_text[popen + 1:pclose - 1]
        if not word.search(args):
            continue
        if is_spawn:
            yield "spawn", ident
        else:
            yield "register", ident


def _required_bounds(sink_kinds, callable_kind):
    req = set()
    for k in sink_kinds:
        req.add("Send")
        req.add("'static")
        if k == "register" and callable_kind in ("Fn", "FnMut"):
            req.add("Sync")
    return req


# ---------------------------------------------------------------------------
# Compiler-redundancy screen for the SPAWN arm.
#
# A missing Send/'static bound is only a NET-NEW soundness gap if `rustc` does
# NOT already reject the code. When the value is handed to a WELL-KNOWN spawn
# primitive, the primitive's OWN signature bounds Send (+ 'static), so rustc
# rejects a missing bound with E0277 - the screen would be REDUNDANT with the
# compiler (see near futures.rs `spawn` -> `f.boxed()` -> `spawn_boxed`, which
# rustc rejects because `FutureExt::boxed` requires `Self: Send`). Those cases
# are down-ranked (fires=False, compiler_redundant=True) so the arm's genuine
# net-new value is scoped to user-defined spawn sinks that do NOT enforce the
# bound at the call. The register + unsafe-auto-impl arms are unaffected: their
# sinks (foreign runtime / manual `unsafe impl`) do NOT propagate the auto-trait,
# which is exactly what makes them compiler-MISSED.
#
# `_compiler_covered_bounds` returns the auto-trait/lifetime bounds that rustc
# already enforces (or that the sink kind does not actually require) for `param`
# at the boundary - these are subtracted from `missing` before firing.
# ---------------------------------------------------------------------------
# `<runtime>::spawn*(` - std/tokio/rayon/async_std/smol/glommio free-function or
# associated spawn primitives; each bounds `Send + 'static` in its own signature.
_PRIMITIVE_SPAWN_CALL_RE = re.compile(
    r"\b(?:std\s*::\s*)?"
    r"(?:thread|tokio|task|rayon|async_std|smol|glommio|Handle|runtime|Runtime)"
    r"\s*(?:::\s*\w+\s*)*::\s*"
    r"(?:spawn|spawn_blocking|spawn_fifo|spawn_ok)\s*\(")
# a scoped-thread constructor `scope(|s| ... s.spawn(...) ...)` (crossbeam /
# rayon / near multicore). A SCOPED spawn enforces `Send` but does NOT require
# `'static` (that is the entire point of scoped threads), so both are "covered".
_SCOPE_BIND_RE = re.compile(r"\bscope\s*\(\s*\|\s*(?:ref\s+)?(?P<recv>\w+)")


def _compiler_covered_bounds(body_text: str, param: str):
    """Auto-trait/lifetime bounds that rustc already enforces (or that the sink
    does not actually require) for `param`'s spawn boundary - a missing bound in
    this set is compiler-REDUNDANT, not net-new."""
    covered = set()
    word = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(param) + r"(?![A-Za-z0-9_])")
    # (1) `.boxed()` passthrough: `FutureExt::boxed` requires `Self: Send`
    # (`.boxed_local()` does NOT and is intentionally excluded).
    if re.search(r"(?<![A-Za-z0-9_])" + re.escape(param)
                 + r"\s*\.\s*boxed\s*\(", body_text):
        covered.add("Send")
    # (2) direct hand-off to a runtime spawn primitive (Send + 'static enforced)
    for m in _PRIMITIVE_SPAWN_CALL_RE.finditer(body_text):
        popen = m.end() - 1
        pclose = _match_close(body_text, popen, "(", ")")
        if word.search(body_text[popen + 1:pclose - 1]):
            covered |= {"Send", "'static"}
    # (3) scoped-thread spawn: `scope(|s| ... s.spawn(<param>) ...)`
    for sm in _SCOPE_BIND_RE.finditer(body_text):
        recv = sm.group("recv")
        for cm in re.finditer(
                r"\b" + re.escape(recv) + r"\s*\.\s*spawn\w*\s*\(", body_text):
            popen = cm.end() - 1
            pclose = _match_close(body_text, popen, "(", ")")
            if word.search(body_text[popen + 1:pclose - 1]):
                covered |= {"Send", "'static"}
    return covered


# ---------------------------------------------------------------------------
# unsafe-auto-impl arm (manual Send/Sync assertion over a type-erased-callable
# holding type)
# ---------------------------------------------------------------------------
_UNSAFE_IMPL_RE = re.compile(
    r"\bunsafe\s+impl\b(?:\s*<[^>]*>)?\s+(?P<trait>Send|Sync)\b"
    r"(?:\s*<[^>]*>)?\s+for\s+(?P<ty>[A-Za-z_]\w*)")
_STRUCT_RE = re.compile(r"\bstruct\s+([A-Za-z_]\w*)")
_ERASED_CALLABLE_FIELD_RE = re.compile(
    r"(?:Box|Arc|Rc)\s*<\s*(?:Pin\s*<\s*Box\s*<\s*)?dyn\s+"
    r"(?P<inner>(?:Fn|FnMut|FnOnce|Future)[^,>]*(?:<[^>]*>)?[^,]*)")


def _struct_defs(text: str):
    """Map struct name -> full struct body text ({...} or (...);)."""
    out = {}
    for m in _STRUCT_RE.finditer(text):
        i = m.end()
        n = len(text)
        while i < n and text[i] in " \t\r\n":
            i += 1
        # skip generics
        if i < n and text[i] == "<":
            i = _match_close(text, i, "<", ">")
            while i < n and text[i] in " \t\r\n":
                i += 1
        if i < n and text[i] == "{":
            end = _match_close(text, i, "{", "}")
            out[m.group(1)] = text[i:end]
        elif i < n and text[i] == "(":
            end = _match_close(text, i, "(", ")")
            out[m.group(1)] = text[i:end]
    return out


def _line_of(text: str, off: int) -> int:
    return text.count("\n", 0, off) + 1


# ---------------------------------------------------------------------------
# Row construction
# ---------------------------------------------------------------------------
def _stable_id(rel, fn, param, line, kind):
    h = hashlib.sha1()
    h.update(f"{rel}|{fn}|{param}|{line}|{kind}".encode())
    return h.hexdigest()[:16]


def _row(rel, fn, is_pub, param, line, boundary_kind, callable_kind,
         required, declared, missing, is_type_erased, sinks, question,
         compiler_covered=frozenset()):
    # A bound rustc already enforces (or the sink does not require) is NOT a
    # net-new gap; only a NET-NEW missing bound fires. `compiler_covered` is
    # non-empty only on the spawn arm (register / unsafe-auto-impl sinks never
    # propagate the auto-trait, so nothing is compiler-covered there).
    net_new = set(missing) - set(compiler_covered)
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "id": _stable_id(rel, fn, param, line, boundary_kind),
        "file": rel,
        "line": line,
        "function": fn,
        "lang": "rust",
        "is_pub_api": is_pub,
        "type_param": param,
        "callable_kind": callable_kind,
        "boundary_kind": boundary_kind,
        "boundary_sinks": sorted(set(sinks)),
        "type_erased": is_type_erased,
        "required_bounds": sorted(required),
        "declared_bounds": sorted(declared),
        "missing_bounds": sorted(missing),
        "compiler_covered_bounds": sorted(compiler_covered),
        "net_new_missing_bounds": sorted(net_new),
        "compiler_redundant": bool(missing) and not net_new,
        "fires": bool(net_new),
        "verdict": "needs-fuzz",
        "advisory": True,
        "auto_credit": False,
        "question": question,
    }


def scan_file(path: Path, rel: str, file_text: str = None):
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    text = _mask_rust(raw)
    rows = []

    # ---- fn-boundary arms (spawn / register) ----
    for name, is_pub, sig_text, body_text, decl_off in _iter_fns(text):
        if not body_text:
            continue
        for pname, ckind, bound_text, erased in _callable_params(sig_text):
            sinks = list(_sinks_for_param(body_text, pname))
            if not sinks:
                continue
            sink_kinds = {k for k, _id in sinks}
            required = _required_bounds(sink_kinds, ckind)
            declared = _declared_bounds(bound_text, is_type_erased=erased)
            missing = required - declared
            # Down-rank spawn bounds that rustc already enforces (or a scoped
            # spawn does not require) - those are compiler-REDUNDANT, not net-new.
            covered = (_compiler_covered_bounds(body_text, pname)
                       if "spawn" in sink_kinds else set())
            net_new = missing - covered
            boundary_kind = "+".join(sorted(sink_kinds))
            line = _line_of(text, decl_off)
            sink_names = sorted({sid for _k, sid in sinks})
            if net_new:
                q = (f"`{name}` hands `{ckind}` value `{pname}` across a "
                     f"{boundary_kind} boundary (sink {sink_names}) but its bound "
                     f"omits {sorted(net_new)}; can a safe caller pass a "
                     f"{'!Sync' if 'Sync' in net_new else '!Send'} payload "
                     f"(Rc/Cell/RefCell/thread-affine) that the API then "
                     f"{'shares' if 'Sync' in net_new else 'sends'} across "
                     f"threads (auto-trait bound omission -> data race, no user "
                     f"`unsafe`)?")
            elif missing:
                q = (f"`{name}` hands `{ckind}` `{pname}` across a {boundary_kind} "
                     f"boundary omitting {sorted(missing)}, but the sink "
                     f"({sink_names}) is a known Send-enforcing spawn primitive - "
                     f"rustc already rejects a missing {sorted(covered)} (E0277), "
                     f"so this is compiler-redundant, not net-new (silent).")
            else:
                q = (f"`{name}` hands `{ckind}` `{pname}` across a {boundary_kind} "
                     f"boundary; bound already carries {sorted(declared)} covering "
                     f"{sorted(required)} - enforcement point sound (silent).")
            rows.append(_row(rel, name, is_pub, pname, line, boundary_kind,
                             ckind, required, declared, missing, erased,
                             sink_names, q, compiler_covered=covered))

    # ---- unsafe-auto-impl arm ----
    structs = _struct_defs(text)
    for m in _UNSAFE_IMPL_RE.finditer(text):
        asserted = m.group("trait")
        tyname = m.group("ty")
        body = structs.get(tyname)
        if not body:
            continue
        for fm in _ERASED_CALLABLE_FIELD_RE.finditer(body):
            inner = fm.group("inner")
            ckind = _callable_kind(inner) or "Fn"
            declared = _declared_bounds(inner, is_type_erased=True)
            # the manual assertion claims `asserted`; the held erased callable must
            # itself guarantee it (Sync for a repeatably-callable Fn/FnMut; Send
            # to be moved). Fire when the field's own bound omits the asserted
            # trait.
            if asserted in declared:
                continue
            # a FnOnce field asserted Sync is a weaker signal; still advisory.
            line = _line_of(text, m.start())
            required = {asserted}
            missing = {asserted}
            q = (f"type `{tyname}` is manually `unsafe impl {asserted}` yet holds a "
                 f"type-erased `dyn {ckind}` whose declared bound omits `{asserted}`;"
                 f" the manual auto-trait assertion breaks propagation - verify "
                 f"every closure stored here is actually `{asserted}` (else a safe "
                 f"caller inserts a !{asserted} payload -> data race).")
            rows.append(_row(rel, f"unsafe_impl_{asserted}", True,
                             f"dyn {ckind}", line, "unsafe_auto_impl", ckind,
                             required, declared, missing, True,
                             [f"unsafe_impl_{asserted}"], q))

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
    kinds = {}
    for r in fired:
        kinds[r.get("boundary_kind")] = kinds.get(r.get("boundary_kind"), 0) + 1
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "enforcement_points": len(rows),
        "fired": len(fired),
        "fired_by_boundary": kinds,
        "sound_silent": len(rows) - len(fired),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def _resolve_ws(arg: str) -> Path:
    ws = Path(arg)
    if not ws.is_absolute():
        for base in ("/Users/wolf/audits", os.getcwd()):
            cand = Path(base) / arg
            if cand.exists():
                return cand
    return ws


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="EXT06 Send/Sync/'static bound-omission at a share/send/FFI "
                    "boundary screen (Rust, advisory)")
    ap.add_argument("--workspace", "--ws")
    ap.add_argument("--source")
    ap.add_argument("--file")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    strict = args.strict or os.environ.get(_STRICT_ENV, "").strip() not in (
        "", "0", "false")

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

    ws = _resolve_ws(args.workspace)
    side = ws / ".auditooor" / _SIDE_NAME

    if args.check:
        rows = []
        if side.exists():
            rows = [json.loads(l) for l in side.read_text().splitlines()
                    if l.strip()]
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
