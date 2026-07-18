#!/usr/bin/env python3
"""transmute-type-confusion-screen.py - GEN-R3, the UNSOUND TRANSMUTE / POINTER-
CAST TYPE-CONFUSION screen (lang-intrinsic layer = rust-soundness).

RUST-ONLY. A GENERAL advisory screen (never a specific bug-shape). Every
REINTERPRETING cast (`mem::transmute`, `transmute_copy`, a raw-pointer cast then
deref, or a `bytemuck` reinterpret) must discharge FOUR soundness obligations:

  (a) SIZE       source and target are the same size;
  (b) ALIGNMENT  the target's alignment does not exceed the source provenance
                 alignment (else an unaligned read is UB);
  (c) BIT-VALIDITY every source bit-pattern is a VALID value of the target type
                 (no niche / validity-invariant type produced from arbitrary
                 bytes - bool/char/enum/NonZero/reference/Box/fn-pointer);
  (d) LIFETIME   the cast does not extend or shorten a borrow.

This screen FIRES the forms that CANNOT discharge these obligations statically:

  (1) generic-param-transmute : `transmute::<T, U>` / `transmute_copy` between BARE
      generic type params (a param in scope) - size & validity are UNKNOWN at the
      cast site, so obligations (a)+(c) cannot be discharged;
  (2) lifetime-transmute      : a transmute that extends/shortens a borrow (e.g.
      `transmute::<&'a T, &'static T>` or a `transmute` whose target is a
      `&'static` reference) - use-after-free / aliasing UB, obligation (d);
  (3) bytes-to-niche          : a transmute (or `bytemuck` from_bytes / cast /
      cast_slice / pod_read_unaligned with a HAND-WRITTEN `unsafe impl Pod`)
      producing a NICHE / validity-invariant target - bool, char, a NonZero
      integer, a reference / Box / mutable reference, or a function pointer - from
      an integer / byte / raw source; an out-of-range byte is INSTANT UB,
      obligation (c);
  (4) stricter-align-deref    : a raw-pointer cast then deref (`*(p as *const U)` /
      `&*(p as *mut U)` / `(p as *const U).read()`) where U has STRICTER alignment
      than the byte/`*const u8` source - unaligned-read UB, obligation (b).

FP-CONTROL (sound forms stay SILENT, they do not spray):
  * a same-size transmute between two CONCRETE repr-C / repr-transparent
    plain-old-data types (all integer/float fields, no niche) is SOUND -> silent;
  * a `transmute::<&T, &U>` reference-to-reference cast that keeps the SAME
    lifetime (the repr-transparent newtype idiom) is SOUND -> silent (only fires
    if the target lifetime is `'static`);
  * a `bytemuck` call on a type with `#[derive(Pod)]` (compiler-checked) is SOUND
    -> silent (bytemuck enforces (a)-(c)); only a HAND `unsafe impl Pod` on a
    niche-bearing target is flagged;
  * a raw-pointer cast whose target pointee is NOT a wider scalar (and whose
    source is not a byte pointer) is treated as a plain layout view -> silent;
  * `read_unaligned` / `write_unaligned` explicitly discharge alignment -> silent
    for the stricter-align arm.
  When POD-ness cannot be determined the row is tagged `medium`, not `high`.

DEDUP (per dispatch brief):
  * RU3 (rust OOB) screens `copy_from_slice` / slice indexing (LENGTH bounds), not
    type/bit VALIDITY of a reinterpret.
  * RU1 (Send/Sync omission) screens CONCURRENCY capability escape, not the
    bit-pattern / alignment obligation of a cast.
  * Glider gap #2 (type-lattice / unsafe-downcast) is EVM/Solidity-only (uint
    downcast), not a Rust transmute.
  * R13 rust-unsafe-soundness-obligation ENUMERATES every unsafe point (an
    inventory that lists all transmutes/raw-ptr/send-sync indiscriminately); GEN-R3
    is the DISCRIMINATING reinterpret-cast screen - it fires ONLY the four
    UNDISCHARGEABLE forms and stays SILENT on sound POD / repr-transparent /
    Pod-derived casts, which the R13 blanket inventory does not distinguish.
  GEN-R3 = the reinterpret-cast four-obligation JOIN; a site that reduces to one
  of the above is dropped as overlap.

nuva has NO Rust surface -> nuva-verify is correctly N/A for this capability.

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False; exit 0 by default. The opt-in env
AUDITOOOR_TRANSMUTE_TYPE_CONFUSION_STRICT (or --strict) raises the exit code when
a fired row exists.

Excludes test / vendor / codegen via the shared exclusion libs.

Usage:
  --workspace <ws>   scan <ws>/src (or <ws>) -> .auditooor/
                     transmute_type_confusion_hypotheses.jsonl + summary
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

HYP_SCHEMA = "auditooor.transmute_type_confusion_hypotheses.v1"
_SIDE_NAME = "transmute_type_confusion_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_TRANSMUTE_TYPE_CONFUSION_STRICT"
_CAPABILITY = "GEN_R3"

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

# scalar target types whose alignment can exceed a byte source's (obligation b).
_WIDE_SCALARS = {"u16", "u32", "u64", "u128", "usize",
                 "i16", "i32", "i64", "i128", "isize",
                 "f32", "f64"}
# integer / byte-ish SOURCE hints: producing a niche / pointer from these = UB.
_BYTE_SRC_RE = re.compile(
    r"^(?:&\s*(?:mut\s*)?)?\[?\s*(?:u8|i8|u16|u32|u64|u128|usize|i16|i32|i64|"
    r"i128|isize)\b|as_ptr|as_mut_ptr|as_bytes|\[u8|as_slice")
# niche / validity-invariant target keywords.
_NONZERO_RE = re.compile(r"\bNonZero(?:U|I)(?:8|16|32|64|128|size)\b")


# ============================================================================
# Rust-aware comment / string masking. Rust uses //, /* */ (we treat block as
# non-nested - good enough) and "..." strings. We do NOT mask ' because it is a
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
# enclosing-function + generic-params-in-scope attribution.
# ============================================================================
_FN_DECL_RE = re.compile(r"(?:^|\n)\s*(?:pub\s+)?(?:async\s+)?(?:unsafe\s+)?"
                         r"(?:const\s+)?(?:extern\s+\"[^\"]*\"\s+)?fn\s+"
                         r"([A-Za-z_]\w*)")


def _enclosing_function(text: str, off: int) -> str:
    best = "<file>"
    for m in _FN_DECL_RE.finditer(text):
        if m.start() > off:
            break
        best = m.group(1)
    return best


def _angle_span(text: str, open_idx: int):
    """(inner, close_idx) for a '<' at text[open_idx]; nesting-aware. -1 if bad."""
    depth = 0
    n = len(text)
    i = open_idx
    while i < n:
        ch = text[i]
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i], i
        elif ch in "{}":
            # a generic-arg list never contains a block; but an array type
            # `[u8; 4]` legitimately contains ';', so only '{}' aborts.
            return "", -1
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


_GENERIC_HDR_RE = re.compile(r"\b(?:fn\s+[A-Za-z_]\w*|impl)\s*<")


def _generics_in_scope(text: str, off: int) -> set:
    """Type-param identifiers introduced by the enclosing `impl<...>` /
    `fn name<...>` headers preceding off."""
    names = set()
    for m in _GENERIC_HDR_RE.finditer(text):
        if m.start() > off:
            break
        lt = m.end() - 1  # position of '<'
        inner, close = _angle_span(text, lt)
        if close == -1 or close < off - 1 and False:
            pass
        if close == -1:
            continue
        # only headers whose body still encloses off, OR any preceding fn/impl
        # header (params stay in scope through the body). Accept all preceding.
        for tok in _top_level_split(inner):
            tok = tok.strip()
            if not tok or tok.startswith("'"):  # lifetime
                continue
            if tok.startswith("const "):
                tok = tok[len("const "):].strip()
                nm = tok.split(":")[0].strip()
                if nm:
                    names.add(nm)
                continue
            nm = tok.split(":")[0].split("=")[0].strip()
            # bare single-segment identifier (a real type param, e.g. T, Err)
            if re.fullmatch(r"[A-Za-z_]\w*", nm):
                names.add(nm)
    return names


# ============================================================================
# type classification helpers
# ============================================================================
def _strip_type(t: str) -> str:
    return re.sub(r"\s+", " ", t).strip()


def _bare_ident(t: str):
    """Return the identifier if t is a bare single-segment type name (no &, *,
    <, ::, [, (), fn), else None."""
    t = _strip_type(t)
    if re.fullmatch(r"[A-Za-z_]\w*", t):
        return t
    return None


def _lifetime_target(t: str):
    """True if t is a reference type whose lifetime is 'static."""
    t = _strip_type(t)
    if not t.startswith("&"):
        return False
    return bool(re.match(r"&\s*'static\b", t) or
                re.match(r"&\s*mut\s+'static\b", t))


def _niche_kind(t: str):
    """Return a niche descriptor if t is a validity-invariant target, else None.
    bool / char / NonZero* / reference / Box / fn-pointer."""
    s = _strip_type(t)
    core = re.sub(r"^&\s*(?:mut\s+)?(?:'[a-z_]\w*\s+)?", "", s)  # peel one ref
    if s.startswith("&"):
        return "reference"
    if re.match(r"(?:std::|core::|alloc::)?Box\s*<", s) or \
            re.match(r"(?:std::|core::|alloc::)?Box\s*<", core):
        return "box"
    if re.search(r"\bfn\s*\(", s) or re.search(r'extern\s+"[^"]*"\s+fn', s):
        return "fn-pointer"
    if _NONZERO_RE.search(s):
        return "nonzero"
    if re.fullmatch(r"bool", s):
        return "bool"
    if re.fullmatch(r"char", s):
        return "char"
    return None


def _byte_source(t: str) -> bool:
    if not t:
        return False
    return bool(_BYTE_SRC_RE.search(_strip_type(t)))


# ============================================================================
# scan a single Rust file
# ============================================================================
_TRANSMUTE_RE = re.compile(
    r"\b(?:mem::|core::mem::|std::mem::)?(transmute_copy|transmute)\s*"
    r"(?:::\s*<)?")
_LET_BIND_RE = re.compile(
    r"let\s+(?:mut\s+)?[A-Za-z_]\w*\s*:\s*([^=;]+?)\s*=\s*(?:unsafe\s*\{)?\s*"
    r"(?:mem::|core::mem::|std::mem::)?transmute", re.S)
# raw-pointer cast + deref: *(expr as *const T) / &*(expr as *mut T)
# src may itself contain a single level of parens, e.g. `bytes.as_ptr()`.
_SRC_INNER = r"(?:[^()]|\([^()]*\))*?"
_PTR_CAST_RE = re.compile(
    r"(?P<deref>&\s*\*|\*)\s*\(\s*(?P<src>" + _SRC_INNER + r")\s+as\s+"
    r"\*\s*(?:const|mut)\s+(?P<ty>[A-Za-z_][\w:]*)\s*\)")
# pointer cast followed by .read()/.read_volatile() (NOT read_unaligned)
_PTR_READ_RE = re.compile(
    r"\(\s*(?P<src>" + _SRC_INNER + r")\s+as\s+\*\s*(?:const|mut)\s+"
    r"(?P<ty>[A-Za-z_][\w:]*)\s*\)\s*\.\s*(?P<m>read|read_volatile)\s*\(")
# bytemuck reinterprets producing a target type
_BYTEMUCK_RE = re.compile(
    r"\bbytemuck::(from_bytes|from_bytes_mut|try_from_bytes|cast|cast_ref|"
    r"cast_mut|cast_slice|cast_slice_mut|pod_read_unaligned)\s*"
    r"(?:::\s*<\s*([^>]+?)\s*>)?")
_UNSAFE_POD_RE = re.compile(r"unsafe\s+impl\s+(?:bytemuck::)?"
                            r"(?:Pod|Zeroable|AnyBitPattern|NoUninit)\b")


def _turbofish_args(text: str, m: re.Match):
    """If the transmute match opened a turbofish `::<`, return (src, dst)."""
    if not m.group(0).rstrip().endswith("<"):
        return None
    lt = text.rfind("<", m.start(), m.end())
    if lt == -1:
        return None
    inner, close = _angle_span(text, lt)
    if close == -1:
        return None
    parts = _top_level_split(inner)
    if len(parts) < 2:
        return None
    return parts[0].strip(), parts[1].strip(), close


def _mk_row(rel, fn, line, form, target_type, obligation, excerpt, severity,
            why):
    # Every _mk_row site is a FIRED survivor (an undischargeable reinterpret
    # obligation). A fired survivor is an OPEN obligation, NOT advisory-green:
    # advisory=False + proof_status='open' so a downstream advisory filter counts
    # it OPEN instead of letting it drain silently to advisory (vacuity-telltale
    # fix). fires==False enumeration leads keep advisory=True (none here emit).
    fires = True
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "id": _stable_id(rel, form, fn + "|" + target_type, line),
        "file": rel,
        "line": line,
        "function": fn,
        "lang": "rust",
        "unsound_form": form,
        "target_type": target_type[:120],
        "obligation_unmet": obligation,
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
    has_hand_pod = bool(_UNSAFE_POD_RE.search(text))
    seen = set()

    # --- transmute / transmute_copy ----------------------------------------
    for m in _TRANSMUTE_RE.finditer(text):
        off = m.start()
        fn = _enclosing_function(text, off)
        line = _line_of_offset(text, off)
        src_ty = dst_ty = ""
        tf = _turbofish_args(text, m)
        if tf:
            src_ty, dst_ty, _close = tf
        else:
            # non-turbofish: recover the target from a `let x: TY = transmute`
            pre = text[max(0, off - 220):off]
            lb = None
            for lb in _LET_BIND_RE.finditer(pre + "transmute"):
                pass
            if lb:
                dst_ty = lb.group(1).strip()
            else:
                # or the enclosing fn return type `-> TY {`
                rm = None
                for rm in re.finditer(
                        r"->\s*([^\{;]+?)\s*\{",
                        text[max(0, off - 600):off]):
                    pass
                if rm:
                    dst_ty = rm.group(1).strip()
        key = (line, "transmute", dst_ty)
        if key in seen:
            continue
        seen.add(key)

        # precedence: bytes-to-niche (bit-validity) > lifetime > generic-param.
        niche = _niche_kind(dst_ty) if dst_ty else None
        if niche and not _lifetime_target(dst_ty):
            byte_src = _byte_source(src_ty) or (not src_ty)
            if niche in ("bool", "char", "nonzero"):
                sev = "high" if _byte_source(src_ty) else "medium"
            elif niche in ("reference", "box", "fn-pointer"):
                # a reference/box/fn-ptr from an integer/byte source = high; from
                # another reference (ptr-to-ptr) = lower (medium, layout view).
                sev = "high" if _byte_source(src_ty) else \
                    ("medium" if src_ty and not src_ty.startswith("&") else None)
                if sev is None:
                    # &A -> &B same-lifetime: repr-transparent idiom -> silent.
                    continue
            else:
                sev = "medium"
            rows.append(_mk_row(
                rel, fn, line, "bytes-to-niche", dst_ty, "bit-validity",
                _excerpt(text, off), sev,
                f"`transmute` produces a niche / validity-invariant target "
                f"(`{_strip_type(dst_ty)[:80]}`, kind={niche})"
                + (f" from source `{_strip_type(src_ty)[:60]}`" if src_ty
                   else "")
                + ". Not every source bit-pattern is a valid value of the "
                "target (obligation c): an out-of-range byte is INSTANT "
                "undefined behaviour. If the source is not a compiler-checked "
                "POD of exactly this validity, this is unsound."))
            continue

        if _lifetime_target(dst_ty):
            rows.append(_mk_row(
                rel, fn, line, "lifetime-transmute", dst_ty, "lifetime",
                _excerpt(text, off), "high",
                f"`transmute` targets a `'static` borrow "
                f"(`{_strip_type(dst_ty)[:80]}`)"
                + (f" from `{_strip_type(src_ty)[:60]}`" if src_ty else "")
                + ". This EXTENDS the borrow lifetime (obligation d): the "
                "referent may be freed while the 'static reference lives -> "
                "use-after-free / aliasing UB reachable from safe code."))
            continue

        # generic-param: a bare in-scope type param on either arm.
        gset = _generics_in_scope(text, off)
        gsrc = _bare_ident(src_ty)
        gdst = _bare_ident(dst_ty)
        hit = None
        if gdst and gdst in gset:
            hit = gdst
        elif gsrc and gsrc in gset:
            hit = gsrc
        if hit:
            rows.append(_mk_row(
                rel, fn, line, "generic-param-transmute",
                dst_ty or hit, "size",
                _excerpt(text, off), "medium",
                f"`transmute` between generic type param(s) (`{hit}` is a "
                f"param in scope). Size and bit-validity are UNKNOWN at the "
                f"cast site (obligations a+c) - the compiler cannot verify "
                f"`size_of::<SRC>() == size_of::<DST>()` nor that every SRC "
                f"bit-pattern is valid for DST, so this is a latent "
                f"type-confusion if instantiated at mismatched types."))
            continue
        # else: concrete->concrete non-niche same-lifetime -> SOUND, silent.

    # --- bytemuck reinterprets (only unsound when a HAND unsafe impl Pod) ----
    for m in _BYTEMUCK_RE.finditer(text):
        dst_ty = (m.group(2) or "").strip()
        niche = _niche_kind(dst_ty) if dst_ty else None
        # bytemuck's Pod bound is compiler-checked: a niche target only compiles
        # (unsoundly) if the author HAND-wrote `unsafe impl Pod`. Otherwise sound.
        if not (niche and has_hand_pod):
            continue
        off = m.start()
        fn = _enclosing_function(text, off)
        line = _line_of_offset(text, off)
        rows.append(_mk_row(
            rel, fn, line, "bytes-to-niche", dst_ty, "bit-validity",
            _excerpt(text, off), "high",
            f"`bytemuck::{m.group(1)}` reinterprets bytes into a niche target "
            f"(`{_strip_type(dst_ty)[:80]}`, kind={niche}) in a file that "
            f"contains a HAND-written `unsafe impl Pod/Zeroable` - bypassing "
            f"the compiler-checked Pod bound. If that impl covers a "
            f"niche-bearing type, an out-of-range byte is instant UB "
            f"(obligation c)."))

    # --- raw-pointer cast then deref (stricter alignment) -------------------
    for m in list(_PTR_CAST_RE.finditer(text)) + list(_PTR_READ_RE.finditer(
            text)):
        ty = m.group("ty").split("::")[-1]
        src = m.group("src")
        # fire only when the target pointee is a wider scalar (align can exceed
        # a byte source) AND the source looks like a byte / u8 pointer, OR the
        # target is a wider scalar with an unknown (non-reference) byte source.
        wide = ty in _WIDE_SCALARS
        byte_src = _byte_source(src) or "u8" in src
        if not wide:
            continue
        if not byte_src:
            continue
        off = m.start()
        fn = _enclosing_function(text, off)
        line = _line_of_offset(text, off)
        # read_unaligned explicitly discharges alignment -> skip (guarded by RE).
        rows.append(_mk_row(
            rel, fn, line, "stricter-align-deref", ty, "alignment",
            _excerpt(text, off), "medium",
            f"a raw byte pointer is cast to `*const/{ty}` (a wider-aligned "
            f"scalar) and DEREFERENCED. If the byte source is not `{ty}`-"
            f"aligned, this is an unaligned read - UB (obligation b). Use "
            f"`read_unaligned` or an aligned buffer."))

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
                # skip inline unit-test-only files (whole file is a test mod).
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
        # Capability-vacuity-telltale: the transmute screen RAN over a real Rust
        # surface and produced 0 candidate/fired rows. PERSIST an explicit cited-empty
        # examined-record so the reasoner-firing gate scores this FIRED_CLEAN (ran,
        # recorded 0) not silently VACUOUS. Only when Rust is actually present -
        # absent Rust is governed by a recorded surface-absent exemption instead.
        if not rows and rust_present:
            fh.write(json.dumps({
                "schema": HYP_SCHEMA,
                "note": ("cited-empty: transmute/pointer-cast type-confusion screen "
                         "ran over the Rust surface, 0 unsound-transmute sites"),
                "survivors": [],
                "report": {"reasoner": "transmute-type-confusion-screen",
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
        "by_unsound_form": _count(rows, "unsound_form"),
        "by_obligation_unmet": _count(rows, "obligation_unmet"),
        "by_severity": _count(rows, "severity"),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="GEN-R3 unsound transmute / pointer-cast type-confusion "
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
    # Rust surface present iff >=1 in-scope .rs file (exclude vendored deps). Used to
    # gate the cited-empty examined-record: over a real Rust surface with 0 rows the
    # screen ran-clean (FIRED_CLEAN); with NO Rust surface it stays empty so a
    # recorded surface-absent exemption (not this reasoner) governs.
    rust_present = any(
        "node_modules" not in p.parts for p in root.rglob("*.rs"))
    _emit_sidecar(ws, rows, rust_present=rust_present)
    summ = _summary(rows)
    print(json.dumps(summ, indent=2))
    return 1 if (strict and summ["fired"]) else 0


if __name__ == "__main__":
    sys.exit(main())
