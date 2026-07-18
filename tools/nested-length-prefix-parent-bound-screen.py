#!/usr/bin/env python3
"""nested-length-prefix-parent-bound-screen.py  (EXT05) - the NESTED length-prefix
PARENT-BOUND reconciliation screen for length-prefixed / TLV deserializers.

GENERAL LOGIC / TRUST-ENFORCEMENT class (never one bug SHAPE). It instantiates the
north-star method ("A TRUSTED ENFORCEMENT is bypassable / its private invariant is
unsound") for one serialization-soundness property no per-function detector owns:

  DELEGATED-TRUSTED INVARIANT
      A length-prefixed / TLV decoder (RLP, protobuf, SSZ, BCS, ASN.1/DER, ABI
      dynamic types, custom framing) is TRUSTED to keep every child element it
      carves out of an attacker-supplied buffer *inside* the bytes its PARENT
      container actually owns.
  PRIVATE INVARIANT
      For every nesting level, a child element's self-declared length / offset,
      once read from the buffer, must be reconciled against the PARENT's remaining
      bytes  ( child_end <= parent_end )  BEFORE it is used to advance a byte /
      memory cursor or to bound a memory copy.  A declared length trusted only
      against the *total* buffer - or trusted with no clamp at all - is unsound.
  ATTACK
      The last / inner item declares a length that runs past its parent item into
      adjacent (possibly caller-controlled scratch / not-yet-zeroed) memory, so
      later parsing reads attacker-planted bytes as if they were valid decoded
      fields - a type-erased deserialize that silently reads out of bounds.

  ANCHOR : Polygon bridge  RLPReader.toList  directly trusted the read length
  field, letting the last RLPItem of a list be pushed out of bounds of its parent
  RLPItem; combined with a parse -> external-call -> parse ordering the attacker
  filled unallocated memory so the OOB RLP parse jumped into controlled data and
  fully forged the decoded receipt.
  (https://hexens.io/research/polygon-bridge-forging-transaction-proofs)

WHY NET-NEW.  This is NOT an unbounded-allocation / decode-bomb detector (E7 /
rust-decode-bomb / host-length-cast own "a decoded length drives a huge alloc /
loop") nor a trailing-bytes detector.  It is the NESTED-reconciliation arm: the
child length must be bounded by the PARENT's remaining bytes, not merely by the
total buffer or a global cap.  No wired capability enumerates length-prefixed
decoder parent-bound reconciliation.

WHAT IT FLAGS (advisory).  Per decoder FUNCTION it enumerates every point where a
child length read from the input buffer is used to advance a cursor / bound a copy,
and flags (verdict=needs-fuzz) when NO parent-bound reconciliation guard
( cursor / child-len  <op>  container-extent, or a bounds-helper ) exists in the
function, AND the advance touches RAW / UNSAFE memory (Solidity assembly-pointer,
Rust `unsafe`/`get_unchecked`/`from_raw_parts`, Go `unsafe`).  Safe-slice languages
(bounds-checked Go/Rust) PANIC on over-read rather than silently reading adjacent
memory, so the silent-OOB teeth require a raw-memory context - a decoder that only
uses checked slicing is recorded as an enforcement point but does NOT fire.

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False. It NEVER auto-credits and NEVER fail-closes in default mode; the
opt-in env AUDITOOOR_NESTED_LENPREFIX_STRICT (or --strict) only raises the exit code
when a fired, severity-eligible (raw-memory) point exists.

Languages: Solidity (.sol), Go (.go), Rust (.rs). Silent on other trees.
Machine-generated code (*.pb.go / *.pulsar.go / *_gen.go / "Code generated ... DO
NOT EDIT") and test files are excluded.

Usage:
  --workspace <ws>   scan <ws>/src -> .auditooor/nested_length_prefix_parent_bound_hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON (NO sidecar)
  --file <f>         scan a single .sol/.go/.rs file, print rows as JSON
  --check            re-read the emitted sidecar, print cert verdict (advisory)
  --strict           (or env) elevate exit code when a fired raw-memory point exists
  --json             machine summary to stdout
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

HYP_SCHEMA = "auditooor.nested_length_prefix_parent_bound_hypotheses.v1"
_SIDE_NAME = "nested_length_prefix_parent_bound_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_NESTED_LENPREFIX_STRICT"
_CAPABILITY = "EXT05"

# always pruned (build/vcs/generated-artifact/test noise), at any depth.
_SKIP_DIRS = {"target", ".git", "_archive", "out", "cache", "__pycache__",
              "dist", "build", ".auditooor", "benches", "benchmarks", "script",
              "scripts", "deployments", "prior_audits", "reference", "testdata",
              "mocks", "docs", ".git", "coverage"}
# third-party dependency dirs - pruned ONLY when NOT inside an in-scope source
# subtree (a `src/` or `contracts/` ancestor). A nested `src/msg/lib/` (the
# Polygon RLPReader lives there) is in-scope and must NOT be pruned, while a
# project-root `lib/` (forge deps: openzeppelin etc.) is.
_DEP_DIRS = {"lib", "dependencies", "node_modules", "vendor", "third_party",
             "external"}
_INSCOPE_ANCHOR = {"src", "contracts"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|test_fixtures|mock|mocks|benches|benchmarks?|examples|fixtures)(/|$)")
# a directory whose name (even hyphen/underscore-joined) marks a test / fuzz /
# fixture subtree - e.g. `near-test-contracts`, `contract-for-fuzzing-rs`.
_TESTY_SEG = re.compile(
    r"(?:^|[-_])(?:tests?|testdata|test-?contracts?|fuzz\w*|mock\w*|fixtures?|"
    r"examples?|benches?|benchmarks?)(?:[-_]|$)", re.I)

# ---------------------------------------------------------------------------
# generated-source exclusion  (copied from declared-control-mutator-completeness-screen.py)
# ---------------------------------------------------------------------------
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


_LANG_BY_EXT = {".sol": "solidity", ".go": "go", ".rs": "rust"}


def _iter_source_files(root: Path):
    for dp, dn, fn in os.walk(root):
        dpn = dp.replace(os.sep, "/")
        parts = set(dpn.split("/"))
        in_src = bool(parts & _INSCOPE_ANCHOR)
        kept = []
        for d in dn:
            if d in _SKIP_DIRS:
                continue
            if _TESTY_SEG.search(d):
                continue
            dl = d.lower()
            # a dep dir is third-party only when NOT inside an in-scope subtree
            if dl in _DEP_DIRS and not in_src:
                continue
            kept.append(d)
        dn[:] = kept
        if _TEST_HINT.search(dpn):
            continue
        for f in fn:
            low = f.lower()
            ext = os.path.splitext(low)[1]
            if ext not in _LANG_BY_EXT:
                continue
            if low.endswith("_test.go") or low.endswith(".t.sol") or low.endswith("_test.rs"):
                continue
            if _TEST_HINT.search(f):
                continue
            p = Path(dp) / f
            if _is_generated_source(p):
                continue
            yield p


# ---------------------------------------------------------------------------
# masking - neutralise comments / string+char literals so brace matching and
# token regexes never fire on noise. Length + newlines preserved (offsets align).
# ---------------------------------------------------------------------------
_CHAR_LIT_RE = re.compile(r"'(?:\\.|[^'\\\n])'")  # 'a' / '\n' - NOT a Rust lifetime


def _mask(text: str) -> str:
    out = []
    i, n = 0, len(text)
    st = None  # None | 'line' | 'block' | 'dq' | 'bq'
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if st is None:
            if c == "/" and nxt == "/":
                st = "line"; out.append("  "); i += 2; continue
            if c == "/" and nxt == "*":
                st = "block"; out.append("  "); i += 2; continue
            if c == '"':
                st = "dq"; out.append('"'); i += 1; continue
            if c == "`":
                st = "bq"; out.append("`"); i += 1; continue
            if c == "'":
                # a genuine char / rune literal - mask it; otherwise it is a Rust
                # lifetime (`'a`) and must pass through untouched.
                mm = _CHAR_LIT_RE.match(text, i)
                if mm:
                    out.append(" " * (mm.end() - mm.start())); i = mm.end(); continue
                out.append(c); i += 1; continue
            out.append(c); i += 1; continue
        # inside a masked region
        if st == "line":
            if c == "\n":
                st = None; out.append("\n")
            else:
                out.append(" ")
            i += 1; continue
        if st == "block":
            if c == "*" and nxt == "/":
                st = None; out.append("  "); i += 2; continue
            out.append("\n" if c == "\n" else " "); i += 1; continue
        if st == "dq":
            if c == "\\":
                out.append("  "); i += 2; continue
            if c == '"':
                st = None; out.append('"'); i += 1; continue
            out.append("\n" if c == "\n" else " "); i += 1; continue
        if st == "bq":  # go raw string
            if c == "`":
                st = None; out.append("`"); i += 1; continue
            out.append("\n" if c == "\n" else " "); i += 1; continue
    return "".join(out)


def _line_starts(text: str):
    starts = [0]
    for m in re.finditer("\n", text):
        starts.append(m.end())
    return starts


def _off_to_line(starts, off: int) -> int:
    # binary search
    lo, hi = 0, len(starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if starts[mid] <= off:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1  # 1-indexed


# ---------------------------------------------------------------------------
# function extraction (brace-matched) - Solidity / Go / Rust
# ---------------------------------------------------------------------------
_FN_DECL = {
    "solidity": re.compile(
        r"(?:function\s+([A-Za-z_]\w*)|(constructor)\b|(fallback|receive)\s*\()"),
    "go": re.compile(r"func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\("),
    "rust": re.compile(r"fn\s+([A-Za-z_]\w*)\s*[<(]"),
}


def _functions(masked: str, lang: str):
    """Yield (name, decl_off, body_start_off, body_end_off) for top-level fns.
    Skips declarations nested inside an already-emitted span (Go closures etc.)."""
    rx = _FN_DECL[lang]
    last_end = -1
    for m in rx.finditer(masked):
        if m.start() < last_end:
            continue
        name = None
        for g in m.groups():
            if g:
                name = g
                break
        name = name or "(anon)"
        brace = masked.find("{", m.end())
        if brace == -1:
            continue
        # a ';' before the first '{' => it's a declaration / interface stub
        semi = masked.find(";", m.end())
        if semi != -1 and semi < brace:
            continue
        depth = 0
        j = brace
        end = -1
        while j < len(masked):
            ch = masked[j]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = j
                    break
            j += 1
        if end == -1:
            continue
        last_end = end
        yield name, m.start(), brace, end


# ---------------------------------------------------------------------------
# token lexicons
# ---------------------------------------------------------------------------
# a helper call that reads a CHILD element's declared length (NOT the item's own
# whole payload - payloadLen / payloadLocation / payloadOffset are deliberately
# excluded: they derive from the parent's own len field, not a nested child).
_CHILD_LEN_HELPER = (
    r"(?<![A-Za-z0-9_])_?(?:"
    r"item[_]?length|item[_]?len|element[_]?length|entry[_]?length|field[_]?length|"
    r"chunk[_]?length|record[_]?length|read[_]?length|read[_]?len|decode[_]?length|"
    r"decode[_]?len|next[_]?length|msg[_]?len|wire[_]?len|prefix[_]?len|value[_]?len|"
    r"read[_]?var(?:int|uint)?|read[_]?uvarint|uvarint|get[_]?var(?:int|uint)?"
    r")\s*\(")
# a raw buffer integer read whose value can be used as a length.
_BUF_INT_READ = (
    r"binary\.(?:Big|Little)Endian\.Uint(?:16|32|64)\s*\(|"
    r"binary\.Uvarint\s*\(|binary\.Varint\s*\(|"
    r"(?<![A-Za-z0-9_])read_u(?:8|16|32|64)\s*\(|(?<![A-Za-z0-9_])get_u(?:8|16|32|64)\s*\(|"
    r"(?<![A-Za-z0-9_])read_uint\s*\(|(?<![A-Za-z0-9_])from_(?:le|be)_bytes\s*\(")

_LEN_SOURCE_RE = re.compile("(?:%s|%s)" % (_CHILD_LEN_HELPER, _BUF_INT_READ), re.I)
_HELPER_ONLY_RE = re.compile(_CHILD_LEN_HELPER, re.I)

# assignment forms that bind a child-length var:  `x = ...LEN..`, `x := ...LEN..`,
# `let x = ...LEN..`,  and the Go 2-tuple  `x, _ := binary.Uvarint(...)`.
_ASSIGN_LEN_RE = re.compile(
    r"(?:let\s+(?:mut\s+)?)?([A-Za-z_]\w*)\s*(?::[^=;]+?)?\s*(?::=|=)\s*[^;{]*?"
    + "(?:%s|%s)" % (_CHILD_LEN_HELPER, _BUF_INT_READ), re.I)
_ASSIGN_LEN_TUPLE_RE = re.compile(
    r"([A-Za-z_]\w*)\s*,\s*[A-Za-z_]\w*\s*:?=\s*[^;{]*?" + "(?:%s)" % _BUF_INT_READ, re.I)

# EXTENT tokens: names / fields that denote a container's end / remaining bytes.
_EXTENT_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:end|end_?ptr|end_?pos|end_?off(?:set)?|remaining|remain|"
    r"bound|bounds|limit|capacity|total_?len|parent[_A-Za-z]*|buf_?len|data_?len)"
    r"(?![A-Za-z0-9_])|\.len\b|\.length\b|\.size\b|(?<![A-Za-z0-9_])len\s*\(", re.I)
# a named bounds-checking helper used as a guard condition.
_BOUNDS_HELPER_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:has_?next|has_?more|has_?bytes|has_?remaining|in_?bounds|"
    r"out_?of_?bounds|check_?bounds?|within_?bounds?|"
    r"ensure_?(?:len|cap|size|bound|bounds|bytes|capacity)|"
    r"require_?(?:len|bound|bounds|bytes)|assert_?(?:len|bound|bounds)|verify_?len|"
    r"bounds_?check|check_?len|expect_?len)\s*\(", re.I)

_RELOP_RE = re.compile(r"(<=|>=|==|!=|<|>)")
_GUARD_HEAD_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:require|assert|assert_eq|if|while|for|ensure|guard)\b")

# raw / unsafe memory markers per language (silent-OOB teeth).
_SOL_RAWMEM_RE = re.compile(
    r"\bassembly\b|\bmload\b|\bmstore\b|\bmstore8\b|\bmcopy\b|\bcalldataload\b|"
    r"\bcalldatacopy\b|\bstaticcall\b")
_RUST_RAWMEM_RE = re.compile(
    r"\bunsafe\b|get_unchecked|from_raw_parts|copy_nonoverlapping|copy_from_slice|"
    r"ptr::|\.as_ptr\s*\(|\.add\s*\(|\.offset\s*\(")
_GO_RAWMEM_RE = re.compile(r"\bunsafe\.|reflect\.SliceHeader|reflect\.StringHeader")

_PTRISH_NAMES = {"memptr", "ptr", "nextptr", "currptr", "curptr", "cur", "dest",
                 "destptr", "src", "srcptr", "cursor", "pos", "position", "offset",
                 "off", "readptr", "writeptr", "wordptr"}
# names that plausibly denote a byte / memory CURSOR being advanced (a superset of
# the raw-pointer names). Deliberately excludes value-accumulator names (sum,
# total, result, acc, count) so plain integer arithmetic is not mis-read as an
# advance.  A variable not in this set can still qualify as a cursor if it is used
# to index / deref the buffer inside the function (see _is_cursor_like).
_CURSOR_NAMES = _PTRISH_NAMES | {"idx", "index", "iter", "head", "tail", "walk",
                                 "reader", "dataptr", "start", "begin", "p", "pp",
                                 "rp", "wp", "seek", "readpos", "writepos"}


def _is_cursor_like(cursor: str, body_text: str) -> bool:
    last = cursor.split(".")[-1].lower()
    if last in _CURSOR_NAMES:
        return True
    ce = re.escape(cursor.split(".")[-1])
    # used as a memory pointer (mload/mstore/calldataload) or a slice / index base
    if re.search(
            r"(?:mload|mstore|mstore8|mcopy|calldataload|calldatacopy)\s*\(\s*[^,)]*?"
            r"(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])" % ce, body_text):
        return True
    if re.search(r"(?<![A-Za-z0-9_])%s\s*\[" % ce, body_text):        # cursor[..]
        return True
    if re.search(r"\[\s*[^\]]*?(?<![A-Za-z0-9_])%s\s*(?::|\.\.)" % ce, body_text):  # buf[cursor:..]
        return True
    if re.search(r"\.(?:add|offset|get_unchecked)\s*\(\s*[^,)]*?"
                 r"(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])" % ce, body_text):
        return True
    return False

_KIND_TOKENS = [
    ("rlp", re.compile(r"\brlp\b|rlpitem|rlpreader", re.I)),
    ("protobuf", re.compile(r"protobuf|proto\.|\bproto\b|unmarshal", re.I)),
    ("ssz", re.compile(r"\bssz\b", re.I)),
    ("borsh", re.compile(r"borsh", re.I)),
    ("bcs", re.compile(r"\bbcs\b", re.I)),
    ("asn1-der", re.compile(r"asn1|\bder\b|\boid\b", re.I)),
    ("abi", re.compile(r"abi\.decode|abidecode|abi_decode", re.I)),
    ("varint", re.compile(r"varint|uvarint", re.I)),
]


def _decoder_kind(blob: str) -> str:
    for kind, rx in _KIND_TOKENS:
        if rx.search(blob):
            return kind
    return "tlv"


# ---------------------------------------------------------------------------
# CORE PREDICATE 1 : the parent-bound reconciliation guard.  A decoder is sound
# only if a guard relates the running cursor (or the child length) to the parent
# container's extent - the essence of THIS class vs a generic bounds detector.
# Returns the guard evidence line, or None when NO reconciliation exists.
# (Extracted as a module seam so a test can neutralise it to prove it is
# load-bearing.)
# ---------------------------------------------------------------------------
def _find_parent_bound_guard(masked_lines, orig_lines, cursor_set, lenref_set):
    for idx, ml in enumerate(masked_lines):
        if not _GUARD_HEAD_RE.search(ml):
            continue
        if _BOUNDS_HELPER_RE.search(ml):
            return orig_lines[idx].strip()
        if not _RELOP_RE.search(ml):
            continue
        if not _EXTENT_RE.search(ml):
            continue
        toks = set(re.findall(r"[A-Za-z_][\w.]*", ml))
        base_toks = {t.split(".")[0] for t in toks} | toks
        if base_toks & (cursor_set | lenref_set):
            return orig_lines[idx].strip()
    return None


# ---------------------------------------------------------------------------
# CORE PREDICATE 2 : the raw / unsafe memory context.  The silent-OOB-into-
# adjacent-memory teeth require a language memory model where an over-read does
# NOT panic (Solidity assembly pointer, Rust `unsafe`, Go `unsafe`).  Bounds-
# checked slicing instead panics (a DoS, not a silent type-confusion), so such a
# decoder is recorded as an enforcement point but does NOT fire.
# ---------------------------------------------------------------------------
def _raw_memory_context(lang, body_text, cursor_set):
    if lang == "solidity":
        return bool(_SOL_RAWMEM_RE.search(body_text)) or bool(
            {c.split(".")[-1].lower() for c in cursor_set} & _PTRISH_NAMES)
    if lang == "rust":
        return bool(_RUST_RAWMEM_RE.search(body_text))
    return bool(_GO_RAWMEM_RE.search(body_text))  # go


# ---------------------------------------------------------------------------
# per-function analysis
# ---------------------------------------------------------------------------
def _analyze_function(name, body, body_line0, lang, file_rel, file_blob):
    """body: masked+original? we pass masked body for detection and a parallel
    original-line list for evidence. Returns a row dict or None."""
    masked_lines = body["masked"]
    orig_lines = body["orig"]
    body_text = "\n".join(masked_lines)

    # 1. child-length vars read in this function
    child_len_vars = {}   # var -> (line_no, orig_text)
    for idx, ml in enumerate(masked_lines):
        if not _LEN_SOURCE_RE.search(ml):
            continue
        # Prefer the tuple regex first: the Go 2-tuple `x, _ := binary.Uvarint(...)`
        # keeps its VALUE var (position 1). The single-var _ASSIGN_LEN_RE would
        # otherwise match the later blank identifier `_` (or the bytes-consumed
        # count var) and lose the decoded length var. The tuple regex requires a
        # `X, Y :=`/`=` comma shape so it never hijacks a genuine single-var line.
        m = _ASSIGN_LEN_TUPLE_RE.search(ml) or _ASSIGN_LEN_RE.search(ml)
        if m:
            var = m.group(1)
            if var and var != "_" and var not in child_len_vars:
                child_len_vars[var] = (body_line0 + idx, orig_lines[idx].strip())

    # 2. advances: cursor advanced by a child-len var OR an inline child-len helper.
    advances = []  # list of dict(cursor, length_ref, line, text)
    for idx, ml in enumerate(masked_lines):
        line_no = body_line0 + idx
        otext = orig_lines[idx].strip()
        # 2a. accumulator  X += ...   or   X = X + ...
        for am in re.finditer(r"([A-Za-z_][\w.]*)\s*(?:\+=|=\s*\1\s*\+)\s*([^;{]+)", ml):
            cursor = am.group(1)
            addend = am.group(2)
            ref = _addend_len_ref(addend, child_len_vars)
            if ref and _is_cursor_like(cursor, body_text):
                advances.append(dict(cursor=cursor, length_ref=ref, line=line_no, text=otext))
        # 2b. base + len :  X = <base> + <child-len>   (base must be a cursor, not a length)
        for bm in re.finditer(r"([A-Za-z_][\w.]*)\s*=\s*([A-Za-z_][\w.]*)\s*\+\s*([^;{]+)", ml):
            cursor, base, addend = bm.group(1), bm.group(2), bm.group(3)
            if cursor == base:  # already handled by accumulator
                continue
            if base in child_len_vars:  # len + len arithmetic, not a cursor advance
                continue
            ref = _addend_len_ref(addend, child_len_vars)
            if ref and (_is_cursor_like(cursor, body_text) or _is_cursor_like(base, body_text)):
                advances.append(dict(cursor=cursor, length_ref=ref, line=line_no, text=otext))
        # 2c. memory copy bounded by a child-len var
        for cm in re.finditer(
                r"(?:copy|copy_nonoverlapping|copy_from_slice)\s*\(\s*([A-Za-z_][\w.]*)\s*,"
                r"\s*[^,]+,\s*([A-Za-z_]\w*)\s*\)", ml):
            base, lv = cm.group(1), cm.group(2)
            if lv in child_len_vars:
                advances.append(dict(cursor=base, length_ref=lv, line=line_no, text=otext))
        for fm in re.finditer(r"from_raw_parts\s*\(\s*([A-Za-z_][\w.]*)\s*,\s*([A-Za-z_]\w*)\s*\)", ml):
            base, lv = fm.group(1), fm.group(2)
            if lv in child_len_vars:
                advances.append(dict(cursor=base, length_ref=lv, line=line_no, text=otext))
        # 2d. slice bounded by  start + child-len  :  buf[start : start+len]
        for sm in re.finditer(r"\[[^\]]*?([A-Za-z_]\w*)\s*(?:\+|\.\.=?\s*[A-Za-z_]\w*\s*\+)\s*([A-Za-z_]\w*)\s*\]", ml):
            lv = sm.group(2)
            if lv in child_len_vars:
                advances.append(dict(cursor=sm.group(1), length_ref=lv, line=line_no, text=otext))

    if not advances:
        return None

    cursor_set = {a["cursor"] for a in advances}
    lenref_set = {a["length_ref"] for a in advances if a["length_ref"] != "(inline-helper)"}
    lenref_set |= set(child_len_vars.keys())

    # 3. parent-bound reconciliation guard anywhere in the function (core predicate)
    guard_evidence = _find_parent_bound_guard(
        masked_lines, orig_lines, cursor_set, lenref_set)

    # 4. raw / unsafe memory context (the silent-OOB teeth - core predicate)
    raw_memory = _raw_memory_context(lang, body_text, cursor_set)

    guarded = guard_evidence is not None
    fires = (not guarded) and raw_memory

    if guarded:
        disposition = "parent-bound-reconciled"
    elif not raw_memory:
        disposition = "memory-safe-slice-panic"
    else:
        disposition = "unreconciled-raw-memory-overread"

    a0 = advances[0]
    lr = child_len_vars.get(a0["length_ref"])
    orig_blob = "\n".join(orig_lines)
    row = {
        "capability": _CAPABILITY,
        "schema": HYP_SCHEMA,
        "fires": fires,
        "file": file_rel,
        "line": a0["line"],
        "function": name,
        "advisory": True,
        "auto_credit": False,
        "verdict": "needs-fuzz",
        "lang": lang,
        "decoder_kind": _decoder_kind(name + "\n" + orig_blob + "\n" + file_blob),
        "cursor_var": a0["cursor"],
        "length_var": a0["length_ref"],
        "length_read_line": lr[0] if lr else None,
        "length_read": lr[1] if lr else None,
        "cursor_advance_line": a0["line"],
        "cursor_advance": a0["text"],
        "advance_sites": len(advances),
        "has_parent_bound_guard": guarded,
        "guard_evidence": guard_evidence,
        "raw_memory": raw_memory,
        "severity_eligible": fires,
        "disposition": disposition,
    }
    return row


def _addend_len_ref(addend: str, child_len_vars: dict):
    """Return the joined length reference for an advance addend, else None.
    Priority: an inline child-len helper call, then a bound child-len var name."""
    if _HELPER_ONLY_RE.search(addend):
        return "(inline-helper)"
    for var in child_len_vars:
        if re.search(r"(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])" % re.escape(var), addend):
            return var
    return None


# ---------------------------------------------------------------------------
# file / tree drivers
# ---------------------------------------------------------------------------
def scan_file(path: Path, rel: str, file_text: str = None):
    lang = _LANG_BY_EXT.get(path.suffix.lower())
    if lang is None:
        return []
    if file_text is None:
        try:
            file_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
    masked = _mask(file_text)
    orig_all = file_text.split("\n")
    masked_all = masked.split("\n")
    starts = _line_starts(masked)
    rows = []
    file_blob = file_text[:600]
    for name, decl_off, body_start, body_end in _functions(masked, lang):
        ln0 = _off_to_line(starts, body_start)     # 1-indexed line of '{'
        ln_end = _off_to_line(starts, body_end)
        # slice inclusive body lines (0-indexed list positions ln0-1 .. ln_end-1)
        sl = slice(ln0 - 1, ln_end)
        body = {"masked": masked_all[sl], "orig": orig_all[sl]}
        try:
            row = _analyze_function(name, body, ln0, lang, rel, file_blob)
        except Exception:
            row = None
        if row:
            rows.append(row)
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
        "guarded": sum(1 for r in rows if r.get("has_parent_bound_guard")),
        "memory_safe_silent": sum(
            1 for r in rows if r.get("disposition") == "memory-safe-slice-panic"),
        "severity_eligible": sum(1 for r in rows if r.get("severity_eligible")),
        "by_lang": _count_by(rows, "lang"),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def _count_by(rows, key):
    d = {}
    for r in rows:
        d[r.get(key)] = d.get(r.get(key), 0) + 1
    return d


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="EXT05 nested length-prefix parent-bound reconciliation screen (advisory)")
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
        return 1 if (strict and any(r.get("severity_eligible") for r in rows)) else 0

    if args.source:
        rows = scan_tree(Path(args.source))
        print(json.dumps(rows, indent=2))
        return 1 if (strict and any(r.get("severity_eligible") for r in rows)) else 0

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
        return 1 if (strict and summ["severity_eligible"]) else 0

    src = ws / "src"
    root = src if src.exists() else ws
    rows = scan_tree(root)
    _emit_sidecar(ws, rows)
    summ = _summary(rows)
    print(json.dumps(summ, indent=2))
    return 1 if (strict and summ["severity_eligible"]) else 0


if __name__ == "__main__":
    sys.exit(main())
