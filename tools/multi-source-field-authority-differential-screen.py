#!/usr/bin/env python3
"""multi-source-field-authority-differential-screen.py - the MULTI-SOURCE
AUTHORITATIVE-FIELD parser-differential screen (EXT01).

GENERAL LOGIC / TRUST-ENFORCEMENT class (never a bug SHAPE). It instantiates the
north-star method ("a trusted parse is UNSOUND at a cross-consumer trust
boundary") for one soundness property that NO single module owns:

  DUPLICATED-AUTHORITY FIELD : one logical field of a serialized artifact (a
    size / length / count / offset / entry-count) is carried in TWO-OR-MORE
    encodings or headers - tar ustar-size vs PAX-size, a length-prefix vs a
    delimiter/terminator, an outer Content-Length vs inner chunk sizes, canonical
    metadata vs an extended-attribute override, a DER copy vs a re-encoded copy.
  PRIVATE INVARIANT          : before THIS parser advances its read cursor by the
    size it CHOSE, it must ASSERT the sibling encodings are absent or byte-
    consistent (`if pax_size != 0 && pax_size != ustar_size -> reject`). A parser
    that selects one authority by precedence WITHOUT that consistency assert is
    unsound: a peer consumer (validator / signature-checker / dedup index / a
    second language's reader) that picks the OTHER authority walks the same bytes
    as a different entry/path set.
  ATTACK                     : the parser reads a duplicated-authority field from
    >1 source, picks one by precedence (fallback / override / conditional-
    reassignment), drives a length/cursor SINK with the chosen value, and never
    asserts the two sources agree. An attacker crafts ONE artifact this parser
    walks as N entries while a trusted peer walks as M!=N - smuggling a payload /
    entry / path past the enforcer that only inspected the other interpretation.

  ANCHOR : RUSTSEC-2025-0111 (tokio-tar) - ustar header size=0 while the PAX
    header size>0; tokio-tar advances by the ustar size (0) and reads what should
    be file bytes as the next entry header. Compliant readers use the PAX size, so
    the two consumers disagree on entry boundaries -> archive confusion / file
    smuggling. No per-parser detector owns this: they audit one parser in
    isolation and never compare how two consumers interpret the same bytes.

Enforcement points = every duplicated-authority field a parse routine reads from
>=2 sources by precedence AND then feeds into a length/cursor sink. The screen
answers per point:
  {field, sources[], precedence, sink, consistency_checked}
and FLAGS (fires=True, verdict=needs-fuzz) ONLY when:
  - the SAME size/length/count field is selected from >=2 distinct non-literal
    sources (a combinator `unwrap_or / or_else / map_or / ?:` OR a conditional
    override that re-assigns the field inside an `if`/`match` from another
    size-or-source ident), AND
  - the chosen field DRIVES a length/cursor sink (alloc-by-size, read_exact /
    ReadAt / take / CopyN / section-reader, a slice by the field, a cursor `+=`),
    AND
  - there is NO cross-source consistency assert - no comparison / assert / require
    / ensure whose two operands are the TWO sources of that field.
A duplicated-authority field that IS consistency-checked is emitted as a COVERED
lead (fires=False) so the (field, sources, precedence, consistency-checked?) table
is complete.

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False. It NEVER auto-credits and NEVER fail-closes in default mode; the
opt-in env AUDITOOOR_MSFA_STRICT (or --strict) only raises the exit code when a
fired (unchecked) duplicated-authority field exists. Escalation to a finding
REQUIRES a differential-parse PoC: one crafted artifact fed to two readers showing
divergent entry/path sets.

Language-general: Rust (.rs), Go (.go), Solidity (.sol). Silent on other trees and
on machine-generated / test sources.

Usage:
  --workspace <ws>   scan <ws>/src -> .auditooor/<sidecar>.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON (NO sidecar)
  --file <f>         scan a single file, print rows as JSON
  --check            re-read the emitted sidecar, print cert verdict (advisory)
  --strict           (or env) elevate exit code when a fired field exists
  --json             machine summary to stdout
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

HYP_SCHEMA = "auditooor.multi_source_field_authority_differential_hypotheses.v1"
_SIDE_NAME = "multi_source_field_authority_differential_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_MSFA_STRICT"
_CAPABILITY = "EXT01"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "lib", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmarks", "script", "scripts", "deployments",
              "prior_audits", "reference", "testdata", "test-data", "mocks",
              "examples", "fixtures"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|test_fixtures|mock|mocks|benches|benchmarks?|examples|fixtures)(/|$)")

# ---------------------------------------------------------------------------
# Machine-generated source is NOT the audited attack surface. Suffix fast-path +
# the "Code generated ... DO NOT EDIT" sentinel (ported from
# declared-control-mutator-completeness-screen.py::_is_generated_source).
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


_EXTS = (".rs", ".go", ".sol")


def _lang_of(path: Path) -> str:
    n = path.name.lower()
    if n.endswith(".rs"):
        return "rust"
    if n.endswith(".go"):
        return "go"
    if n.endswith(".sol"):
        return "solidity"
    return ""


def _iter_source_files(root: Path):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        if _TEST_HINT.search(dp.replace(os.sep, "/")):
            continue
        for f in fn:
            low = f.lower()
            if not low.endswith(_EXTS):
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
# Comment + string stripping. Preserves newlines and byte offsets so line numbers
# and brace-matching stay aligned; string/char/raw-string bodies are blanked so a
# brace or `//` inside a literal cannot fool the parser.
def _strip_code(text: str) -> str:
    out = []
    i, n = 0, len(text)
    in_line = in_block = False
    in_str = None           # holds the closing delimiter for the active string
    raw = False             # Go backtick raw string
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line:
            if c == "\n":
                in_line = False
                out.append(c)
            else:
                out.append(" ")
            i += 1
        elif in_block:
            if c == "*" and nxt == "/":
                in_block = False
                out.append("  ")
                i += 2
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
        elif in_str is not None:
            if c == "\n":
                # Go raw strings + unusual cases may span lines; keep newline.
                out.append(c)
                i += 1
                continue
            if not raw and c == "\\":
                out.append("  ")
                i += 2
                continue
            if c == in_str:
                in_str = None
                raw = False
                out.append(" ")
                i += 1
            else:
                out.append(" ")
                i += 1
        else:
            if c == "/" and nxt == "/":
                in_line = True
                out.append("  ")
                i += 2
            elif c == "/" and nxt == "*":
                in_block = True
                out.append("  ")
                i += 2
            elif c == '"':
                in_str = '"'
                raw = False
                out.append(" ")
                i += 1
            elif c == "`":
                in_str = "`"
                raw = True
                out.append(" ")
                i += 1
            elif c == "'":
                # Rust char / lifetime / Go rune. Only treat as a string when it
                # looks like a short char literal ('a' or '\n'); a lifetime
                # (`'a`) has no closing quote nearby.
                j = i + 1
                if j < n and text[j] == "\\":
                    close = i + 3
                else:
                    close = i + 2
                if close < n and text[close] == "'":
                    in_str = "'"
                    raw = False
                    out.append(" ")
                    i += 1
                else:
                    out.append(c)
                    i += 1
            else:
                out.append(c)
                i += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# Function extraction (brace-matched; Rust + Go + Solidity).
_FN_DECL_RE = re.compile(
    r"(?:"
    r"(?:pub\s+)?(?:async\s+)?(?:unsafe\s+)?(?:const\s+)?(?:extern\s+\"[^\"]*\"\s+)?fn\s+([A-Za-z_]\w*)"  # rust
    r"|func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)"          # go
    r"|function\s+([A-Za-z_]\w*)"                        # solidity
    r"|(constructor)\b"                                   # solidity
    r")")

_TEST_ATTR_RE = re.compile(r"#\s*\[\s*(?:cfg\s*\(\s*test\s*\)|[\w:]*test)")


def _line_starts(text: str):
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def _idx_to_line(starts, idx: int) -> int:
    # binary search: 1-based line number for a char index
    lo, hi = 0, len(starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if starts[mid] <= idx:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1


def _iter_functions(stripped: str, lang: str):
    """Yield (name, header_line, body_text, body_start_line) for each fn body."""
    starts = _line_starts(stripped)
    for m in _FN_DECL_RE.finditer(stripped):
        name = m.group(1) or m.group(2) or m.group(3) or m.group(4)
        if not name:
            continue
        # Rust: skip #[test] / #[cfg(test)] annotated fns (look back a few lines).
        if lang == "rust":
            pre = stripped[max(0, m.start() - 240):m.start()]
            if _TEST_ATTR_RE.search(pre):
                continue
        # find opening brace of the body
        j = stripped.find("{", m.end())
        if j == -1:
            continue
        # a `;` before the first `{` means a decl-only (interface / trait) -> skip
        semi = stripped.find(";", m.end())
        if semi != -1 and semi < j:
            continue
        depth = 0
        k = j
        end = -1
        while k < len(stripped):
            ch = stripped[k]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = k
                    break
            k += 1
        if end == -1:
            continue
        body = stripped[j + 1:end]
        yield name, _idx_to_line(starts, m.start()), body, _idx_to_line(starts, j + 1)


# ---------------------------------------------------------------------------
# Size / length field classifier (segment-aware so `client`/`silent` are NOT
# size-ish but `contentLength`/`pax_size`/`nEntries` are).
_SIZE_TOKENS = {
    "size", "sz", "len", "length", "count", "cnt", "nbytes", "numbytes",
    "offset", "nentries", "entries", "entry", "datalen", "payloadlen", "msglen",
    "bodylen", "hdrlen", "buflen", "chunklen", "blocklen", "blocksize",
    "chunksize", "framesize", "contentlength", "itemcount", "itemsize", "nitems",
    "records", "reclen", "amount", "width", "capacity",
}
# tokens that qualify a SOURCE of a duplicated field (base vs override encodings)
_OVERRIDE_TOKENS = {
    "pax", "ext", "extended", "extra", "xattr", "override", "gnu", "sparse",
    "long", "longname", "longlink", "attr", "inner", "chunk", "chunked",
    "secondary", "alt", "real", "trailer", "footer", "declared", "advertised",
}
_BASE_TOKENS = {
    "ustar", "header", "hdr", "base", "main", "outer", "primary", "canonical",
    "standard", "fixed", "meta", "prefix", "record", "raw",
}


def _segments(name: str):
    # split snake + camel + digit boundaries
    parts = re.split(r"[^A-Za-z0-9]+", name)
    out = []
    for p in parts:
        if not p:
            continue
        # camelCase / PascalCase / digit split
        for seg in re.findall(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+", p):
            out.append(seg.lower())
        # also keep the fully-joined lowercase form for glued tokens
        out.append(p.lower())
    return set(out)


def _is_size_ident(name: str) -> bool:
    if not name:
        return False
    segs = _segments(name)
    return bool(segs & _SIZE_TOKENS)


def _source_kind(name: str):
    segs = _segments(name)
    if segs & _OVERRIDE_TOKENS:
        return "override"
    if segs & _BASE_TOKENS:
        return "base"
    return None


_LIT_RE = re.compile(
    r"^(?:0x[0-9A-Fa-f_]+|\d[\d_]*(?:u\d+|i\d+|usize|isize)?|true|false|None|"
    r"Default::default\(\)|default\(\)|u\d+::MAX|i\d+::MAX|usize::MAX|"
    r"[A-Z][A-Z0-9_]*)$")  # trailing arm: ALL_CAPS constant (a limit, not a 2nd authority)


def _leading_ident(expr: str):
    expr = expr.strip()
    m = re.match(r"([A-Za-z_]\w*)", expr)
    return m.group(1) if m else None


def _strip_one_cast(e: str) -> str:
    """Strip ONE wrapping cast/paren layer:  (x) / uint64(x) / x as u64 -> x.
    Returns the argument unchanged when no single wrapping layer applies (a
    double cast or a `.`-qualified receiver like r.ReadAt(off) is NOT stripped)."""
    e = e.strip()
    # `x as u64` -> x  (Rust cast suffix)
    m = re.match(r"^(.+?)\s+as\s+\w+$", e)
    if m:
        return m.group(1).strip()
    # `(x)` -> x  (the whole expr wrapped in a single balanced paren pair)
    if e.startswith("(") and e.endswith(")"):
        depth = 0
        wraps = True
        for idx, ch in enumerate(e):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and idx != len(e) - 1:
                    wraps = False
                    break
        if wraps:
            return e[1:-1].strip()
    # `uint64(x)` / `u32(x)` -> x  (bare identifier-cast call around a single arg;
    # a `.`-qualified call such as r.ReadMetadataAt(off) does NOT match).
    m = re.match(r"^([A-Za-z_]\w*)\s*\((.*)\)$", e)
    if m and m.group(2).strip() and len(_split_top_commas(m.group(2))) == 1:
        return m.group(2).strip()
    return e


def _is_literal_alt(expr: str) -> bool:
    """A default/constant alt (unwrap_or(0), or(MAX)) is NOT a redundant second
    authority - it is a fallback default. Only a second *field* counts. A single
    wrapping numeric cast/paren layer is stripped first so a casted-zero default
    (uint32(0) / u64(0) / (0)) is recognized as a literal too."""
    e = expr.strip().rstrip(";, ").strip()
    if not e:
        return True
    if _LIT_RE.match(e):
        return True
    # strip ONE wrapping cast/paren layer:  uint32(0) / (0) / 0 as u64 -> 0
    inner = _strip_one_cast(e)
    if inner != e and _LIT_RE.match(inner):
        return True
    # legacy fallback: a stray unbalanced trailing ')' from an embedding extraction
    legacy = e.rstrip(") ").strip()
    if legacy != e and _LIT_RE.match(legacy):
        return True
    return False


# ---------------------------------------------------------------------------
# Precedence-combinators (a single-statement select of one field from 2 sources).
_COMBINATOR_RE = re.compile(
    r"\.(unwrap_or|unwrap_or_else|or|or_else|map_or|map_or_else|value_or)\s*\(")
# Solidity / general ternary select:  a = cond ? x : y
_TERNARY_RE = re.compile(r"\?\s*[^?:]+:")

_CTRL_LEAD_RE = re.compile(r"^\s*(if|for|while|match|switch|case|else|return|"
                           r"require|assert|ensure|revert)\b")
_DECL_LEAD_RE = re.compile(r"^\s*(let\s+mut|let|var|const|final)\b")


def _lhs_names(lhs: str):
    """Extract binding names from a (possibly typed / comma) LHS, dropping a
    leading let/var/const and any `<type> name` / `name: type` decoration."""
    lhs = _DECL_LEAD_RE.sub("", lhs, count=1).strip()
    names = []
    for part in _split_top_commas(lhs):
        p = part.strip()
        if not p:
            continue
        # drop a rust `: type` tail (but not `::`)
        p = re.split(r"(?<!:):(?!:)", p, maxsplit=1)[0].strip()
        toks = re.findall(r"[A-Za-z_]\w*", p)
        if toks:
            names.append(toks[-1])   # `uint256 len` -> len ; `length` -> length
    return names


def _parse_assign(line: str):
    """Return (names, op, rhs, is_decl) for an assignment statement, else None.
    Skips control-lead lines and compound-assign ops (+=, <<=, ...)."""
    if _CTRL_LEAD_RE.match(line):
        return None
    # locate the first := (Go) or a standalone = (not ==/!=/<=/>=/compound).
    walrus = line.find(":=")
    eq = -1
    for i, ch in enumerate(line):
        if ch != "=":
            continue
        prev = line[i - 1] if i > 0 else ""
        nxt = line[i + 1] if i + 1 < len(line) else ""
        if nxt == "=" or prev in "=!<>+-*/%&|^~:":
            continue
        eq = i
        break
    if walrus != -1 and (eq == -1 or walrus < eq):
        op, pos = ":=", walrus
        rhs = line[pos + 2:]
    elif eq != -1:
        op, pos = "=", eq
        rhs = line[pos + 1:]
    else:
        return None
    lhs = line[:pos]
    names = _lhs_names(lhs)
    if not names:
        return None
    is_decl = (op == ":=") or bool(_DECL_LEAD_RE.match(line)) or (
        # `<type> name = ...` typed declaration (LHS has 2+ tokens, no comma-list)
        len(_split_top_commas(lhs.strip())) == 1 and
        len(re.findall(r"[A-Za-z_]\w*", lhs)) >= 2)
    return names, op, rhs.strip().rstrip(";").strip(), is_decl


_COND_OPEN_RE = re.compile(r"\b(if|else\s+if|match|switch|case|when)\b")
_ASSERT_RE = re.compile(
    r"\b(assert|assert_eq|debug_assert|debug_assert_eq|require|ensure|expect|"
    r"panic|revert)\b|assert_eq!|assert_ne!|ensure!")
_RELOP_RE = re.compile(r"(==|!=|>=|<=|<|>)")

# length / cursor sinks driven by the chosen size field.
_SINK_RES = [
    re.compile(r"\bmake\s*\(\s*\[\]\s*[\w.\[\]]+\s*,"),      # go make([]T, n)
    re.compile(r"\bwith_capacity\s*\("),                     # rust Vec::with_capacity
    re.compile(r"\bvec!\s*\["),                              # rust vec![x; n]
    re.compile(r"\[\s*0[\w]*\s*;"),                          # rust [0u8; n]
    re.compile(r"\bread_exact\s*\("),
    re.compile(r"\bread_to_end\s*\(|\bread_to\s*\("),
    re.compile(r"\bread_full\b|\breadFull\b|\bReadFull\s*\("),
    re.compile(r"\bReadAt\s*\(|\bread_at\s*\("),
    re.compile(r"\btake\s*\("),
    re.compile(r"\bCopyN\s*\(|\bcopy_n\s*\("),
    re.compile(r"\bLimitReader\s*\("),
    re.compile(r"\bNewSectionReader\s*\("),
    re.compile(r"\bset_len\s*\(|\bresize\s*\(|\breserve\s*\(|\btruncate\s*\("),
    re.compile(r"\bseek\s*\(|\bSeek\s*\(|\badvance\s*\(|\bskip\s*\(|"
               r"\bdiscard\s*\(|\bDiscard\s*\(|\bconsume\s*\("),
    re.compile(r"\[[^\]]*\.\.[^\]]*\]"),                     # rust slice a..b
    re.compile(r"\[[^\]]*:[^\]]*\]"),                        # go slice a:b
    re.compile(r"(?:pos|off|offset|cursor|idx|index|ptr|head|read)\w*\s*\+="),
]


def _find_sink(body_lines, field):
    fld_re = re.compile(rf"\b{re.escape(field)}\b")
    for lineno, txt in body_lines:
        if not fld_re.search(txt):
            continue
        for sr in _SINK_RES:
            if sr.search(txt):
                return lineno, txt.strip()
    return None, None


_ALIAS_RES = [
    # if let Some(x) = src  /  while let Some(x) = src
    re.compile(r"\blet\s+Some\s*\(\s*([A-Za-z_]\w*)\s*\)\s*=\s*([A-Za-z_]\w*)"),
    re.compile(r"\bSome\s*\(\s*([A-Za-z_]\w*)\s*\)\s*=>"),   # match arm (alias, src ambiguous)
    # let x = src;  (bare-ident rebind, incl. `let x = src as u64` / `uint64(src)`)
    re.compile(r"\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::[^=]+)?=\s*([A-Za-z_]\w*)\s*(?:as\s+\w+)?\s*;"),
]


def _alias_groups(body_lines):
    """alias -> canonical-source (one hop). Handles `if let Some(px)=pax_size`,
    bare rebinds, and simple casts so a consistency assert phrased on a rebound
    name still counts."""
    amap = {}
    for _lineno, txt in body_lines:
        m = _ALIAS_RES[0].search(txt)
        if m:
            amap.setdefault(m.group(1), m.group(2))
        m = _ALIAS_RES[2].search(txt)
        if m and m.group(1) != m.group(2):
            amap.setdefault(m.group(1), m.group(2))
    return amap


def _expand(name, amap):
    grp = {name}
    if name in amap:
        grp.add(amap[name])
    for al, src in amap.items():
        if src == name:
            grp.add(al)
    return grp


def _has_consistency(body_lines, a, b, skip_line, amap):
    """True iff some line ties the two sources (or their aliases) together via a
    comparison or an assert/require/ensure (the cross-source agreement check)."""
    if not a or not b or a == b:
        return None
    ga = _expand(a, amap)
    gb = _expand(b, amap)
    ra = re.compile(r"\b(?:%s)\b" % "|".join(re.escape(x) for x in ga))
    rb = re.compile(r"\b(?:%s)\b" % "|".join(re.escape(x) for x in gb))
    for lineno, txt in body_lines:
        if lineno == skip_line:
            continue
        if ra.search(txt) and rb.search(txt):
            if _RELOP_RE.search(txt) or _ASSERT_RE.search(txt):
                return lineno
    return None


def _split_top_commas(s: str):
    """Split on commas not nested in (), [], <>, {}."""
    out, depth, cur = [], 0, []
    for ch in s:
        if ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur))
    return out


def _detect_precedence(body_lines):
    """Yield precedence-select candidates:
       (field, src_a, src_b, precedence, decl_line)."""
    # index assignments by field to find conditional-reassignment overrides
    assigns = {}          # field -> list of (lineno, depth, rhs, is_conditional)
    depth = 0
    cond_stack = []       # is the currently-open brace a conditional block?
    seen = []

    for lineno, txt in body_lines:
        stripped = txt.strip()
        parsed = _parse_assign(txt)
        lhs_names = parsed[0] if parsed else []
        rhs = parsed[2] if parsed else ""
        is_decl = parsed[3] if parsed else False
        # -- combinator / ternary single-statement select ------------------
        if parsed and len(lhs_names) == 1 and _is_size_ident(lhs_names[0]):
            fld = lhs_names[0]
            cm = _COMBINATOR_RE.search(rhs)
            if cm:
                recv = rhs[:cm.start()].strip()
                recv_id = _leading_ident(recv.rsplit(".", 1)[0] if "." in recv else recv)
                arg = rhs[cm.end():]
                # first top-level arg of the combinator
                arg_inner = arg
                # cut at matching close paren depth
                depth2, buf = 1, []
                for ch in arg:
                    if ch == "(":
                        depth2 += 1
                    elif ch == ")":
                        depth2 -= 1
                        if depth2 == 0:
                            break
                    buf.append(ch)
                arg_inner = "".join(buf)
                alt = _split_top_commas(arg_inner)[0] if arg_inner.strip() else ""
                alt_id = _leading_ident(alt)
                if recv_id and alt_id and not _is_literal_alt(alt):
                    # at least one operand must look size-ish or source-qualified
                    if (_is_size_ident(recv_id) or _source_kind(recv_id) or
                            _is_size_ident(alt_id) or _source_kind(alt_id)):
                        seen.append((fld, recv_id, alt_id, "combinator", lineno))
            else:
                tern = _TERNARY_RE.search(rhs)
                if tern:
                    q = rhs.index("?")
                    colon = rhs.index(":", q)
                    a_expr = rhs[q + 1:colon]
                    b_expr = rhs[colon + 1:]
                    a_id = _leading_ident(a_expr)
                    b_id = _leading_ident(b_expr)
                    if (a_id and b_id and a_id != b_id and not _is_literal_alt(a_expr)
                            and not _is_literal_alt(b_expr)
                            and (_is_size_ident(a_id) or _source_kind(a_id))
                            and (_is_size_ident(b_id) or _source_kind(b_id))):
                        seen.append((fld, a_id, b_id, "ternary", lineno))

        # -- record assignments for conditional-override detection ---------
        if parsed:
            # for a multi-var LHS (e.g. Go `typ, length, err := ...`) the RHS
            # cannot be attributed to one name, so rhs_id is None there.
            single = len(lhs_names) == 1
            rhs_id = _leading_ident(rhs) if single else None
            for nm in lhs_names:
                if _is_size_ident(nm):
                    assigns.setdefault(nm, []).append(
                        (lineno, depth, rhs, rhs_id, bool(cond_stack), is_decl))

        # -- brace depth bookkeeping (after processing the line) -----------
        opens = txt.count("{")
        closes = txt.count("}")
        is_cond_line = bool(_COND_OPEN_RE.search(stripped))
        for _ in range(opens):
            cond_stack.append(is_cond_line)
            depth += 1
        for _ in range(closes):
            if cond_stack:
                cond_stack.pop()
            depth = max(0, depth - 1)

    # conditional-override: a field first BOUND at a dominating (non-conditional)
    # site, then RE-ASSIGNED inside a conditional block from a DIFFERENT size/
    # source ident. Tuple = (lineno, depth, rhs, rhs_id, is_conditional, is_decl).
    #
    # The override MUST be a plain reassignment (is_decl False): a fresh `:=` /
    # `let` inside a nested block is a NEW shadow binding that never reaches the
    # outer field the sink reads, so two independent `x := ...` in sibling if/else
    # branches are NOT an override (that was a real FP on sei consensus.go).
    for fld, sites in assigns.items():
        if len(sites) < 2:
            continue
        base_sites = [s for s in sites if not s[4]]        # dominating, top-level
        override_sites = [s for s in sites
                          if s[4] and not s[5]]            # conditional reassignment
        if not base_sites or not override_sites:
            continue
        for (ln, dpth, rhs, rhs_id, _c, _d) in override_sites:
            # a DOMINATING base binding of fld must appear BEFORE the override AND
            # carry a genuine non-literal second source. A literal-default base
            # (`size := 0` / `length := uint32(0)`) is single-authority - the 0 is
            # an uninitialized default, not a second encoding of the field - so a
            # lone conditional reassignment from one source is NOT a differential.
            # (Mirrors the combinator/ternary arms, which exclude a literal alt.)
            if not any(b[0] < ln and not _is_literal_alt(b[2]) for b in base_sites):
                continue
            if not rhs_id or rhs_id == fld:
                continue
            if _is_literal_alt(rhs):
                continue
            # override RHS must be a size/source ident, not a derive of fld itself
            if not (_is_size_ident(rhs_id) or _source_kind(rhs_id)):
                continue
            # avoid pure arithmetic on the field (fld = fld - n etc.)
            if re.search(rf"\b{re.escape(fld)}\b", rhs):
                continue
            # dedup against a combinator already emitted for the same field/line
            if any(s[0] == fld and s[4] == ln for s in seen):
                continue
            seen.append((fld, rhs_id, fld, "conditional-override", ln))

    return seen


# ---------------------------------------------------------------------------
def scan_file(path: Path, rel: str, file_text: str = None):
    lang = _lang_of(path)
    if not lang:
        return []
    if file_text is None:
        try:
            file_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
    stripped = _strip_code(file_text)
    rows = []
    for name, hdr_line, body, body_start in _iter_functions(stripped, lang):
        body_lines = []
        for off, ln in enumerate(body.split("\n")):
            body_lines.append((body_start + off, ln))
        cands = _detect_precedence(body_lines)
        if not cands:
            continue
        amap = _alias_groups(body_lines)
        # dedup identical (field, decl_line)
        seen_keys = set()
        for (field, src_a, src_b, prec, decl_line) in cands:
            key = (field, decl_line, prec)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            sink_line, sink_txt = _find_sink(body_lines, field)
            if sink_line is None:
                continue    # a select with no length/cursor sink is not on-class
            ck_line = _has_consistency(body_lines, src_a, src_b, decl_line, amap)
            fires = ck_line is None
            rows.append({
                "capability": _CAPABILITY,
                "fires": fires,
                "file": rel,
                "line": decl_line,
                "function": name,
                "advisory": True,
                "auto_credit": False,
                "verdict": "needs-fuzz",
                "subclass": "multi-source-authoritative-field-differential",
                "language": lang,
                "field": field,
                "sources": [src_a, src_b],
                "precedence": prec,
                "sink": sink_txt,
                "sink_line": sink_line,
                "consistency_checked": (ck_line is not None),
                "consistency_line": ck_line,
                "anchor": "RUSTSEC-2025-0111 tokio-tar ustar-vs-PAX size",
                "note": (
                    f"parser '{name}' selects size field '{field}' from >=2 sources "
                    f"({src_a} / {src_b}) via {prec} and drives a length/cursor sink "
                    f"at L{sink_line}"
                    + ("; NO cross-source consistency assert -> a peer consumer "
                       "picking the other authority walks a different entry set "
                       "(differential-parse smuggling). Escalate ONLY with a "
                       "two-reader divergence PoC."
                       if fires else
                       f"; consistency asserted at L{ck_line} (covered).")
                ),
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
        "covered": sum(1 for r in rows if not r.get("fires")),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="EXT01 multi-source authoritative-field parser-differential "
                    "screen (advisory)")
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
