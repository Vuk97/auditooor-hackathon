#!/usr/bin/env python3
"""G9 - Go unbounded-allocation / no-progress-loop enforcement screen (GENERAL).

North-star framing (w8mv5mpcw - "A TRUSTED ENFORCEMENT is bypassable or its
private invariant is unsound"):

  * DELEGATED-AND-TRUSTED enforcement: a RESOURCE-SIZING primitive - either an
    eager allocation (``make([]T, n)`` / ``make([]T, 0, n)`` / ``make(map[K]V,
    n)`` / ``growslice(x, n)`` / ``buf.Grow(n)``) or a bounded loop
    (``for i := 0; i < n; i++``) - consumes a length/count value ``n`` to size
    memory or to bound the work it will do.  The site DELEGATES to (TRUSTS) an
    upstream producer to have bounded ``n``.
  * PRIVATE INVARIANT: ``n <= MAX`` for some sane cap, established BEFORE the
    sizing site and DOMINATING it on every path (or the loop otherwise carries a
    max-iteration / progress guarantee).
  * ATTACK ON THE INVARIANT: when ``n`` is derived from a decode / deserialize /
    wire-read boundary (an EXTERNAL producer) and NO cap-enforcement point
    dominates the sizing site, an attacker sets ``n`` to ``MaxUint32`` / a huge
    ``uint64`` and forces a multi-GiB allocation or an unbounded loop before any
    real payload is processed - pre-auth memory/CPU amplification (OOM / halt).

This is the GENERAL resource-exhaustion invariant, NOT a specific bug shape:
  - It enumerates the WHOLE length-sized-work primitive family (allocation AND
    loop-bound) and asks ONE enforcement-completeness question of each site:
    "does a MAX-cap guard dominate this length-proportional allocation/loop?"
  - The IMPACT is left open (verdict=needs-fuzz); nothing here decides a tier.

Deduplication vs pre-existing detectors (tool-duplication preflight, do-NOT #10):
  - ``go-detector-runner.py`` Pattern 36 (``go.crypto.loop.untrusted_length_
    unbounded``), the G11 arm (``go.panic.untrusted_ingress_unbounded_loop_or_
    panic``) and the fire7 ``go_ast_dos_cap_unbounded_input_growth`` detector are
    the IN-RUNNER, higher-precision confirmers.  Those live inside the shared
    go-detector-runner and this screen deliberately does NOT edit them.
  - G9 is a SEPARATE, standalone ADVISORY lens keyed on the ENFORCEMENT-
    COMPLETENESS invariant over the ALLOCATION-SIZING primitives (make/growslice/
    Grow) as well as the loop-bound, emitting its own
    ``go_unbounded_alloc_noprogress_hypotheses.jsonl`` sidecar so it can later be
    folded (needs-fuzz, no-auto-credit) by ``auto-coverage-closer``.  Rows are a
    SUPERSET lens ("no dominating cap"); the runner patterns remain the higher-
    precision confirmers.  G9 never auto-credits and never fail-closes a gate.

Fleet (mutation-verify corpus, read-only): optimism / sei / polygon / nuva.

Advisory-first contract:
  - A row is emitted ONLY for a length-sized alloc/loop whose length is
    decode/wire-boundary derived AND has NO dominating MAX-cap (i.e. it FIRES
    when the guard is absent, and is SILENT on guarded/benign sites).
  - Every row carries ``verdict="needs-fuzz"`` and ``auto_credit=False``.  The
    process NEVER exits non-zero on findings unless ``--strict`` is explicitly
    passed (opt-in CI signal); default is advisory (exit 0).

CLI:
    python3 tools/go-unbounded-alloc-noprogress-screen.py --workspace ~/audits/sei --print-json
    python3 tools/go-unbounded-alloc-noprogress-screen.py --workspace ~/audits/sei   # writes sidecar
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path


SCHEMA_VERSION = "auditooor.go_unbounded_alloc_noprogress_screen.v1"
DETECTOR = "go.dos.unbounded_alloc_or_noprogress_loop"

# Directories / suffixes never worth scanning (vendored / generated / tests).
SKIP_DIR_PARTS = {
    "vendor", "node_modules", "testdata", ".git", "third_party",
    "mocks", "mock", ".auditooor", "critical_hunt", "prior_audits",
    ".engage_scratch",
}
SKIP_SUFFIX = (
    "_test.go", ".pb.go", ".pb.gw.go", "_string.go", "_gen.go", ".gen.go",
    "_mock.go", "mock_test.go",
)

# ---------------------------------------------------------------------------
# Length-sized-work primitive family (GENERAL - the whole class, not one shape).
# Each allocation primitive is LOCATED by a keyword regex; the sizing argument
# is then extracted by a paren-depth-aware scan (so a call-wrapped length such as
# ``int(binary.BigEndian.Uint32(b))`` is captured intact, which a flat regex
# cannot do).  For ``make`` the CAPACITY (3rd arg when present, else the length
# arg) is what allocates.
# ---------------------------------------------------------------------------
_MAKE_TYPE_RE = re.compile(r"^\s*(?:\[\]|map\[)")
ALLOC_LOCATORS: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    ("make", re.compile(r"\bmake\s*\(")),
    # growslice(base, n) (go-ethereum) / any eager grow helper.
    ("growslice", re.compile(r"\bgrowslice\s*\(")),
    # buf.Grow(n) / builder.Grow(n) - bytes.Buffer / strings.Builder reserve.
    ("grow", re.compile(r"\.\s*Grow\s*\(")),
)

# for i := 0; i < n; i++  -> the loop is bounded by the length EXPRESSION `n`.
LOOP_PRIMITIVE = (
    "loop_bound",
    re.compile(
        r"\bfor\b[^;{\n]*;\s*[A-Za-z_][\w.]*\s*<=?\s*(?P<len>[^;{\n]+?)\s*;"
    ),
)

# ---------------------------------------------------------------------------
# Boundary tokens: a token is decode/wire-boundary derived when it is assigned
# from (or the length expression itself directly contains) one of these reads.
# ---------------------------------------------------------------------------
BOUNDARY_RHS_TOKENS = (
    "binary.BigEndian.Uint16",
    "binary.BigEndian.Uint32",
    "binary.BigEndian.Uint64",
    "binary.LittleEndian.Uint16",
    "binary.LittleEndian.Uint32",
    "binary.LittleEndian.Uint64",
    "binary.Uvarint",
    "binary.Varint",
    "binary.ReadUvarint",
    "binary.ReadVarint",
    "binary.Read",
    "ReadUvarint",
    "ReadVarint",
    "DecodedLen",       # snappy.DecodedLen / lz4 etc - reads the length prefix
    "readUint24",       # go-ethereum rlpx frame size
    ".Uint16(",
    ".Uint32(",
    ".Uint64(",
)

# Decode-context signals in the enclosing fn (name or body) that make an integer
# PARAMETER / decoded FIELD trustworthy-as-wire-length.
DECODE_CTX_NAME_RE = re.compile(
    r"(?:decode|deserialize|unmarshal|from_?bytes|from_?slice|parse|unpack|"
    r"readframe|readmsg|read_?msg|readmessage|decompress|scan)",
    re.IGNORECASE,
)
DECODE_CTX_BODY_TOKENS = (
    "Unmarshal",
    "binary.Read",
    "binary.BigEndian",
    "binary.LittleEndian",
    "DecodedLen",
    "ReadUvarint",
    "io.Reader",
    "bufio.Reader",
    ".Decode(",
    "asn1.",
    "gob.NewDecoder",
    "json.Unmarshal",
    "proto.Unmarshal",
)
# WEAK decode signal - the fn RECEIVES wire input as a ``[]byte`` / ``io.Reader``
# / ``bytes.Reader`` PARAMETER.  This is checked against the PARAM list (never the
# body): a bare ``[]byte`` in the body is circular (every ``make([]byte, n)``
# contains it) and a ``.data`` struct-field access is not a wire read.  (Fleet FP:
# go-ethereum rlpx writeBuffer.appendZero, an internal zero-fill write helper.)
DECODE_PARAM_TYPE_RE = re.compile(
    r"\[\s*\]\s*(?:byte|uint8)\b|io\.Reader|bufio\.Reader|"
    r"\*?\s*bytes\.(?:Reader|Buffer)"
)

# A length looks like a length by NAME (param or decoded field tail).
LEN_NAME_RE = re.compile(
    r"(?:^|[^A-Za-z])(?:len|length|size|count|num|amount|capacity|cap|n|"
    r"nbytes|numbytes|[A-Za-z_]*len|[A-Za-z_]*length|[A-Za-z_]*size|"
    r"[A-Za-z_]*count|num[A-Za-z_]*)$",
    re.IGNORECASE,
)

# Decoded-struct-field length: foo.SomethingLen / foo.NumX / foo.Size / foo.Count.
FIELD_LEN_RE = re.compile(
    r"\b[A-Za-z_]\w*\.(?:\w*Len|\w*Length|\w*Size|\w*Count|Num\w+)\b"
)

# Materialized-collection length - bounded by an ALREADY-allocated object, so it
# is NOT a pre-read amplification boundary. Exclude.
MATERIALIZED_LEN_RE = re.compile(r"\b(?:len|cap)\s*\(")
# Compile-time constant length (ALL_CAPS ident, or a numeric literal / arith).
ALLCAPS_CONST_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
NUMERIC_ONLY_RE = re.compile(r"^[0-9_]+(?:\s*[*+/<>-]{1,2}\s*[0-9_]+)*$")

# Dominating cap-enforcement idioms (searched in the fn body BEFORE the site and
# required to CO-OCCUR near the length token, plus structural comparison guards).
CAP_GUARD_TOKENS = (
    "Max", "MAX", "Maximum", "Limit", "LIMIT", "TooLarge", "too large",
    "too big", "exceeds", "min(", "Min(",
)

# Go fn header: func (recv T) Name(params) ... {   OR   func Name(params) ... {
FN_START_RE = re.compile(
    r"\bfunc\s*(?:\(\s*[A-Za-z_]\w*\s+[\w.*\[\]]+\s*\)\s*)?"
    r"(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^{]*?)\)",
    re.DOTALL,
)

# Assignment (Go): supports ``a := rhs``, ``a = rhs`` and multi-LHS ``a, err =
# rhs``.  The LHS must NOT span a newline (else a preceding ``var x int``
# declaration line would be swallowed into the following assignment's LHS and the
# token would no longer match by name).
BOUNDARY_ASSIGN_RE = re.compile(
    r"(?:^|\n)[ \t]*(?:var\s+)?(?P<lhs>[A-Za-z_][\w,\t ]*?)\s*:?=\s*(?P<rhs>[^\n]+)"
)

# A single length-token candidate: an identifier (optionally a field chain).
TOKEN_RE = re.compile(r"[A-Za-z_][\w.]*")
_KEYWORDS = {"int", "uint", "int32", "uint32", "int64", "uint64", "int16",
             "uint16", "byte", "uintptr", "len", "cap", "make"}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class UnboundedRow:
    file: str
    line: int
    primitive: str          # make_len / make_cap / growslice / grow / loop_bound
    kind: str               # "alloc" or "loop"
    function: str
    length_expr: str
    length_token: str
    boundary_source: str    # wire_read / inline_wire_read / decode_param / decode_field
    detector: str = DETECTOR
    invariant: str = (
        "n <= MAX established and dominating the length-sized alloc/loop"
    )
    enforcement_status: str = "unbounded"
    dominating_cap_found: bool = False
    snippet: str = ""
    attack_class: str = "unbounded-alloc-or-noprogress-loop-dos"
    hacker_question: str = ""
    verdict: str = "needs-fuzz"
    auto_credit: bool = False
    advisory: bool = True
    recommendation: str = (
        "Enforce an upper bound on the decode-boundary length BEFORE the "
        "allocation / loop (if n > MAX { return err }), or bound the loop by the "
        "actually-available input length, so a hostile length cannot force a "
        "pre-payload multi-GiB allocation or an unbounded loop (OOM / CPU halt)."
    )
    harness_task: str = (
        "Fuzz: feed the decoder a length prefix at MaxUint32 / a large uint64 "
        "and assert the callee rejects it (err) and does not eagerly allocate, "
        "grow, or loop proportionally to the attacker length."
    )
    not_applicable_impacts: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _safe_rel(path: Path, workspace: Path) -> str:
    try:
        return str(path.relative_to(workspace))
    except ValueError:
        return str(path)


def _snippet(text: str, offset: int) -> str:
    line_start = text.rfind("\n", 0, offset) + 1
    line_end = text.find("\n", offset)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end].strip()[:200]


def _extract_call_args(text: str, open_idx: int) -> tuple[list[str], int]:
    """Given ``open_idx`` = index of a ``(``, return (top_level_args, end_idx).

    Splits on top-level commas only (paren/bracket/brace-depth aware) so a
    call-wrapped or indexed argument (``int(f(x))`` / ``b[i:j]``) is kept intact.
    ``end_idx`` is the index just past the matching ``)`` (or len(text)).
    """
    n = len(text)
    depth = 0
    args: list[str] = []
    cur: list[str] = []
    i = open_idx
    while i < n:
        c = text[i]
        if c in "([{":
            depth += 1
            if depth == 1 and c == "(":
                i += 1
                continue  # skip the outermost opening paren itself
            cur.append(c)
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                arg = "".join(cur).strip()
                if arg:
                    args.append(arg)
                return args, i + 1
            cur.append(c)
        elif c == "," and depth == 1:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        i += 1
    if cur:
        args.append("".join(cur).strip())
    return args, n


def _enclosing_fn(text: str, offset: int) -> tuple[str, str, str, int]:
    """Return (fn_name, params, fn_full_text, fn_start_offset).

    ``fn_full_text`` is the enclosing fn text (decl..matching closing brace);
    ``fn_start_offset`` is its absolute start so callers can slice the region
    that DOMINATES a downstream site.
    """
    last_start = -1
    last_name = "<file>"
    last_params = ""
    for m in FN_START_RE.finditer(text, 0, offset + 1):
        last_start = m.start()
        last_name = m.group("name")
        last_params = m.group("params") or ""
    if last_start < 0:
        return "<file>", "", text, 0
    n = len(text)
    i = text.find("{", last_start)
    if i < 0:
        return last_name, last_params, text[last_start:], last_start
    depth = 0
    j = i
    while j < n:
        c = text[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                j += 1
                break
        j += 1
    return last_name, last_params, text[last_start:j], last_start


def _param_names(params: str) -> set[str]:
    """Extract Go parameter identifier names.

    Handles ``name Type``, grouped ``a, b Type`` and variadic ``args ...T``.
    """
    names: set[str] = set()
    for part in params.split(","):
        part = part.strip()
        if not part:
            continue
        m = re.match(r"([A-Za-z_]\w*)\b", part)
        if m and m.group(1) not in _KEYWORDS:
            names.add(m.group(1))
    return names


def is_decode_context(fn_name: str, fn_params: str, fn_body: str) -> bool:
    if DECODE_CTX_NAME_RE.search(fn_name):
        return True
    for tok in DECODE_CTX_BODY_TOKENS:
        if tok in fn_body:
            return True
    # The fn RECEIVES wire input as a []byte / io.Reader param (checked against
    # the param list, NOT the body - see DECODE_PARAM_TYPE_RE rationale).
    if DECODE_PARAM_TYPE_RE.search(fn_params):
        return True
    return False


# Bases whose `.Field` is a compile-time package constant (crypto/hash block+digest
# sizes), NOT an attacker-decoded wire field - e.g. aes.BlockSize, sha256.Size.
_PKG_CONST_BASES = frozenset({
    "aes", "des", "rc4", "md5", "sha1", "sha256", "sha512", "sha3",
    "blake2b", "blake2s", "crc32", "crc64", "adler32", "fnv", "ripemd160",
})
# Bases that are operator-set CONFIG structs, not attacker-wire-derived - e.g.
# cfg.batchSize, opts.MaxItems. A config-sized allocation is not a wire boundary.
_CONFIG_BASES = frozenset({
    "cfg", "config", "conf", "opts", "opt", "options", "settings",
})


def classify_boundary_source(
    length_expr: str,
    fn_name: str,
    fn_params: str,
    fn_body: str,
) -> tuple[str | None, str]:
    """CORE PREDICATE (half 1): is the length decode/wire-boundary derived?

    Returns (source_kind, primary_token) or (None, "") when the length is NOT a
    pre-read boundary length (materialized collection / compile-time const /
    unrelated local).  Neutralizing this predicate (forcing it to return None)
    must make every positive row disappear - see the non-vacuity test.
    """
    expr = length_expr.strip()

    # Exclude materialized-collection lengths (already-allocated object bound).
    if MATERIALIZED_LEN_RE.search(expr):
        return None, ""
    # Exclude pure compile-time constants / numeric arithmetic.
    if ALLCAPS_CONST_RE.match(expr) or NUMERIC_ONLY_RE.match(expr):
        return None, ""

    # (0) The length EXPRESSION itself directly contains a wire read
    #     (e.g. int(binary.BigEndian.Uint32(chunk[5:9]))). Inline boundary.
    for bt in BOUNDARY_RHS_TOKENS:
        if bt in expr:
            return "inline_wire_read", expr[:80]

    tokens = [
        t for t in TOKEN_RE.findall(expr)
        if t not in _KEYWORDS and not t.replace("_", "").isdigit()
    ]
    if not tokens:
        return None, ""

    decode_ctx = is_decode_context(fn_name, fn_params, fn_body)
    params = _param_names(fn_params)

    for tok in tokens:
        base = tok.split(".")[0]

        # (a) token assigned from a wire/decode boundary read in the fn body.
        for m in BOUNDARY_ASSIGN_RE.finditer(fn_body):
            lhs_names = {p.strip() for p in m.group("lhs").split(",")}
            if base not in lhs_names:
                continue
            rhs = m.group("rhs")
            if any(bt in rhs for bt in BOUNDARY_RHS_TOKENS):
                return "wire_read", tok

        # (b) token IS a fn parameter that looks like a length, in a decode ctx.
        if base in params and decode_ctx and LEN_NAME_RE.search(base):
            return "decode_param", tok

        # (c) decoded-struct-field length (foo.SomethingLen) in a decode ctx.
        #     Exclude METHOD calls (foo.Len()) - a method return is computed,
        #     not a decoded wire field.
        if "." in tok and decode_ctx and FIELD_LEN_RE.search(tok):
            if (tok + "(") in expr or (tok + " (") in expr:
                continue
            # Exclude package-const idioms (aes.BlockSize) + config-struct fields
            # (cfg.batchSize): compile-time / operator-set, not attacker-wire.
            if base in _PKG_CONST_BASES or base in _CONFIG_BASES:
                continue
            return "decode_field", tok

    return None, ""


def has_dominating_cap(length_token: str, fn_body_before: str) -> tuple[bool, str]:
    """CORE PREDICATE (half 2): is there a MAX-cap enforcement that dominates?

    ``fn_body_before`` is the fn text from its declaration up to (and including)
    the alloc/loop line.  A cap must be a structural comparison guard on the
    token OR a known cap idiom co-occurring near the token.  Neutralizing this
    predicate (forcing it to return True) must silence every positive row - see
    the non-vacuity test.
    """
    base = re.split(r"[.\s(]", length_token.strip())[0]
    if not base:
        return False, ""

    # Structural comparison-guard: `if <tok> > ...` / `>= ` / `<tok> = min(...)`.
    if re.search(rf"\b{re.escape(base)}\s*(?:>|>=)\s*", fn_body_before):
        return True, "compare_guard"
    if re.search(rf"\b{re.escape(base)}\s*=\s*(?:min|Min)\s*\(", fn_body_before):
        return True, "min_clamp"

    # Idiom-based cap co-occurring within +/-180 chars of the token.
    for tok in CAP_GUARD_TOKENS:
        idx = fn_body_before.find(tok)
        while idx != -1:
            window = fn_body_before[max(0, idx - 180): idx + 180]
            if base in window:
                return True, tok
            idx = fn_body_before.find(tok, idx + 1)
    return False, ""


def _hacker_question(row_kind: str, token: str, fn: str) -> str:
    if row_kind == "loop":
        return (
            f"Can an attacker set the decode-boundary length `{token}` to a huge "
            f"value so the loop in `{fn}` iterates unbounded (CPU halt / DoS) with "
            f"no MAX-cap guard dominating it?"
        )
    return (
        f"Can an attacker set the decode-boundary length `{token}` to MaxUint32 / "
        f"a large uint64 so `{fn}` eagerly allocates multi-GiB before any payload "
        f"is validated, with no MAX-cap guard dominating the reservation (OOM)?"
    )


# ---------------------------------------------------------------------------
# Per-file scanning
# ---------------------------------------------------------------------------


def _alloc_sites(text: str) -> list[tuple[int, str, str]]:
    """Enumerate allocation sites as (offset, primitive, length_expr).

    Locates each primitive keyword, extracts its call args paren-depth-aware,
    and selects the SIZING expression (make capacity / grow-target arg).
    """
    out: list[tuple[int, str, str]] = []
    for family, pat in ALLOC_LOCATORS:
        for m in pat.finditer(text):
            open_idx = m.end() - 1  # index of the '('
            args, _end = _extract_call_args(text, open_idx)
            if not args:
                continue
            if family == "make":
                # make(T, len[, cap]) - the CAPACITY is the eager reservation.
                if not _MAKE_TYPE_RE.match(args[0]):
                    continue  # not a slice/map make (e.g. make(chan, n))
                if len(args) >= 3:
                    out.append((m.start(), "make_cap", args[2]))
                elif len(args) == 2:
                    out.append((m.start(), "make_len", args[1]))
            elif family == "growslice":
                if len(args) >= 2:
                    out.append((m.start(), "growslice", args[1]))
            elif family == "grow":
                if len(args) >= 1:
                    out.append((m.start(), "grow", args[0]))
    return out


def scan_text(text: str, rel: str) -> list[UnboundedRow]:
    rows: list[UnboundedRow] = []
    seen: set[tuple[int, str]] = set()

    sites: list[tuple[int, str, str, str]] = [
        (off, prim, expr, "alloc") for off, prim, expr in _alloc_sites(text)
    ]
    for m in LOOP_PRIMITIVE[1].finditer(text):
        sites.append((m.start(), LOOP_PRIMITIVE[0], m.group("len").strip(), "loop"))

    for offset, primitive, length_expr, kind in sites:
        length_expr = length_expr.strip()
        if not length_expr:
            continue
        fn_name, fn_params, fn_full, fn_start = _enclosing_fn(text, offset)

        source, token = classify_boundary_source(
            length_expr, fn_name, fn_params, fn_full
        )
        if source is None:
            continue

        # Cap must DOMINATE: the guard region is the fn text from its
        # declaration up to (and including) the alloc/loop line.
        line_end = text.find("\n", offset)
        if line_end == -1:
            line_end = len(text)
        fn_body_before = text[fn_start:line_end]

        capped, _ind = has_dominating_cap(token, fn_body_before)
        if capped:
            continue  # SILENT on guarded/benign sites.

        line = _line_for_offset(text, offset)
        key = (line, primitive)
        if key in seen:
            continue
        seen.add(key)

        rows.append(
            UnboundedRow(
                file=rel,
                line=line,
                primitive=primitive,
                kind=kind,
                function=fn_name,
                length_expr=length_expr,
                length_token=token,
                boundary_source=source,
                snippet=_snippet(text, offset),
                hacker_question=_hacker_question(kind, token, fn_name),
            )
        )
    rows.sort(key=lambda r: (r.line, r.primitive))
    return rows


def scan_file(file_path: Path, workspace: Path) -> list[UnboundedRow]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return scan_text(text, _safe_rel(file_path, workspace))


# ---------------------------------------------------------------------------
# File enumeration
# ---------------------------------------------------------------------------


def enumerate_files(workspace: Path, extra_roots: list[str]) -> list[Path]:
    seen: set[Path] = set()
    out: list[Path] = []
    roots: list[Path]
    if extra_roots:
        roots = [(workspace / r) for r in extra_roots]
    else:
        roots = [workspace]
    for root in roots:
        root = root.resolve()
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.go")):
            if set(path.parts) & SKIP_DIR_PARTS:
                continue
            if path.name.endswith(SKIP_SUFFIX):
                continue
            if path in seen:
                continue
            seen.add(path)
            out.append(path)
    return out


def _count_by(rows: list[UnboundedRow], key) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        k = key(r)
        out[k] = out.get(k, 0) + 1
    return out


def run(workspace: Path, extra_roots: list[str]) -> list[UnboundedRow]:
    files = enumerate_files(workspace, extra_roots)
    rows: list[UnboundedRow] = []
    for f in files:
        rows.extend(scan_file(f, workspace))
    rows.sort(key=lambda r: (r.file, r.line, r.primitive))
    return rows


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="go-unbounded-alloc-noprogress-screen.py",
        description=(
            "G9 - GENERAL Go unbounded-allocation / no-progress-loop enforcement "
            "screen. Advisory-first: flags eager allocs and length-bounded loops "
            "whose length is decode/wire boundary derived and has NO dominating "
            "MAX-cap guard (verdict=needs-fuzz)."
        ),
    )
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument(
        "--root",
        action="append",
        default=[],
        help="Extra workspace-relative path to walk. May be repeated.",
    )
    parser.add_argument(
        "--print-json",
        action="store_true",
        help="Print the JSON payload to stdout instead of writing the JSON report.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "OPT-IN CI signal: exit 1 when any advisory row is emitted. Default "
            "is advisory-first (exit 0 regardless of rows)."
        ),
    )
    args = parser.parse_args(argv)

    workspace: Path = args.workspace
    if not workspace.is_dir():
        print(
            f"[go-unbounded-alloc-noprogress-screen] ERR workspace not a "
            f"directory: {workspace}",
            file=sys.stderr,
        )
        return 2

    rows = run(workspace, list(args.root))

    payload = {
        "schema": SCHEMA_VERSION,
        "capability": "G9",
        "detector": DETECTOR,
        "workspace": str(workspace),
        "advisory_first": True,
        "verdict_all": "needs-fuzz",
        "row_count": len(rows),
        "primitive_counts": _count_by(rows, lambda r: r.primitive),
        "kind_counts": _count_by(rows, lambda r: r.kind),
        "boundary_source_counts": _count_by(rows, lambda r: r.boundary_source),
        "rows": [asdict(r) for r in rows],
    }

    # Advisory sidecar for the hunt corpus (foldable by auto-coverage-closer's
    # GO advisory list): JSONL, one needs-fuzz / no-auto-credit row per
    # hypothesis, under <ws>/.auditooor/ so the pipeline consumer can ingest it.
    sidecar_dir = workspace / ".auditooor"
    sidecar_dir.mkdir(parents=True, exist_ok=True)
    sidecar = sidecar_dir / "go_unbounded_alloc_noprogress_hypotheses.jsonl"
    with open(sidecar, "w", encoding="utf-8") as sf:
        for r in rows:
            sf.write(json.dumps({
                **asdict(r), "capability": "G9",
                "verdict": "needs-fuzz", "advisory": True, "auto_credit": False,
            }) + "\n")

    if args.print_json:
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    else:
        out_dir = workspace / "critical_hunt" / "unbounded_alloc_noprogress"
        out_dir.mkdir(parents=True, exist_ok=True)
        json_path = out_dir / "go_unbounded_alloc_noprogress_screen.json"
        json_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(
            f"[go-unbounded-alloc-noprogress-screen] wrote "
            f"{json_path.relative_to(workspace)} ({len(rows)} advisory row(s))",
            file=sys.stderr,
        )

    # Advisory-first: default NEVER fail-closes. --strict is an opt-in signal.
    if args.strict and rows:
        print(
            f"[go-unbounded-alloc-noprogress-screen] STRICT: {len(rows)} advisory row(s)",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
