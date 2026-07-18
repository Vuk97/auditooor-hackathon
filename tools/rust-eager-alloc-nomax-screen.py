#!/usr/bin/env python3
"""RU8 - Rust eager-allocation no-max-bound enforcement screen (GENERAL).

North-star framing (w8mv5mpcw - "A TRUSTED ENFORCEMENT is bypassable or its
private invariant is unsound"):

  * DELEGATED-AND-TRUSTED enforcement: an eager pre-allocation primitive
    (``Vec::with_capacity``, ``vec![_; n]``, ``<T>::with_capacity``,
    ``Vec::reserve``/``reserve_exact``, ``iter::repeat(..).take(n).collect``)
    reserves memory proportional to a length value ``n``.  The allocation site
    DELEGATES to (TRUSTS) an upstream producer to have bounded ``n``.
  * PRIVATE INVARIANT: ``n <= MAX`` for some sane cap, established BEFORE the
    reservation and DOMINATING it on every path.
  * ATTACK ON THE INVARIANT: when ``n`` is derived from a decode / deserialize /
    wire-read boundary (an EXTERNAL producer) and NO cap-enforcement point
    dominates the allocation, an attacker sets ``n`` to ``u32::MAX`` / a huge
    ``u64`` and forces an eager multi-GiB reservation *before any payload bytes
    are even read* - pre-auth memory amplification / OOM.

This is a GENERAL invariant/enforcement CLASS, not a bug shape:
  - It enumerates the WHOLE eager-alloc primitive family (not one crate/one
    channel) and asks a single enforcement-completeness question of each site:
    "does a MAX-cap guard dominate this length-proportional reservation?"
  - The IMPACT is left open (verdict=needs-fuzz); nothing here decides a tier.

Deduplication vs pre-existing tools (tool-duplication preflight, do-NOT #10):
  - ``rust-host-length-cast-unbounded-alloc-scan.py`` is SHAPE-specific: it
    matches host/oracle/hint/preimage-CHANNEL reads with an explicit ``as usize``
    cast.  RU8 does not require a channel path token nor an ``as usize`` cast and
    treats *any* decode-boundary length uniformly.
  - ``rust-decode-bomb-scan.py`` is SHAPE-specific to decompression crates
    (snappy/zstd/brotli) and named attacker-len token heuristics.  RU8 is about
    the ENFORCEMENT-COMPLETENESS invariant over eager reservation primitives,
    independent of the downstream consumer.
  RU8 rows are ADVISORY (verdict=needs-fuzz), never auto-credited, never
  fail-closing; they are a superset lens keyed on "no dominating cap", so the
  two shape tools remain the higher-precision confirmers.

Fleet (mutation-verify corpus, read-only): monero / near /
near-intents-contracts / leansig / base-azul.

Advisory-first contract:
  - The screen emits a row ONLY for an eager alloc whose length is
    decode-boundary-derived AND has NO dominating cap (i.e. it FIRES when the
    guard is absent, is SILENT on guarded/benign sites).
  - Every row carries ``verdict="needs-fuzz"`` and ``auto_credit=False``.  The
    process NEVER exits non-zero on findings unless ``--strict`` is explicitly
    passed (opt-in CI signal); default is advisory (exit 0).

CLI:
    python3 tools/rust-eager-alloc-nomax-screen.py --workspace ~/audits/near --print-json
    python3 tools/rust-eager-alloc-nomax-screen.py --workspace ~/audits/near   # writes sidecar
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

try:
    from lib.project_source_roots import rust_crate_scan_roots
except ModuleNotFoundError:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from lib.project_source_roots import rust_crate_scan_roots


SCHEMA_VERSION = "auditooor.rust_eager_alloc_nomax_screen.v1"

DEFAULT_SCAN_ROOTS = (
    "src",
    "crates",
    "external/base/crates",
)

TEST_PATH_TOKENS = (
    "/tests/",
    "/test_",
    "/testing/",
    "_tests.rs",
    "/benches/",
    "/examples/",
    "/fuzz/",
    "/bench/",
    # Non-production test-support / fuzzing contracts and dev/estimation tooling
    # (NOT the audited runtime): flagging these fabricates fleet FPs.
    "/near-test-contracts/",
    "/contract-for-fuzzing-rs/",
    "/runtime-params-estimator/",
    "/state-viewer/",
)

# ---------------------------------------------------------------------------
# Eager-allocation primitive family (GENERAL - the whole class, not one shape).
# Each regex captures the length EXPRESSION in group "len".
# ``try_reserve`` / ``try_reserve_exact`` are deliberately EXCLUDED: they are
# the fallible (safe) forms and are the recommended remediation.
# ---------------------------------------------------------------------------
ALLOC_PRIMITIVES: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    (
        "vec_with_capacity",
        re.compile(r"\bVec\s*::\s*with_capacity\s*\(\s*(?P<len>[^;)]+?)\s*\)"),
    ),
    (
        "typed_with_capacity",
        re.compile(
            r"\b(?:HashMap|HashSet|BTreeMap|BTreeSet|String|VecDeque|BytesMut|"
            r"SmallVec|IndexMap|IndexSet|DashMap|DashSet)\s*(?:::\s*<[^>]*>)?"
            r"\s*::\s*with_capacity\s*\(\s*(?P<len>[^;)]+?)\s*\)"
        ),
    ),
    (
        "vec_macro_fill",
        # vec![<val>; <len>]  -> length is the SECOND arg after the ';'
        re.compile(r"\bvec!\s*\[\s*[^;\]]+?;\s*(?P<len>[^;\]]+?)\s*\]"),
    ),
    (
        "reserve",
        re.compile(r"\.\s*reserve(?:_exact)?\s*\(\s*(?P<len>[^;)]+?)\s*\)"),
    ),
    (
        "repeat_take_collect",
        # iter::repeat(x).take(<len>).collect
        re.compile(r"\.\s*take\s*\(\s*(?P<len>[^;)]+?)\s*\)\s*\.\s*collect\b"),
    ),
)

# A length EXPRESSION is decode/wire-boundary derived when it mentions a token
# that was produced by one of these boundary reads (assignment shape) ...
BOUNDARY_ASSIGN_RE = re.compile(
    r"\blet\s+(?:mut\s+)?(?P<tok>[a-z_][A-Za-z0-9_]*)\b[^=;\n]*=\s*(?P<rhs>[^;]+);",
)
BOUNDARY_RHS_TOKENS = (
    "from_be_bytes",
    "from_le_bytes",
    "from_ne_bytes",
    "read_u16",
    "read_u32",
    "read_u64",
    "read_u128",
    "read_uint",
    "read_varint",
    "read_var_int",
    "read_leb128",
    "read_length",
    "read_len",
    "read_compact",
    "decode_length",
    "get_uint",
    "get_u32",
    "get_u64",
)
# ... or names a fn PARAMETER in a decode-context fn whose name looks like a
# length (a scalar received from the wire, e.g. reed_solomon_decode(encoded_length)).
LEN_PARAM_NAME_RE = re.compile(
    r"(?:^|[^a-z])(?:len|length|size|count|num|amount|capacity|n|nbytes|"
    r"num_[a-z_]+|[a-z_]+_len|[a-z_]+_length|[a-z_]+_size|[a-z_]+_count)$"
)

# Decode-context signals in the enclosing fn (name or body) that make an
# integer PARAMETER trustworthy-as-wire-length.
DECODE_CTX_NAME_RE = re.compile(
    r"(?:decode|deserialize|from_bytes|from_slice|from_reader|parse|unpack|"
    r"read_|try_from_slice|de_|_de\b|unmarshal|decompress)",
    re.IGNORECASE,
)
# STRONG decode signals - unambiguous enough to substring-match the fn body.
DECODE_CTX_BODY_TOKENS = (
    "from_be_bytes",
    "from_le_bytes",
    "read_exact",
    "BorshDeserialize",
    "try_from_slice",
    "Deserialize",
    "deserialize",
    "Decode",
    ".decode(",
    "from_reader",
    "Cursor",
)
# WEAK decode signals - ``bytes`` / ``buf`` / ``&[u8]`` are too short to
# substring-match safely: a bare ``in`` test flags unrelated field names such as
# ``cumulative_da_bytes_used`` (a fully-materialized u64 accumulator, NOT a wire
# read).  Require them to appear as whole words / a real slice type so a field
# name that merely *contains* the letters ``bytes`` does not fabricate a
# decode-context.  (Fleet FP: base-azul execution.rs ExecutionInfo::with_capacity.)
DECODE_CTX_BODY_WORD_RE = re.compile(r"(?:\bbytes\b|\bbuf\b|&\s*\[\s*u8\s*\])")

# Field-access length: foo.<name>_len / foo.num_x / foo.<name>_count read as the
# alloc size. Only trusted when the enclosing fn is a decode context (else a
# struct already fully materialized in memory - not a pre-read boundary).
FIELD_LEN_RE = re.compile(
    r"\b[a-z_][A-Za-z0-9_]*\.(?:[a-z_]+_len|[a-z_]+_length|[a-z_]+_size|"
    r"[a-z_]+_count|num_[a-z_]+)\b"
)

# Materialized-collection lengths - these are bounded by an ALREADY-allocated
# object, so they are NOT a pre-read amplification boundary. Exclude.
MATERIALIZED_LEN_RE = re.compile(
    r"\.\s*(?:len|count|capacity|size_hint)\s*\(\s*\)"
)
# Compile-time constant length (ALL_CAPS ident, or a numeric literal only).
ALLCAPS_CONST_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
NUMERIC_ONLY_RE = re.compile(r"^[0-9_]+(?:\s*[*+/-]\s*[0-9_]+)*$")

# Dominating cap-enforcement indicators (searched in the fn body BEFORE alloc,
# and required to CO-OCCUR with the length token within a 160-char window).
#
# NOTE: tokens here must NOT be substrings of the eager-alloc primitives
# themselves (e.g. "_cap"/"capacity"/"cap(" all appear inside `with_capacity`
# and would make every reservation self-cancel).  Structural comparison guards
# (`tok > ...`, `tok.min()`, `tok.clamp()`) are handled separately below.
CAP_GUARD_TOKENS = (
    "MAX_",
    "_MAX",
    "MAXIMUM",
    "MAX_LEN",
    "LIMIT",
    "_LIMIT",
    "ensure!",
    "bail!",
    "require!",
    "assert!",
    "debug_assert!",
    "cmp::min",
    "cmp::max",
    "try_reserve",
    # Clamp idioms: safe here because ``fn_body_before`` is sliced at the alloc,
    # so a post-alloc ``.min()`` (e.g. reed_solomon's copy loop) cannot leak in,
    # and these are not substrings of the eager-alloc primitives.
    ".min(",
    ".clamp(",
)

FN_START_RE = re.compile(
    r"\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?(?:const\s+)?(?:unsafe\s+)?"
    r"(?:extern\s+\"[^\"]*\"\s+)?fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?:<[^>]*>)?\s*\((?P<params>[^{;]*)",
    re.DOTALL,
)

# A single length-token candidate in an expression: a lowercase identifier
# (optionally a field chain), possibly with `as usize`.
TOKEN_RE = re.compile(r"[a-z_][A-Za-z0-9_.]*")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class EagerAllocRow:
    file: str
    line: int
    primitive: str
    function: str
    length_expr: str
    length_token: str
    boundary_source: str  # how the length reaches a wire/decode boundary
    invariant: str = (
        "capacity(n) <= MAX established and dominating the reservation"
    )
    enforcement_status: str = "unbounded"  # this screen only emits unbounded
    dominating_cap_found: bool = False
    snippet: str = ""
    verdict: str = "needs-fuzz"
    auto_credit: bool = False
    advisory: bool = True
    recommendation: str = (
        "Enforce an upper bound on the decode-boundary length BEFORE the eager "
        "reservation (if n > MAX { return Err(..) }), or use the fallible "
        "try_reserve / read-then-grow pattern so a hostile length cannot force "
        "a pre-payload multi-GiB allocation."
    )
    harness_task: str = (
        "Fuzz: feed the decoder a length prefix at u32::MAX / large u64 and "
        "assert the callee rejects it (Err) and does not eagerly reserve or OOM."
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


def _strip_test_blocks(text: str) -> str:
    out_parts: list[str] = []
    i = 0
    while True:
        m = re.search(r"#\[cfg\(test\)\]\s*\n?\s*(?:pub\s+)?mod\s+\w+\s*\{", text[i:])
        if not m:
            out_parts.append(text[i:])
            break
        out_parts.append(text[i : i + m.start()])
        depth = 0
        j = i + m.end() - 1
        n = len(text)
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
        i = j
    return "".join(out_parts)


def _enclosing_fn(text: str, offset: int) -> tuple[str, str, str, int]:
    """Return (fn_name, params, fn_full_text, fn_start_offset).

    ``fn_full_text`` is the enclosing fn text (decl..closing brace or ; );
    ``fn_start_offset`` is that text's absolute start in ``text`` so callers can
    slice the region that DOMINATES a downstream allocation.
    """
    last_start = -1
    last_name = "<module>"
    last_params = ""
    for m in FN_START_RE.finditer(text, 0, offset + 1):
        last_start = m.start()
        last_name = m.group("name")
        last_params = m.group("params") or ""
    if last_start < 0:
        return "<module>", "", text, 0
    # Find body extent from the first '{' after the param list.
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


def _snippet(text: str, offset: int) -> str:
    line_start = text.rfind("\n", 0, offset) + 1
    line_end = text.find("\n", offset)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end].strip()[:200]


def _param_names(params: str) -> set[str]:
    names: set[str] = set()
    for part in params.split(","):
        part = part.strip()
        if not part or part.startswith("&") and ":" not in part:
            continue
        # `name: Type` or `mut name: Type`
        m = re.match(r"(?:mut\s+)?([a-z_][A-Za-z0-9_]*)\s*:", part)
        if m:
            names.add(m.group(1))
    return names


def is_decode_context(fn_name: str, fn_body: str) -> bool:
    if DECODE_CTX_NAME_RE.search(fn_name):
        return True
    for tok in DECODE_CTX_BODY_TOKENS:
        if tok in fn_body:
            return True
    if DECODE_CTX_BODY_WORD_RE.search(fn_body):
        return True
    return False


def _is_with_capacity_ctor(fn_name: str) -> bool:
    """A ``with_capacity`` constructor takes a CALLER-supplied capacity.

    ``fn with_capacity(capacity: usize) -> Self`` mirrors the std
    ``Vec::with_capacity`` contract: the size is chosen by the caller, not
    decoded from the wire.  Such a parameter is never a decode boundary even if
    the body happens to trip a weak decode signal.  (Fleet FP: base-azul
    ExecutionInfo::with_capacity.)
    """
    return fn_name == "with_capacity" or fn_name.endswith("_with_capacity")


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

    tokens = [t for t in TOKEN_RE.findall(expr) if t not in {"as", "usize", "u8", "u16", "u32", "u64", "u128", "isize"}]
    if not tokens:
        return None, ""

    decode_ctx = is_decode_context(fn_name, fn_body)
    params = _param_names(fn_params)

    for tok in tokens:
        base = tok.split(".")[0]

        # (a) token assigned from a wire/decode boundary read in the fn body.
        for m in BOUNDARY_ASSIGN_RE.finditer(fn_body):
            if m.group("tok") != base:
                continue
            rhs = m.group("rhs")
            if any(bt in rhs for bt in BOUNDARY_RHS_TOKENS):
                return "wire_read", tok

        # (b) token IS a fn parameter that looks like a length, in a decode ctx.
        if base in params and decode_ctx and LEN_PARAM_NAME_RE.search(base):
            # A ``with_capacity(capacity)`` constructor is caller-supplied, not
            # wire-derived - the size is chosen by the calling code.
            if _is_with_capacity_ctor(fn_name):
                continue
            return "decode_param", tok

        # (c) field-access length (foo.<x>_len / foo.num_x) in a decode ctx.
        #     Exclude METHOD calls (foo.num_clients()) - a method return is not
        #     a decoded wire field, it is a computed/materialized value.
        if "." in tok and decode_ctx and FIELD_LEN_RE.search(tok):
            if (tok + "(") in expr or (tok + " (") in expr:
                continue
            return "decode_field", tok

    return None, ""


def has_dominating_cap(length_token: str, fn_body_before: str) -> tuple[bool, str]:
    """CORE PREDICATE (half 2): is there a MAX-cap enforcement that dominates?

    ``fn_body_before`` is the fn text from its declaration up to (and including)
    the allocation line.  A cap must (i) be one of the known cap idioms and
    (ii) co-occur near the length token OR be a structural guard idiom.
    Neutralizing this predicate (forcing it to return True) must silence every
    positive row - see the non-vacuity test.
    """
    base = length_token.split(".")[0]

    # Structural comparison-guard: `if <tok> > ...` / `>= ` / `<tok>.min(`
    if re.search(rf"\b{re.escape(base)}\s*(?:>|>=)\s*", fn_body_before):
        return True, "compare_guard"
    if re.search(rf"\b{re.escape(base)}\s*\.\s*min\s*\(", fn_body_before):
        return True, "token.min()"
    if re.search(rf"\b{re.escape(base)}\s*\.\s*clamp\s*\(", fn_body_before):
        return True, "token.clamp()"

    # Idiom-based cap co-occurring within +/-160 chars of the token.
    for tok in CAP_GUARD_TOKENS:
        idx = fn_body_before.find(tok)
        while idx != -1:
            window = fn_body_before[max(0, idx - 160) : idx + 160]
            if base in window:
                return True, tok
            idx = fn_body_before.find(tok, idx + 1)
    return False, ""


# RHS of a field-cap comparison: an ALL-ish-CAPS cap constant (contains MAX /
# LIMIT / MAXIMUM, possibly a `Type::CONST` path) or a plain numeric literal.
_FIELD_CAP_RHS_RE = re.compile(
    r"(?P<rhs>[A-Za-z_][A-Za-z0-9_]*(?:\s*::\s*[A-Za-z_][A-Za-z0-9_]*)*|[0-9][0-9_]*)"
)


def has_cross_fn_field_cap(field_token: str, file_text: str) -> bool:
    """CROSS-FUNCTION cap domination for a ``self.<field>`` decode length.

    A decoded struct field (e.g. ``self.total_block_tx_count``) is frequently
    range-checked in a DIFFERENT method of the same ``impl`` (the decode of the
    count itself, ``if self.field > MAX { return Err }``) than the method that
    later ``Vec::with_capacity(self.field)``.  ``has_dominating_cap`` is
    intraprocedural (its ``base`` is ``self``), so it cannot see that guard.

    Scan the WHOLE file for ``self.field >|>= <CAP>`` where ``<CAP>`` is a
    MAX/LIMIT constant or a numeric literal, and treat the field as bounded when
    such a guard exists anywhere in the file.  (Fleet FP: base-azul
    consensus/protocol/src/batch/transactions.rs + payload.rs.)
    """
    if "." not in field_token:
        return False
    esc = re.escape(field_token)
    for m in re.finditer(rf"{esc}\s*(?:>=|>)\s*", file_text):
        rhs_m = _FIELD_CAP_RHS_RE.match(file_text, m.end())
        if not rhs_m:
            continue
        rhs = rhs_m.group("rhs")
        upper = rhs.upper()
        if "MAX" in upper or "LIMIT" in upper or rhs[:1].isdigit():
            return True
    return False


# ---------------------------------------------------------------------------
# Per-file scanning
# ---------------------------------------------------------------------------


def scan_text(text: str, rel: str) -> list[EagerAllocRow]:
    cleaned = _strip_test_blocks(text)
    rows: list[EagerAllocRow] = []
    seen: set[tuple[int, str]] = set()

    for primitive, pat in ALLOC_PRIMITIVES:
        for m in pat.finditer(cleaned):
            length_expr = m.group("len").strip()
            if not length_expr:
                continue
            offset = m.start()
            fn_name, fn_params, fn_full, fn_start = _enclosing_fn(cleaned, offset)

            source, token = classify_boundary_source(
                length_expr, fn_name, fn_params, fn_full
            )
            if source is None:
                continue

            # Cap must DOMINATE: the guard region is the fn text from its
            # declaration up to (and including) the allocation line - NOT merely
            # the first mention of the length token (which is the signature).
            alloc_line_end = cleaned.find("\n", offset)
            if alloc_line_end == -1:
                alloc_line_end = len(cleaned)
            fn_body_before = cleaned[fn_start:alloc_line_end]

            capped, _cap_ind = has_dominating_cap(token, fn_body_before)
            # A ``self.<field>`` decode length is often capped in a DIFFERENT
            # method of the same impl (cross-fn); has_dominating_cap is
            # intraprocedural and cannot see it.  Scan the whole file.
            if not capped and source == "decode_field":
                capped = has_cross_fn_field_cap(token, cleaned)
            if capped:
                continue  # SILENT on guarded/benign sites.

            line = _line_for_offset(cleaned, offset)
            key = (line, primitive)
            if key in seen:
                continue
            seen.add(key)

            rows.append(
                EagerAllocRow(
                    file=rel,
                    line=line,
                    primitive=primitive,
                    function=fn_name,
                    length_expr=length_expr,
                    length_token=token,
                    boundary_source=source,
                    snippet=_snippet(cleaned, offset),
                )
            )
    return rows


def scan_file(file_path: Path, workspace: Path) -> list[EagerAllocRow]:
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
    roots = rust_crate_scan_roots(workspace, DEFAULT_SCAN_ROOTS) + list(extra_roots)
    if not roots:
        roots = ["."]
    for rel in roots:
        root = (workspace / rel).resolve()
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.rs")):
            spath = str(path)
            if any(tok in spath for tok in TEST_PATH_TOKENS):
                continue
            if path.name.endswith("_test.rs") or path.name.endswith("_tests.rs"):
                continue
            if path in seen:
                continue
            seen.add(path)
            out.append(path)
    return out


def _count_by(rows: list[EagerAllocRow], key) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        k = key(r)
        out[k] = out.get(k, 0) + 1
    return out


def run(workspace: Path, extra_roots: list[str]) -> list[EagerAllocRow]:
    files = enumerate_files(workspace, extra_roots)
    rows: list[EagerAllocRow] = []
    for f in files:
        rows.extend(scan_file(f, workspace))
    rows.sort(key=lambda r: (r.file, r.line, r.primitive))
    return rows


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rust-eager-alloc-nomax-screen.py",
        description=(
            "RU8 - GENERAL Rust eager-allocation no-max-bound enforcement screen. "
            "Advisory-first: flags eager reservations whose length is decode/wire "
            "boundary derived and has NO dominating MAX-cap guard (verdict=needs-fuzz)."
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
        help="Print the JSON payload to stdout instead of writing the sidecar.",
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
            f"[rust-eager-alloc-nomax-screen] ERR workspace not a directory: {workspace}",
            file=sys.stderr,
        )
        return 2

    rows = run(workspace, list(args.root))

    payload = {
        "schema": SCHEMA_VERSION,
        "capability": "RU8",
        "workspace": str(workspace),
        "advisory_first": True,
        "verdict_all": "needs-fuzz",
        "row_count": len(rows),
        "primitive_counts": _count_by(rows, lambda r: r.primitive),
        "boundary_source_counts": _count_by(rows, lambda r: r.boundary_source),
        "rows": [asdict(r) for r in rows],
    }

    # Advisory sidecar for the hunt corpus (folded by auto-coverage-closer's
    # RUST_ADVISORY list): JSONL, one needs-fuzz / no-auto-credit row per
    # hypothesis, under <ws>/.auditooor/ so the pipeline consumer can ingest it.
    _sidecar_dir = workspace / ".auditooor"
    _sidecar_dir.mkdir(parents=True, exist_ok=True)
    with open(_sidecar_dir / "rust_eager_alloc_nomax_hypotheses.jsonl", "w", encoding="utf-8") as _sf:
        for _r in rows:
            _sf.write(json.dumps({
                **asdict(_r), "capability": "RU8",
                "verdict": "needs-fuzz", "advisory": True, "auto_credit": False,
            }) + "\n")

    if args.print_json:
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    else:
        out_dir = workspace / "critical_hunt" / "eager_alloc_nomax"
        out_dir.mkdir(parents=True, exist_ok=True)
        json_path = out_dir / "rust_eager_alloc_nomax_screen.json"
        json_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(
            f"[rust-eager-alloc-nomax-screen] wrote {json_path.relative_to(workspace)} "
            f"({len(rows)} advisory row(s))",
            file=sys.stderr,
        )

    # Advisory-first: default NEVER fail-closes. --strict is an opt-in signal.
    if args.strict and rows:
        print(
            f"[rust-eager-alloc-nomax-screen] STRICT: {len(rows)} advisory row(s)",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
