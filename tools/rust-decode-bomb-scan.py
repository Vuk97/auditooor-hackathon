#!/usr/bin/env python3
"""Rust decode-bomb scanner — Wave 6 Worker G (PR #556 Priority 4 task 2).

Wave 5 Worker O surfaced a single concrete decode-bomb in the Base Azul tree:
``snap::raw::Decoder::decompress_vec(&msg.data)`` in
``crates/consensus/gossip/src/config.rs:106`` and four more in the Engine API
``rpc-types-engine/src/envelope.rs`` (decode_v1..v4). Each takes attacker-
controlled gossip / engine_newPayload bytes and lets the snappy crate allocate
without a per-call output cap — a 4 GiB blowup is a one-byte CRC-OK header
away.

This scanner generalises that finding. It walks ``*.rs`` under the workspace's
declared Rust project roots (falling back to ``external/base/crates/``) and emits a row
per attacker-controlled-length allocation site. Pattern types map back to the
PR #556 brief:

  * ``snappy_decompress_vec``           — Wave 5 finding shape.
  * ``unbounded_decompress``            — zstd / brotli / lz4 / miniz_oxide
                                          decompress without a per-call limit.
  * ``vec_with_capacity_attacker_len``  — ``Vec::with_capacity(<expr>)`` where
                                          ``<expr>`` mentions a length token
                                          read from the wire (``self.<x>_count``,
                                          ``self.<x>_len``, ``payload.<x>``,
                                          ``decoded.<x>``, fn parameter).
  * ``vec_macro_attacker_len``          — ``vec![0; <expr>]`` and
                                          ``vec![<expr>; <attacker-len>]``.
  * ``ssz_rlp_unbounded_len``           — SSZ / RLP / JSON decoders that read
                                          a ``len`` / ``length`` / ``size``
                                          field from input and feed it to a
                                          downstream allocation in the same
                                          function body without a clamp.
  * ``read_then_with_capacity``         — ``let n = reader.read_u32/u64()``
                                          (or equivalents) followed by
                                          ``Vec::with_capacity(n)`` /
                                          ``vec![<expr>; n]`` / ``read_exact``
                                          on a buffer of size ``n``.

Default-to-kill: every row carries ``length_cap_present`` and
``length_cap_value_or_const_name``. When the function body has a
``MAX_*`` constant comparison, an ``ensure!``, or an ``if … > N`` clamp
on the same length token, the scanner records the cap and recommends
re-checking the cap value rather than landing the row blindly.

The scanner emits behavior candidates only. It never makes Snappy or any
decode-bomb row Critical/direct-submit-ready. For Snappy gossip decode,
mempool impact is not applicable; the row stays NOT_SUBMIT_READY /
kill_or_reframe unless a later evidence record proves an exact listed Base
Azul impact, such as measured >=30% node resource consumption under realistic
non-bruteforce conditions or a quantified node-shutdown threshold.

CLI shape matches ``tools/base-rpc-crash-probe.py`` and
``tools/base-block-delay-probe.py`` (``--workspace``, ``--strict``,
``--print-json`` / ``--out-json -``). Stdlib-only, offline-safe.

Examples
--------

::

    python3 tools/rust-decode-bomb-scan.py \\
        --workspace ~/audits/base-azul --print-json | jq '.rows | length'
    python3 tools/rust-decode-bomb-scan.py \\
        --workspace ~/audits/base-azul --strict
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
except ModuleNotFoundError:  # pragma: no cover - direct import from test loaders.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from lib.project_source_roots import rust_crate_scan_roots


SCHEMA_VERSION = "auditooor.rust_decode_bomb_scan.v1"

DEFAULT_SCAN_ROOTS = (
    "external/base/crates",
    "crates",
)

# Test code we never flag. Same conventions as base-rpc-crash-probe.
TEST_PATH_TOKENS = (
    "/tests/",
    "/test_",
    "/testing/",
    "_tests.rs",
    "/benches/",
    "/examples/",
    "/fuzz/",
)

# ---------------------------------------------------------------------------
# Pattern compilation
# ---------------------------------------------------------------------------

# `decoder.decompress_vec(<arg>)` from snap / snappy crates.
SNAPPY_DECOMPRESS_RE = re.compile(
    r"\b(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)?decompress_vec\s*\(",
)

# Other decompression entrypoints that return owned Vec<u8>. We list crates
# that are commonly mis-used without an output cap. Each match is reported
# with the matched callee for transparency.
UNBOUNDED_DECOMPRESS_RE = re.compile(
    r"\b("
    r"zstd::(?:bulk::)?decode_all|"
    r"zstd::stream::decode_all|"
    r"zstd::decode_all|"
    r"brotli::Decompressor::new|"
    r"brotli_decompressor::Decompressor::new|"
    r"lz4(?:_flex)?::block::decompress|"
    r"miniz_oxide::inflate::decompress_to_vec(?!_(?:zlib_)?with_limit)\b|"
    r"flate2::read::(?:GzDecoder|ZlibDecoder|DeflateDecoder)::new"
    r")\s*\(",
)

# Vec::with_capacity(<expr>)
VEC_WITH_CAPACITY_RE = re.compile(
    r"\bVec\s*::\s*with_capacity\s*\(\s*([^)]*)\)",
)

# vec![<value>; <count>]
VEC_MACRO_REPEAT_RE = re.compile(
    r"\bvec!\s*\[\s*([^;\]]+);\s*([^\]]+)\]",
)

# `let <name> = <expr>.read_u32()` / `read_u64()` / `read_uXX()` / `read_varint()`
READ_LEN_RE = re.compile(
    r"\blet\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?::\s*[A-Za-z0-9_<>:\s]+)?\s*=\s*"
    r"[^;]*?\.read_(?:u(?:8|16|32|64|128)|varint|leb128|compact_size)\s*\(",
)

# SSZ / RLP / JSON length-driven allocation hints.
SSZ_RLP_LEN_RE = re.compile(
    r"\blet\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?::\s*[A-Za-z0-9_<>:\s]+)?\s*=\s*"
    r"[^;]*?\.(?:read_length|read_list_length|read_size|"
    r"decode_offset|sszde::decode_length)\s*\(",
)

# Function declaration boundary. We only care about the start position so we
# can attribute each hit to its enclosing function — the scanner runs per-
# file and we don't need a full body parse.
FN_START_RE = re.compile(
    r"\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?"
    r"fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*",
)

# Attribute or `///` doc comment lines belonging to the fn (used for
# attacker-input-source heuristics).
ATTR_LINE_RE = re.compile(r"^\s*(?:#\[[^\]]+\]|///[^\n]*|//[^\n]*)$")

# ---------------------------------------------------------------------------
# Heuristics: what makes a length "attacker-derived"?
# ---------------------------------------------------------------------------

# Tokens that strongly hint the value comes from the wire / decoded payload.
ATTACKER_LEN_TOKENS = (
    "_count",
    "_len",
    "_length",
    "_size",
    "declared_len",
    "declared_length",
    "declared_size",
    "payload_len",
    "msg_len",
    "data_len",
    "header.len",
    "tx_count",
    "block_count",
    "n_blocks",
    "n_txs",
    "num_blocks",
    "num_txs",
    "num_bytes",
    "self.size",
    "self.len",
    "header.size",
    "decoded.size",
    "decoded.len",
)

# Length-cap evidence: function body mentions one of these on the same token.
LEN_CAP_TOKENS = (
    "MAX_",
    "MAXIMUM_",
    "_MAX",
    "max_capacity",
    "max_length",
    "max_size",
    "max_count",
    "saturating_min",
    "min(",
    ".min(",
    "ensure!",
    "saturating_sub",
)

# Constants that resemble a cap declaration we can name in the row.
CONST_CAP_RE = re.compile(
    r"\b(?:const|static)\s+([A-Z][A-Z0-9_]*(?:MAX|LIMIT|CAP|SIZE)[A-Z0-9_]*)\s*:",
)

# Attacker-input-source heuristics by file path.
INPUT_SOURCE_BY_PATH = (
    ("/gossip/", "gossip"),
    ("/p2p/", "p2p"),
    ("/network/", "p2p"),
    ("/rpc-types-engine/", "engine_api"),
    ("/engine/", "engine_api"),
    ("/rpc/", "rpc"),
    ("/blob", "blob"),
    ("/consensus/protocol/", "untrusted_l1"),
    ("/consensus/derive/", "untrusted_l1"),
    ("/batcher/", "untrusted_l1"),
    ("/batch/", "untrusted_l1"),
    ("/tee/", "tee_attestation"),
    ("/proof/", "untrusted_proof"),
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class BombRow:
    file: str
    line: int
    pattern_id: str
    function: str
    attacker_input_source: str
    length_cap_present: bool
    length_cap_value_or_const_name: str
    snippet: str
    recommendation: str
    evidence_class: str = "detector_hit"
    candidate_kind: str = "detector_harness_task_candidate"
    submission_posture: str = "NOT_SUBMIT_READY"
    selected_impact: str = ""
    severity: str = "none"
    impact_contract_required: bool = True
    impact_contract_id: str = ""
    harness_task: str = (
        "Create a bounded harness task only after an impact_contract selects "
        "one exact program impact sentence and required evidence class."
    )
    kill_or_reframe_rule: str = (
        "kill_or_reframe unless the follow-up proof demonstrates the exact "
        "selected program impact sentence; detector output alone is not "
        "severity evidence."
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


def _input_source(rel_path: str) -> str:
    for tok, src in INPUT_SOURCE_BY_PATH:
        if tok in "/" + rel_path:
            return src
    return "unknown"


def _strip_test_blocks(text: str) -> str:
    """Cheap removal of ``#[cfg(test)] mod tests { ... }`` blocks."""
    out_parts: list[str] = []
    i = 0
    while True:
        m = re.search(r"#\[cfg\(test\)\]\s*\n?\s*mod\s+\w+\s*\{", text[i:])
        if not m:
            out_parts.append(text[i:])
            break
        out_parts.append(text[i:i + m.start()])
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


def _enclosing_function(text: str, offset: int) -> str:
    """Return the name of the fn that contains ``offset``, or ``"<module>"``."""
    last = "<module>"
    for m in FN_START_RE.finditer(text, 0, offset):
        last = m.group(1)
    return last


def _enclosing_function_body(text: str, offset: int) -> str:
    """Return the body text of the enclosing fn, or the whole file as a fallback."""
    fn_starts = [m.start() for m in FN_START_RE.finditer(text, 0, offset)]
    if not fn_starts:
        return text
    fn_start = fn_starts[-1]
    # Find the body brace.
    n = len(text)
    i = fn_start
    depth = 0
    square_depth = 0
    body_start = -1
    while i < n:
        c = text[i]
        if c == "[":
            square_depth += 1
        elif c == "]" and square_depth > 0:
            square_depth -= 1
        if c == ";" and depth == 0 and square_depth == 0 and body_start == -1:
            return text[fn_start:i]
        if c == "{":
            if body_start == -1:
                body_start = i
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0 and body_start != -1:
                return text[body_start:i + 1]
        i += 1
    return text[fn_start:]


def _is_attacker_len_expr(expr: str, fn_body: str) -> tuple[bool, str | None]:
    """Heuristic: is ``expr`` likely an attacker-controlled length?

    Returns (is_attacker, named_token). ``named_token`` is the substring of
    ``expr`` that triggered the heuristic, useful for the row's snippet.
    """
    e = expr.strip()
    if not e:
        return False, None

    # Constant integer literal — clean.
    if re.fullmatch(r"\d+(?:_\d+)*\s*(?:as\s+\w+)?", e):
        return False, None

    # Const-style identifier (ALL_CAPS) — likely a static cap.
    if re.fullmatch(r"[A-Z][A-Z0-9_]*(?:\s*as\s+\w+)?", e):
        return False, None
    # ``Self::CONST`` / ``Module::CONST``.
    if re.fullmatch(
        r"(?:[A-Za-z_][A-Za-z0-9_]*::)+[A-Z][A-Z0-9_]*(?:\s*as\s+\w+)?",
        e,
    ):
        return False, None
    # ``T::CONST + N``-style additive expressions of all-caps tokens.
    if re.fullmatch(r"[A-Z0-9_:\s+\-*/]+(?:as\s+\w+)?", e):
        return False, None

    # Strong attacker tokens.
    for tok in ATTACKER_LEN_TOKENS:
        if tok in e:
            return True, tok

    # `<param>.len()` where <param> is a fn param mentioned in the body via
    # the same identifier — heuristic only, but Wave 5 PoC fits this pattern.
    m_paren = re.search(r"\b([a-z_][A-Za-z0-9_]*)\.len\s*\(\s*\)", e)
    if m_paren:
        name = m_paren.group(1)
        # A fn parameter typically appears in the signature: ``name:``.
        if re.search(rf"\b{re.escape(name)}\s*:", fn_body[:200]):
            return True, f"{name}.len()"

    # Bare identifier that also appears as a fn parameter.
    if re.fullmatch(r"[a-z_][a-zA-Z0-9_]*(?:\s+as\s+\w+)?", e):
        bare = re.split(r"\s+as\s+", e)[0]
        if re.search(rf"\b{re.escape(bare)}\s*:\s*(?:u(?:8|16|32|64|128)|usize|U256)\b", fn_body[:400]):
            return True, bare

    return False, None


def _len_cap_present(fn_body: str, length_token: str) -> tuple[bool, str]:
    """Look for a clamp / cap on ``length_token`` inside the fn body.

    Returns (cap_present, name_or_value_string).
    """
    if not length_token:
        return False, ""

    # 1) ``if <token> > MAX_X { ... return ... }``
    m = re.search(
        rf"if\s+{re.escape(length_token)}\s*>\s*([A-Z][A-Z0-9_]*|\d+(?:_\d+)*)\b",
        fn_body,
    )
    if m:
        return True, m.group(1)

    # 2) ``ensure!(<token> <= MAX_X)``
    m = re.search(
        rf"ensure!\s*\([^)]*{re.escape(length_token)}[^)]*?(?:<=|<|<\.)\s*"
        rf"([A-Z][A-Z0-9_]*|\d+(?:_\d+)*)",
        fn_body,
    )
    if m:
        return True, m.group(1)

    # 3) ``<token>.min(MAX_X)``
    m = re.search(
        rf"{re.escape(length_token)}\.min\s*\(\s*([A-Z][A-Z0-9_]*|\d+(?:_\d+)*)\s*\)",
        fn_body,
    )
    if m:
        return True, m.group(1)

    # 4) Module-scope MAX_* const NAMED in the same body line as the token.
    for line in fn_body.splitlines():
        if length_token in line:
            mc = re.search(r"\b(MAX_[A-Z0-9_]+|[A-Z][A-Z0-9_]*_(?:MAX|LIMIT|CAP|SIZE))\b", line)
            if mc:
                return True, mc.group(1)

    # 5) Known suppressors: `with_limit` decode helpers, `decode_to_vec_with_limit`,
    #    `take(N)` adapters chained on a reader.
    if re.search(r"\.take\s*\(\s*[A-Z0-9_]+\s*\)", fn_body):
        m = re.search(r"\.take\s*\(\s*([A-Z][A-Z0-9_]*)\s*\)", fn_body)
        if m:
            return True, m.group(1)
    if "with_limit" in fn_body:
        return True, "decompress_to_vec_with_limit"

    return False, ""


def _snappy_predecode_cap_present(fn_body: str) -> tuple[bool, str]:
    """Detect the 498fb52f-style Snappy pre-decompression length cap.

    The Base fix calls ``snap::raw::decompress_len`` first, compares the
    declared decoded length to a MAX_* cap, and only then calls
    ``decompress_vec``. This is the important regression property; checking
    for a cap on the literal token ``decompress_vec`` misses the fixed shape.
    """
    if "decompress_len" not in fn_body:
        return False, ""
    if "decompress_vec" not in fn_body:
        return False, ""
    cap_names = re.findall(
        r"\b([A-Z][A-Z0-9_]*(?:MAX|LIMIT|CAP|SIZE)[A-Z0-9_]*|"
        r"MAX_[A-Z0-9_]+)\b",
        fn_body,
    )
    if not cap_names:
        return False, ""
    if re.search(
        r"(?:decompressed|decoded|declared)[A-Za-z0-9_]*\s*>\s*"
        r"([A-Z][A-Z0-9_]*(?:MAX|LIMIT|CAP|SIZE)[A-Z0-9_]*|MAX_[A-Z0-9_]+)",
        fn_body,
    ):
        return True, re.search(
            r"(?:decompressed|decoded|declared)[A-Za-z0-9_]*\s*>\s*"
            r"([A-Z][A-Z0-9_]*(?:MAX|LIMIT|CAP|SIZE)[A-Z0-9_]*|MAX_[A-Z0-9_]+)",
            fn_body,
        ).group(1)
    return True, cap_names[0]


def _snippet(text: str, offset: int, span: int = 100) -> str:
    line_start = text.rfind("\n", 0, offset) + 1
    line_end = text.find("\n", offset)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end].strip()[:160]


# ---------------------------------------------------------------------------
# Per-file analysis
# ---------------------------------------------------------------------------


def scan_file(file_path: Path, workspace: Path) -> list[BombRow]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    cleaned = _strip_test_blocks(text)
    rel = _safe_rel(file_path, workspace)
    src = _input_source(rel)
    rows: list[BombRow] = []

    # 1) snappy decompress_vec.
    for m in SNAPPY_DECOMPRESS_RE.finditer(cleaned):
        line = _line_for_offset(cleaned, m.start())
        fn_name = _enclosing_function(cleaned, m.start())
        body = _enclosing_function_body(cleaned, m.start())
        cap, cap_val = _len_cap_present(body, "decompress_vec")
        if not cap:
            cap, cap_val = _snappy_predecode_cap_present(body)
        # Snappy callers almost never wrap with_limit — flag unconditionally.
        rec = (
            "Replace with snap::raw::Decoder::decompress_len() + size check, "
            "or wrap in a hard MAX_DECOMPRESSED_SIZE clamp before allocating."
        )
        rows.append(
            BombRow(
                file=rel,
                line=line,
                pattern_id="snappy_decompress_vec",
                function=fn_name,
                attacker_input_source=src,
                length_cap_present=cap,
                length_cap_value_or_const_name=cap_val,
                snippet=_snippet(cleaned, m.start()),
                recommendation=rec,
                harness_task=(
                    "For Snappy/gossip decode, first create an impact_contract "
                    "for an exact Base Azul impact row. Only then build a "
                    "realistic non-bruteforce resource or node-shutdown harness "
                    "with measured thresholds."
                ),
                kill_or_reframe_rule=(
                    "NOT_SUBMIT_READY/kill_or_reframe unless evidence proves "
                    "an exact listed impact, e.g. measured >=30% node resource "
                    "consumption under realistic non-bruteforce conditions or "
                    "a quantified node-shutdown threshold."
                ),
                not_applicable_impacts=["mempool impact"],
            )
        )

    # 2) other unbounded decompression entrypoints.
    for m in UNBOUNDED_DECOMPRESS_RE.finditer(cleaned):
        line = _line_for_offset(cleaned, m.start())
        fn_name = _enclosing_function(cleaned, m.start())
        body = _enclosing_function_body(cleaned, m.start())
        # decompress_to_vec_with_limit / .take(N) are accepted as caps.
        cap, cap_val = _len_cap_present(body, m.group(1).split("::")[-1])
        if "with_limit" in m.group(0):
            cap, cap_val = True, "with_limit"
        rec = (
            "Use the *_with_limit variant (miniz_oxide / flate2) or wrap the "
            "reader in .take(MAX_BYTES) before decoding."
        )
        rows.append(
            BombRow(
                file=rel,
                line=line,
                pattern_id="unbounded_decompress",
                function=fn_name,
                attacker_input_source=src,
                length_cap_present=cap,
                length_cap_value_or_const_name=cap_val,
                snippet=_snippet(cleaned, m.start()),
                recommendation=rec,
            )
        )

    # 3) Vec::with_capacity(<attacker-derived-len>).
    for m in VEC_WITH_CAPACITY_RE.finditer(cleaned):
        expr = m.group(1).strip()
        line = _line_for_offset(cleaned, m.start())
        fn_name = _enclosing_function(cleaned, m.start())
        body = _enclosing_function_body(cleaned, m.start())
        is_atk, tok = _is_attacker_len_expr(expr, body)
        if not is_atk:
            continue
        cap, cap_val = _len_cap_present(body, tok or "")
        rec = (
            "Clamp the length against a MAX_* constant before "
            "Vec::with_capacity (or use try_with_capacity + bound)."
        )
        rows.append(
            BombRow(
                file=rel,
                line=line,
                pattern_id="vec_with_capacity_attacker_len",
                function=fn_name,
                attacker_input_source=src,
                length_cap_present=cap,
                length_cap_value_or_const_name=cap_val,
                snippet=_snippet(cleaned, m.start()),
                recommendation=rec,
            )
        )

    # 4) vec![<expr>; <count>] macro.
    for m in VEC_MACRO_REPEAT_RE.finditer(cleaned):
        count_expr = m.group(2).strip()
        line = _line_for_offset(cleaned, m.start())
        fn_name = _enclosing_function(cleaned, m.start())
        body = _enclosing_function_body(cleaned, m.start())
        is_atk, tok = _is_attacker_len_expr(count_expr, body)
        if not is_atk:
            continue
        cap, cap_val = _len_cap_present(body, tok or "")
        rec = (
            "Clamp the repeat-count against a MAX_* constant before "
            "vec![..; n], or convert to Vec::with_capacity + push loop."
        )
        rows.append(
            BombRow(
                file=rel,
                line=line,
                pattern_id="vec_macro_attacker_len",
                function=fn_name,
                attacker_input_source=src,
                length_cap_present=cap,
                length_cap_value_or_const_name=cap_val,
                snippet=_snippet(cleaned, m.start()),
                recommendation=rec,
            )
        )

    # 5) read_uXX -> Vec::with_capacity / vec![..; n] / read_exact pattern.
    for read_match in READ_LEN_RE.finditer(cleaned):
        name = read_match.group(1)
        # Look forward up to 600 bytes for an alloc that uses `name`.
        window = cleaned[read_match.end():read_match.end() + 600]
        used = False
        for sub_re in (
            re.compile(rf"\bVec\s*::\s*with_capacity\s*\(\s*{re.escape(name)}\b"),
            re.compile(rf"\bvec!\s*\[\s*[^;\]]+;\s*{re.escape(name)}\b"),
            re.compile(rf"\bread_exact\s*\(\s*&mut\s+\w+\[\s*\.\.\s*{re.escape(name)}\s*\]"),
        ):
            mw = sub_re.search(window)
            if mw:
                used = True
                line = _line_for_offset(cleaned, read_match.start())
                fn_name = _enclosing_function(cleaned, read_match.start())
                body = _enclosing_function_body(cleaned, read_match.start())
                cap, cap_val = _len_cap_present(body, name)
                rec = (
                    f"Clamp `{name}` against a MAX_* constant immediately "
                    "after the read; otherwise a 4-byte attacker u32 can "
                    "request a 4 GiB allocation."
                )
                rows.append(
                    BombRow(
                        file=rel,
                        line=line,
                        pattern_id="read_then_with_capacity",
                        function=fn_name,
                        attacker_input_source=src,
                        length_cap_present=cap,
                        length_cap_value_or_const_name=cap_val,
                        snippet=_snippet(cleaned, read_match.start()),
                        recommendation=rec,
                    )
                )
                break
        del used

    # 6) SSZ / RLP read_length / decode_offset hints.
    for m in SSZ_RLP_LEN_RE.finditer(cleaned):
        name = m.group(1)
        line = _line_for_offset(cleaned, m.start())
        fn_name = _enclosing_function(cleaned, m.start())
        body = _enclosing_function_body(cleaned, m.start())
        # Only fire if the identifier is reused for an allocation downstream.
        window = cleaned[m.end():m.end() + 600]
        if not re.search(
            rf"(Vec\s*::\s*with_capacity\s*\(\s*{re.escape(name)}\b|"
            rf"vec!\s*\[\s*[^;\]]+;\s*{re.escape(name)}\b)",
            window,
        ):
            continue
        cap, cap_val = _len_cap_present(body, name)
        rows.append(
            BombRow(
                file=rel,
                line=line,
                pattern_id="ssz_rlp_unbounded_len",
                function=fn_name,
                attacker_input_source=src,
                length_cap_present=cap,
                length_cap_value_or_const_name=cap_val,
                snippet=_snippet(cleaned, m.start()),
                recommendation=(
                    "SSZ/RLP-declared length must be checked against the SSZ "
                    "list-length cap before allocating downstream Vec."
                ),
            )
        )

    return rows


# ---------------------------------------------------------------------------
# File enumeration
# ---------------------------------------------------------------------------


def enumerate_files(workspace: Path, extra_roots: list[str]) -> list[Path]:
    seen: set[Path] = set()
    out: list[Path] = []
    roots = rust_crate_scan_roots(workspace, DEFAULT_SCAN_ROOTS) + list(extra_roots)
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


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def render_markdown(rows: list[BombRow]) -> str:
    out: list[str] = []
    out.append("# Rust decode-bomb scan")
    out.append("")
    out.append(f"_Schema: `{SCHEMA_VERSION}`_")
    out.append("")
    counts: dict[str, int] = {}
    for r in rows:
        counts[r.pattern_id] = counts.get(r.pattern_id, 0) + 1
    out.append("## Pattern counts")
    out.append("")
    if counts:
        for k, v in sorted(counts.items()):
            out.append(f"- `{k}`: {v}")
    else:
        out.append("- _(no rows)_")
    out.append("")
    out.append("## Rows")
    out.append("")
    if not rows:
        out.append("_No decode-bomb candidates found._")
        return "\n".join(out) + "\n"
    out.append(
        "All rows are detector/harness-task candidates only. They are "
        "`NOT_SUBMIT_READY` until an `impact_contract` selects and proves one "
        "exact program impact sentence."
    )
    out.append("")
    out.append("| file:line | pattern_id | fn | source | posture | severity | cap? | cap_value | recommendation |")
    out.append("|---|---|---|---|---|---|---|---|---|")
    for r in rows:
        out.append(
            "| `{f}:{l}` | `{p}` | `{fn}` | `{src}` | `{posture}` | `{sev}` | `{cap}` | `{cv}` | {rec} |".format(
                f=r.file,
                l=r.line,
                p=r.pattern_id,
                fn=r.function,
                src=r.attacker_input_source,
                posture=r.submission_posture,
                sev=r.severity,
                cap="yes" if r.length_cap_present else "no",
                cv=r.length_cap_value_or_const_name or "_(none)_",
                rec=r.recommendation,
            )
        )
    out.append("")
    return "\n".join(out) + "\n"


def write_outputs(workspace: Path, rows: list[BombRow]) -> tuple[Path, Path]:
    out_dir = workspace / "critical_hunt" / "decode_bomb"
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "rust_decode_bomb_scan.json"
    md_path = out_dir / "rust_decode_bomb_scan.md"
    payload = {
        "schema": SCHEMA_VERSION,
        "workspace": str(workspace),
        "pattern_counts": _count_by(rows, lambda r: r.pattern_id),
        "rows": [asdict(r) for r in rows],
    }
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(rows), encoding="utf-8")
    return json_path, md_path


def _count_by(rows: list[BombRow], key) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        k = key(r)
        out[k] = out.get(k, 0) + 1
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def run(workspace: Path, extra_roots: list[str]) -> list[BombRow]:
    files = enumerate_files(workspace, extra_roots)
    rows: list[BombRow] = []
    for f in files:
        rows.extend(scan_file(f, workspace))
    rows.sort(key=lambda r: (r.file, r.line, r.pattern_id))
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rust-decode-bomb-scan.py",
        description=(
            "PR #556 Wave 6 Worker G — decode-bomb scanner. Walks Rust "
            "workspace roots and emits attacker-controlled-length allocation "
            "rows generalising the Wave 5 snappy decompress_vec finding."
        ),
    )
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument(
        "--root",
        action="append",
        default=[],
        help=(
            "Extra workspace-relative path to walk. May be passed multiple "
            "times. Defaults to declared project_source_roots Rust crates "
            "(for example external/base-rc28-clean/crates), then historical "
            "external/base/crates and crates when no declaration exists."
        ),
    )
    parser.add_argument(
        "--print-json",
        action="store_true",
        help="Print the JSON payload to stdout instead of writing files.",
    )
    parser.add_argument(
        "--out-json",
        default="",
        help="Set to '-' to print JSON to stdout (alias for --print-json).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "Exit 1 when at least one row was emitted with "
            "length_cap_present=False on a public attacker-input source "
            "(gossip, p2p, engine_api, rpc, blob, untrusted_l1)."
        ),
    )
    args = parser.parse_args(argv)

    workspace: Path = args.workspace
    if not workspace.is_dir():
        print(
            f"[rust-decode-bomb-scan] ERR workspace not a directory: {workspace}",
            file=sys.stderr,
        )
        return 2

    rows = run(workspace, list(args.root))

    print_json = args.print_json or args.out_json == "-"

    if print_json:
        sys.stdout.write(
            json.dumps(
                {
                    "schema": SCHEMA_VERSION,
                    "rows": [asdict(r) for r in rows],
                    "pattern_counts": _count_by(rows, lambda r: r.pattern_id),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
    else:
        json_path, md_path = write_outputs(workspace, rows)
        print(
            f"[rust-decode-bomb-scan] wrote {json_path.relative_to(workspace)}",
            file=sys.stderr,
        )
        print(
            f"[rust-decode-bomb-scan] wrote {md_path.relative_to(workspace)}",
            file=sys.stderr,
        )
        if rows:
            counts_str = ", ".join(
                f"{k}={v}"
                for k, v in sorted(_count_by(rows, lambda r: r.pattern_id).items())
            )
            print(
                f"[rust-decode-bomb-scan] {len(rows)} rows: {counts_str}",
                file=sys.stderr,
            )
        else:
            print("[rust-decode-bomb-scan] no rows emitted", file=sys.stderr)

    if args.strict:
        public_sources = {"gossip", "p2p", "engine_api", "rpc", "blob", "untrusted_l1"}
        unfixed = [
            r for r in rows
            if not r.length_cap_present and r.attacker_input_source in public_sources
        ]
        if unfixed:
            print(
                f"[rust-decode-bomb-scan] STRICT FAIL: {len(unfixed)} "
                f"uncapped public-source row(s) remain",
                file=sys.stderr,
            )
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
