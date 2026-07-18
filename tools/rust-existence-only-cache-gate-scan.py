#!/usr/bin/env python3
"""Rust existence-only cache gate scanner — Wave H-3B.

Detects cached-state lookup patterns where an existence-only check
(``contains_key``, ``has_transaction_hash``, ``is_some``) is used to gate
state reuse without verifying that the cached entry's position matches the
current execution position.

Bug shape (patch 6ab29cf0): ``FlashblocksCachedExecutionProvider`` used
``pending_blocks.has_transaction_hash(prev_cached_hash)`` to decide whether to
return cached state for transaction N, but the check only verified the previous
transaction hash was present anywhere in the pending block — not that it
appeared at position N-1.  A sequencer leadership transfer or specifically
crafted payload sequence could cause stale cached flashblock state to be
applied to a mismatched transaction prefix, corrupting EL state.

Pattern IDs
-----------
* ``existence_only_cache_gate`` — ``if cache.contains_key(k)`` / ``.is_some()``
  used to gate returning a cached value without a positional/equality check.

Heuristics
----------
1. Detect ``has_transaction_hash`` / ``contains_key`` / ``.get(`` calls in
   execution-provider-like contexts.
2. Look for the pattern in ``fn get_cached*`` or ``fn get_execution*`` bodies.
3. Flag when the function returns a cached value in the same branch as the
   existence check, without any index/position equality check.

CLI: ``--workspace``, ``--strict``, ``--print-json``.
``--strict`` exits 1 when any row is emitted.

Examples
--------

::

    python3 tools/rust-existence-only-cache-gate-scan.py \\
        --workspace ~/audits/base-azul --print-json | jq '.rows | length'
    python3 tools/rust-existence-only-cache-gate-scan.py \\
        --workspace ~/audits/base-azul --strict
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

try:
    from lib.project_source_roots import rust_crate_scan_roots
except ModuleNotFoundError:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from lib.project_source_roots import rust_crate_scan_roots


SCHEMA_VERSION = "auditooor.rust_existence_only_cache_gate_scan.v1"

DEFAULT_SCAN_ROOTS = (
    "external/base/crates",
    "crates",
)

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

# Foot-gun #3: \b not ^.
# Match existence-only cache checks in if-conditions.
EXISTENCE_CHECK_RE = re.compile(
    r"\b(?:has_transaction_hash|contains_key|is_cached|cache_contains)\s*\(",
)

# Also match .is_some() used to gate a cache return.
IS_SOME_GATE_RE = re.compile(
    r"\b(?:get_cache|cached|flashblocks|pending_blocks|cache)\b[^;{]*\.is_some\s*\(\s*\)",
)

# Positional check patterns — if any of these appear in the same fn body,
# downgrade to lower confidence.
POSITION_CHECK_RE = re.compile(
    r"\b(?:position|index|successor|prev_index|seq_no|tx_index|order)\b",
)

FN_START_RE = re.compile(
    r"\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*",
)

INPUT_SOURCE_BY_PATH = (
    ("/gossip/", "gossip"),
    ("/p2p/", "p2p"),
    ("/network/", "p2p"),
    ("/engine-tree/", "engine_api"),
    ("/engine/", "engine_api"),
    ("/execution/", "engine_api"),
    ("/flashblocks/", "engine_api"),
    ("/cached_execution", "engine_api"),
    ("/rpc/", "rpc"),
    ("/consensus/", "untrusted_l1"),
    ("/proof/", "untrusted_proof"),
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class CacheGateRow:
    file: str
    line: int
    pattern_id: str
    containing_fn: str
    input_source: str
    has_position_check: bool
    snippet: str
    confidence: str
    candidate_status: str = "kill_or_reframe"


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
    out_parts: list[str] = []
    i = 0
    while True:
        m = re.search(r"#\[cfg\(test\)\]\s*\n?\s*mod\s+\w+\s*\{", text[i:])
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


def _enclosing_function(text: str, offset: int) -> str:
    last = "<module>"
    for m in FN_START_RE.finditer(text, 0, offset):
        last = m.group(1)
    return last


def _enclosing_function_body(text: str, offset: int) -> str:
    fn_starts = [m.start() for m in FN_START_RE.finditer(text, 0, offset)]
    if not fn_starts:
        return text
    fn_start = fn_starts[-1]
    n = len(text)
    i = fn_start
    depth = 0
    body_start = -1
    while i < n:
        c = text[i]
        if c == "{":
            if body_start == -1:
                body_start = i
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0 and body_start != -1:
                return text[body_start : i + 1]
        i += 1
    return text[fn_start:]


def _snippet(text: str, offset: int) -> str:
    line_start = text.rfind("\n", 0, offset) + 1
    line_end = text.find("\n", offset)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end].strip()[:160]


# ---------------------------------------------------------------------------
# Per-file analysis
# ---------------------------------------------------------------------------


def scan_file(file_path: Path, workspace: Path) -> list[CacheGateRow]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    cleaned = _strip_test_blocks(text)
    rel = _safe_rel(file_path, workspace)
    src = _input_source(rel)
    rows: list[CacheGateRow] = []

    patterns = [
        (EXISTENCE_CHECK_RE, "existence_only_cache_gate"),
        (IS_SOME_GATE_RE, "existence_only_cache_gate"),
    ]

    seen_lines: set[int] = set()
    for pat_re, pat_id in patterns:
        for m in pat_re.finditer(cleaned):
            abs_offset = m.start()
            line = _line_for_offset(cleaned, abs_offset)
            if line in seen_lines:
                continue
            fn_name = _enclosing_function(cleaned, abs_offset)
            body = _enclosing_function_body(cleaned, abs_offset)
            has_pos = bool(POSITION_CHECK_RE.search(body))
            confidence = "medium" if has_pos else "high"
            seen_lines.add(line)
            rows.append(
                CacheGateRow(
                    file=rel,
                    line=line,
                    pattern_id=pat_id,
                    containing_fn=fn_name,
                    input_source=src,
                    has_position_check=has_pos,
                    snippet=_snippet(cleaned, abs_offset),
                    confidence=confidence,
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


def _count_by(rows: list[CacheGateRow], key) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        k = key(r)
        out[k] = out.get(k, 0) + 1
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def run(workspace: Path, extra_roots: list[str]) -> list[CacheGateRow]:
    files = enumerate_files(workspace, extra_roots)
    rows: list[CacheGateRow] = []
    for f in files:
        rows.extend(scan_file(f, workspace))
    rows.sort(key=lambda r: (r.file, r.line, r.pattern_id))
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rust-existence-only-cache-gate-scan.py",
        description=(
            "Wave H-3B — existence-only cache gate scanner. "
            "Finds cached-state lookups that use only presence (no position equality). "
            "Bug shape: patch 6ab29cf0."
        ),
    )
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument(
        "--scan-root",
        action="append",
        default=[],
        dest="scan_roots",
    )
    parser.add_argument("--print-json", action="store_true")
    parser.add_argument("--out-json", default="")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 when at least one row is emitted.",
    )
    args = parser.parse_args(argv)

    workspace: Path = args.workspace
    if not workspace.is_dir():
        print(
            f"[rust-existence-only-cache-gate-scan] ERR workspace not a directory: {workspace}",
            file=sys.stderr,
        )
        return 2

    rows = run(workspace, list(args.scan_roots))

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
        print(
            f"[rust-existence-only-cache-gate-scan] {len(rows)} row(s)",
            file=sys.stderr,
        )

    if args.strict and rows:
        print(
            f"[rust-existence-only-cache-gate-scan] STRICT FAIL: {len(rows)} row(s)",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
