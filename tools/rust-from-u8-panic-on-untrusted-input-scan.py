#!/usr/bin/env python3
"""Rust From<u8>/TryFrom<u8> panic-on-unknown-discriminant scanner — Wave H-3B.

Detects ``impl From<TYPE> for ENUM`` blocks that contain a wildcard arm with
``panic!`` or ``unreachable!``, where the impl is reachable from a
network-facing / untrusted-input decode path.

Bug shape (patch 4839aea3): ``BatchType::from(u8)`` panicked on any byte
value outside the two known discriminants. A remote gossip peer can send a
batch envelope with type byte 0x02..0xFF, triggering a process crash before
any authentication check.  The fix changed ``From<u8>`` to ``TryFrom<u8>``
returning a ``BatchDecodingError``.

Pattern IDs
-----------
* ``from_u8_panic_wildcard``  — ``impl From<uN> for TYPE`` with ``_ => panic!``.
* ``from_u8_unreachable_wildcard`` — same but with ``_ => unreachable!``.

Default-to-kill discipline: every row carries ``candidate_status``.  Rows
require an ``impact_contract`` before submission.

CLI: ``--workspace``, ``--strict``, ``--print-json``.
``STRICT=1`` / ``--strict`` exits 1 when any row is emitted.

Examples
--------

::

    python3 tools/rust-from-u8-panic-on-untrusted-input-scan.py \\
        --workspace ~/audits/base-azul --print-json | jq '.rows | length'
    python3 tools/rust-from-u8-panic-on-untrusted-input-scan.py \\
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


SCHEMA_VERSION = "auditooor.rust_from_u8_panic_on_untrusted_input_scan.v1"

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

# Match the start of a From<uN> impl block.
# Foot-gun #3 rule: \b not ^.
FROM_U8_IMPL_RE = re.compile(
    r"\bimpl\s+From\s*<\s*u(?:8|16|32|64|128|size)\s*>\s+for\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{",
)

# Wildcard arm with panic! or unreachable!
PANIC_WILDCARD_RE = re.compile(
    r"\b_\s*=>\s*(?:panic|unreachable)\s*!",
)

# Function declaration boundary (for enclosing fn detection).
FN_START_RE = re.compile(
    r"\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*",
)

# Input-source heuristics by path token.
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
class PanicRow:
    file: str
    line: int
    pattern_id: str
    containing_fn: str
    enum_name: str
    input_source: str
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


def _extract_impl_body(text: str, impl_start: int) -> str:
    """Extract the body of the impl block starting at impl_start."""
    n = len(text)
    i = impl_start
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
    return text[impl_start:]


def _snippet(text: str, offset: int) -> str:
    line_start = text.rfind("\n", 0, offset) + 1
    line_end = text.find("\n", offset)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end].strip()[:160]


# ---------------------------------------------------------------------------
# Per-file analysis
# ---------------------------------------------------------------------------


def scan_file(file_path: Path, workspace: Path) -> list[PanicRow]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    cleaned = _strip_test_blocks(text)
    rel = _safe_rel(file_path, workspace)
    src = _input_source(rel)
    rows: list[PanicRow] = []

    for impl_match in FROM_U8_IMPL_RE.finditer(cleaned):
        enum_name = impl_match.group(1)
        body = _extract_impl_body(cleaned, impl_match.start())
        # Look for wildcard arm with panic! or unreachable!
        for pat_match in PANIC_WILDCARD_RE.finditer(body):
            full_snippet = pat_match.group(0)
            pattern_id = (
                "from_u8_panic_wildcard"
                if "panic" in full_snippet
                else "from_u8_unreachable_wildcard"
            )
            # offset in the original text
            abs_offset = impl_match.start() + pat_match.start()
            line = _line_for_offset(cleaned, abs_offset)
            fn_name = _enclosing_function(cleaned, abs_offset)
            rows.append(
                PanicRow(
                    file=rel,
                    line=line,
                    pattern_id=pattern_id,
                    containing_fn=fn_name,
                    enum_name=enum_name,
                    input_source=src,
                    snippet=_snippet(cleaned, abs_offset),
                    confidence="high" if src != "unknown" else "medium",
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


def _count_by(rows: list[PanicRow], key) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        k = key(r)
        out[k] = out.get(k, 0) + 1
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def run(workspace: Path, extra_roots: list[str]) -> list[PanicRow]:
    files = enumerate_files(workspace, extra_roots)
    rows: list[PanicRow] = []
    for f in files:
        rows.extend(scan_file(f, workspace))
    rows.sort(key=lambda r: (r.file, r.line, r.pattern_id))
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rust-from-u8-panic-on-untrusted-input-scan.py",
        description=(
            "Wave H-3B — From<u8> panic-on-unknown-discriminant scanner. "
            "Finds impl From<uN> blocks with wildcard panic!/unreachable! arms "
            "in network-facing Rust decode paths. Bug shape: patch 4839aea3."
        ),
    )
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument(
        "--scan-root",
        action="append",
        default=[],
        dest="scan_roots",
        help="Extra workspace-relative path to walk. May be passed multiple times.",
    )
    parser.add_argument(
        "--print-json",
        action="store_true",
        help="Print the JSON payload to stdout.",
    )
    parser.add_argument(
        "--out-json",
        default="",
        help="Set to '-' to print JSON to stdout (alias for --print-json).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 when at least one row is emitted.",
    )
    args = parser.parse_args(argv)

    workspace: Path = args.workspace
    if not workspace.is_dir():
        print(
            f"[rust-from-u8-panic-on-untrusted-input-scan] ERR workspace not a directory: {workspace}",
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
            f"[rust-from-u8-panic-on-untrusted-input-scan] {len(rows)} row(s)",
            file=sys.stderr,
        )

    if args.strict and rows:
        print(
            f"[rust-from-u8-panic-on-untrusted-input-scan] STRICT FAIL: {len(rows)} row(s)",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
