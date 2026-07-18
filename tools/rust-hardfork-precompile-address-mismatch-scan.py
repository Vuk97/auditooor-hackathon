#!/usr/bin/env python3
"""Rust hardfork-precompile address mismatch scanner — Wave H-3B.

Detects cases where a hardfork-versioned precompile constant (e.g.,
``P256VERIFY_OSAKA``) is expected in a hardfork-specific setup path but the
wrong constant (e.g., pre-fork ``P256VERIFY``) is used instead.

Bug shape (patch 56381928): The zkVM precompile registry used
``secp256r1::P256VERIFY`` instead of ``secp256r1::P256VERIFY_OSAKA`` for the
Azul hardfork (Base V1), causing the zkVM to use the wrong secp256r1 precompile
address post-Azul activation.  Transactions using P256VERIFY_OSAKA would fail
in the zkVM prover while succeeding in the EL, producing invalid state root
proofs.

Pattern IDs
-----------
* ``hardfork_precompile_non_osaka_in_zkvm`` — ``P256VERIFY`` (non-OSAKA) found
  in a file that also references hardfork SpecId context (zkVM / precompile
  provider setup path).

Heuristics
----------
1. Find files that reference both a hardfork-specific spec arm (``BASE_V1``,
   ``OSAKA``, ``AZUL``) and ``P256VERIFY`` (non-OSAKA form).
2. In those files, flag each bare ``P256VERIFY`` token that is NOT immediately
   followed by ``_OSAKA`` (i.e., not ``P256VERIFY_OSAKA``).
3. In precompile provider setup functions (``get_precompiles``,
   ``new_with_spec``, ``set_spec``), raise confidence.

CLI: ``--workspace``, ``--strict``, ``--print-json``.
``--strict`` exits 1 when any row is emitted.

Examples
--------

::

    python3 tools/rust-hardfork-precompile-address-mismatch-scan.py \\
        --workspace ~/audits/base-azul --print-json | jq '.rows | length'
    python3 tools/rust-hardfork-precompile-address-mismatch-scan.py \\
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


SCHEMA_VERSION = "auditooor.rust_hardfork_precompile_address_mismatch_scan.v1"

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
# Match bare P256VERIFY that is NOT followed by _OSAKA (i.e. the old form).
# We use a negative lookahead to skip P256VERIFY_OSAKA.
P256VERIFY_BARE_RE = re.compile(r"\bP256VERIFY\b(?!_OSAKA)")

# Hardfork context markers — if any of these appear in the file the pre-fork
# precompile usage is suspicious.
HARDFORK_CONTEXT_RE = re.compile(
    r"\b(?:BASE_V1|OSAKA|AZUL|OpSpecId|SpecId)\b",
)

# Precompile-setup function names that raise confidence.
SETUP_FN_RE = re.compile(
    r"\bfn\s+(?:get_precompiles|new_with_spec|set_spec|build_precompiles|precompiles_for)\b",
)

FN_START_RE = re.compile(
    r"\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*",
)

INPUT_SOURCE_BY_PATH = (
    ("/succinct/", "untrusted_proof"),
    ("/proof/", "untrusted_proof"),
    ("/precompile", "untrusted_proof"),
    ("/zkvm", "untrusted_proof"),
    ("/fpvm", "untrusted_proof"),
    ("/evm/", "engine_api"),
    ("/execution/", "engine_api"),
    ("/engine/", "engine_api"),
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class PrecompileRow:
    file: str
    line: int
    pattern_id: str
    containing_fn: str
    input_source: str
    has_hardfork_context: bool
    in_setup_fn: bool
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


def _snippet(text: str, offset: int) -> str:
    line_start = text.rfind("\n", 0, offset) + 1
    line_end = text.find("\n", offset)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end].strip()[:160]


# ---------------------------------------------------------------------------
# Per-file analysis
# ---------------------------------------------------------------------------


def scan_file(file_path: Path, workspace: Path) -> list[PrecompileRow]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    cleaned = _strip_test_blocks(text)
    rel = _safe_rel(file_path, workspace)
    src = _input_source(rel)

    # Only scan files that have at least one hardfork context marker.
    has_hardfork_ctx = bool(HARDFORK_CONTEXT_RE.search(cleaned))
    if not has_hardfork_ctx:
        return []

    rows: list[PrecompileRow] = []
    has_setup = bool(SETUP_FN_RE.search(cleaned))

    for m in P256VERIFY_BARE_RE.finditer(cleaned):
        abs_offset = m.start()
        line = _line_for_offset(cleaned, abs_offset)
        fn_name = _enclosing_function(cleaned, abs_offset)
        # Determine if this occurrence is inside a setup function.
        in_setup = has_setup and bool(re.search(
            r"\bfn\s+(?:get_precompiles|new_with_spec|set_spec|build_precompiles|precompiles_for)\b",
            cleaned[:abs_offset],
        ))
        confidence = "high" if in_setup else ("medium" if has_hardfork_ctx else "low")
        rows.append(
            PrecompileRow(
                file=rel,
                line=line,
                pattern_id="hardfork_precompile_non_osaka_in_zkvm",
                containing_fn=fn_name,
                input_source=src,
                has_hardfork_context=has_hardfork_ctx,
                in_setup_fn=in_setup,
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


def _count_by(rows: list[PrecompileRow], key) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        k = key(r)
        out[k] = out.get(k, 0) + 1
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def run(workspace: Path, extra_roots: list[str]) -> list[PrecompileRow]:
    files = enumerate_files(workspace, extra_roots)
    rows: list[PrecompileRow] = []
    for f in files:
        rows.extend(scan_file(f, workspace))
    rows.sort(key=lambda r: (r.file, r.line, r.pattern_id))
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rust-hardfork-precompile-address-mismatch-scan.py",
        description=(
            "Wave H-3B — hardfork-versioned precompile address mismatch scanner. "
            "Finds P256VERIFY (non-OSAKA) used in hardfork-aware precompile setup. "
            "Bug shape: patch 56381928."
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
            f"[rust-hardfork-precompile-address-mismatch-scan] ERR workspace not a directory: {workspace}",
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
            f"[rust-hardfork-precompile-address-mismatch-scan] {len(rows)} row(s)",
            file=sys.stderr,
        )

    if args.strict and rows:
        print(
            f"[rust-hardfork-precompile-address-mismatch-scan] STRICT FAIL: {len(rows)} row(s)",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
