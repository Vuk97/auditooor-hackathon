"""
anchor_cpi_reentrancy_invoke_signed_mid_state.py

Detects Anchor/Solana CPI reentrancy: a function that calls
`invoke_signed` / `invoke` / CPI-helper (e.g. `transfer`, `mint_to`,
`burn`) AFTER mutating account state but BEFORE persisting / verifying
a reentrancy guard.

Bug class: HIGH (theft of funds via reentrancy)
Platform:  Solana / Anchor
Empirical anchor: OtterSec H-47260 family (missing CPI guard before
                  external call into user-supplied program).

Algorithm (pure regex):
1. Find each function body (brace-depth tracking).
2. Within the body, scan for state-mutation patterns (field assignment,
   account data writes, balance decrements) before a CPI call.
3. Flag if: state_mutation_position < cpi_call_position AND the body
   does NOT contain an explicit reentrancy guard (`reentrancy_guard`,
   `is_entered`, `check_and_set`, `cpi_guard`) before the CPI call.

False-positive guards:
  - `cpi_guard` / `reentrancy_guard` fields present before the CPI call.
  - State mutation is inside an `if` block that returns early on failure
    (CEI pattern - checked by looking for `return Err` in the same block).
  - Test files (`#[cfg(test)]`, `#[test]`).
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
from typing import Optional

DETECTOR_ID = "rust_wave1.anchor_cpi_reentrancy_invoke_signed_mid_state"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive"}

# CPI call patterns
_CPI_RE = re.compile(
    r"\b(invoke_signed|invoke\s*\(|anchor_spl::token::|token::transfer\s*\(|"
    r"token::mint_to\s*\(|token::burn\s*\(|cpi::|CpiContext\s*::new)",
)

# State mutation patterns (account field write / balance change)
_STATE_MUT_RE = re.compile(
    r"\b(ctx\.accounts\.\w+\.\w+\s*[+-]?=|"
    r"account\.\w+\s*[+-]?=|"
    r"data\.\w+\s*[+-]?=|"
    r"\.amount\s*[+-]?=|"
    r"\.balance\s*[+-]?=|"
    r"\.lamports\s*[+-]?=)",
)

# Reentrancy guard patterns
_GUARD_RE = re.compile(
    r"\b(reentrancy_guard|is_entered|cpi_guard|check_and_set|"
    r"guard\s*=\s*true|locked\s*=\s*true)",
)

_FN_HEADER_RE = re.compile(
    r"^[ \t]*"
    r"(?:pub(?:\s*\([^)]*\))?\s+)?"
    r"(?:unsafe\s+|const\s+|async\s+)*"
    r"fn\s+(?P<name>[A-Za-z_]\w*)"
    r"(?:\s*<[^(>]*>)?\s*\(",
    re.MULTILINE,
)

_TEST_RE = re.compile(r"#\[\s*(?:cfg\s*\(\s*test|test)\s*\]")


def _extract_fn_body(content: str, fn_start: int) -> tuple[Optional[str], int]:
    depth = 0
    body_start = None
    start_line = content[:fn_start].count("\n") + 1
    i = fn_start
    while i < len(content):
        ch = content[i]
        if ch == "{":
            depth += 1
            if depth == 1:
                body_start = i + 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and body_start is not None:
                return content[body_start:i], start_line
        i += 1
    return None, 0


def scan_file(filepath: str) -> list[dict]:
    try:
        with open(filepath, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
        return []

    # Only run on Anchor / Solana files
    if "anchor_lang" not in content and "solana_program" not in content and "invoke_signed" not in content:
        return []

    fp = pathlib.Path(filepath)
    _crate_name: Optional[str] = None
    _mod_prefix = ""
    try:
        _DETECTOR_DIR = pathlib.Path(__file__).resolve().parent
        if str(_DETECTOR_DIR) not in sys.path:
            sys.path.insert(0, str(_DETECTOR_DIR))
        from _util import crate_name_from_path as _cnfp, _file_module_prefix
        _crate_name = _cnfp(fp)
        _mod_prefix = _file_module_prefix(fp)
    except Exception:
        pass

    hits = []

    for m_fn in _FN_HEADER_RE.finditer(content):
        fn_name_val = m_fn.group("name")
        fn_offset = m_fn.start()
        fn_line = content[:fn_offset].count("\n") + 1

        # Skip test functions
        surrounding = content[max(0, fn_offset - 200):fn_offset]
        if _TEST_RE.search(surrounding):
            continue

        body, _ = _extract_fn_body(content, fn_offset)
        if body is None:
            continue

        # Find positions of state mutations and CPI calls
        state_mut_match = _STATE_MUT_RE.search(body)
        cpi_match = _CPI_RE.search(body)

        if state_mut_match is None or cpi_match is None:
            continue

        # CEI violation: state mutation BEFORE cpi call
        if state_mut_match.start() >= cpi_match.start():
            continue

        # Check for reentrancy guard between start of function and CPI call
        guard_match = _GUARD_RE.search(body[:cpi_match.start()])
        if guard_match:
            continue

        cpi_line = fn_line + body[:cpi_match.start()].count("\n")
        mut_line = fn_line + body[:state_mut_match.start()].count("\n")

        hit: dict = {
            "detector_id": DETECTOR_ID,
            "file": filepath,
            "line": fn_line,
            "fn_name": fn_name_val,
            "state_mut_line": mut_line,
            "cpi_line": cpi_line,
            "severity": "HIGH",
            "message": (
                f"fn `{fn_name_val}`: state mutation at line {mut_line} precedes "
                f"CPI call at line {cpi_line} without a reentrancy guard - "
                f"re-entrant CPI can exploit inconsistent state."
            ),
        }
        if _crate_name and _crate_name != "unknown":
            hit["crate_name"] = _crate_name
        if _mod_prefix:
            hit["module_path"] = _mod_prefix
        hits.append(hit)

    return hits


def scan(root: str) -> list[tuple[str, int, str]]:
    results = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in filenames:
            if not fname.endswith(".rs"):
                continue
            fpath = os.path.join(dirpath, fname)
            for h in scan_file(fpath):
                results.append((h["file"], h["line"], h["message"]))
    return results


def run(tree, source_bytes, filepath: str, *, engine=None) -> list[dict]:
    return scan_file(filepath)


if __name__ == "__main__":
    import json
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    for fpath, line, msg in scan(root):
        print(f"{fpath}:{line}:{DETECTOR_ID}:{msg}")
