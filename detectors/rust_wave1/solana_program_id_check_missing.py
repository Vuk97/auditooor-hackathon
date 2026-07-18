"""
solana_program_id_check_missing.py

Detects missing program-id / owner validation on accounts in Solana programs.

When processing accounts in a Solana program (native, not Anchor), each
account's `owner` field MUST be checked against the expected program ID before
reading or mutating its data.  Missing this check allows an attacker to pass
an account owned by a malicious program that returns crafted data.

In Anchor, the `Account<'info, T>` type performs owner checks automatically.
The risk exists in native programs using raw `AccountInfo` where the check
is manual.

Bug class: HIGH (arbitrary data injection via account owner spoofing)
Platform:  Solana (native + Anchor raw AccountInfo usage)
Empirical anchor: OtterSec absence-of-oracle-account-validation class;
                  absence-of-verification-of-issuance-account-index.yaml.

Algorithm (regex):
1. Find functions that accept `AccountInfo` parameters (native Solana pattern).
2. Within the body, check if any `account.owner` or
   `account.key == &expected_program_id` comparison is performed before
   `account.data.borrow()` or `account.try_borrow_data()`.
3. If data is borrowed without an owner check, flag the function.
4. Safe patterns: `check_program_id(account, program_id)`, `account.owner == program_id`,
   Anchor's `Account<'info, T>` (implicit owner check), `spl_token::check_program_account`.
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
from typing import Optional

DETECTOR_ID = "rust_wave1.solana_program_id_check_missing"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive"}

# Pattern for functions accepting AccountInfo parameters (native Solana)
_FN_HEADER_RE = re.compile(
    r"^[ \t]*"
    r"(?:pub(?:\s*\([^)]*\))?\s+)?"
    r"(?:unsafe\s+|const\s+|async\s+)*"
    r"fn\s+(?P<name>[A-Za-z_]\w*)"
    r"(?:\s*<[^(>]*>)?\s*\(",
    re.MULTILINE,
)

# Accessing account data without owner check
_DATA_BORROW_RE = re.compile(
    r"\b(try_borrow_data|borrow_data|data\.borrow|from_account_info)\s*\("
)

# Owner validation patterns
_OWNER_CHECK_RE = re.compile(
    r"\b(\.owner\s*[=!]=|check_program_id\s*\(|check_program_account\s*\(|"
    r"spl_token::check_program_account|"
    r"if\s+\w+\.owner\s*!=|"
    r"require_eq!\s*\(\s*\w+\.owner)",
)

# AccountInfo parameter presence - matches AccountInfo<'info> or &[AccountInfo]
_ACCOUNT_INFO_PARAM_RE = re.compile(r"AccountInfo\s*(?:<|\])")

_TEST_RE = re.compile(r"#\[\s*(?:cfg\s*\(\s*test|test)\s*\]")

# Skip Anchor programs (Account<'info, T> performs implicit checks)
_ANCHOR_MARKER_RE = re.compile(r"#\[\s*derive\s*\(\s*Accounts\s*\)\s*\]")

# Strip line comments for false-positive reduction
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")


def _extract_fn_body(content: str, fn_start: int) -> tuple[Optional[str], int]:
    depth = 0
    body_start: Optional[int] = None
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
                return content[body_start:i], content[:fn_start].count("\n") + 1
        i += 1
    return None, 0


def scan_file(filepath: str) -> list[dict]:
    try:
        with open(filepath, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
        return []

    # Must have AccountInfo usage
    if "AccountInfo" not in content:
        return []

    # Must be Solana (native or Anchor)
    if "solana_program" not in content and "anchor_lang" not in content:
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

        surrounding = content[max(0, fn_offset - 200):fn_offset]
        if _TEST_RE.search(surrounding):
            continue

        # Get function signature (params)
        sig_end = content.find("{", fn_offset)
        if sig_end == -1:
            continue
        signature = content[fn_offset:sig_end]

        # Must have AccountInfo in params (native pattern)
        if not _ACCOUNT_INFO_PARAM_RE.search(signature):
            continue

        body, _ = _extract_fn_body(content, fn_offset)
        if body is None:
            continue

        data_match = _DATA_BORROW_RE.search(body)
        if data_match is None:
            continue

        # Check if owner is validated before data borrow
        # Strip line comments to avoid false negatives from comment text
        before_borrow = _LINE_COMMENT_RE.sub("", body[:data_match.start()])
        if _OWNER_CHECK_RE.search(before_borrow):
            continue

        borrow_line = fn_line + body[:data_match.start()].count("\n")

        h: dict = {
            "detector_id": DETECTOR_ID,
            "file": filepath,
            "line": fn_line,
            "fn_name": fn_name_val,
            "borrow_line": borrow_line,
            "severity": "HIGH",
            "message": (
                f"fn `{fn_name_val}`: `AccountInfo` data borrowed at line {borrow_line} "
                f"without prior `account.owner` check - attacker can pass an account "
                f"owned by a malicious program containing crafted data."
            ),
        }
        if _crate_name and _crate_name != "unknown":
            h["crate_name"] = _crate_name
        if _mod_prefix:
            h["module_path"] = _mod_prefix
        hits.append(h)

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
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    for fpath, line, msg in scan(root):
        print(f"{fpath}:{line}:{DETECTOR_ID}:{msg}")
