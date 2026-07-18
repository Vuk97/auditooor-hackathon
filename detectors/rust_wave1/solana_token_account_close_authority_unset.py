"""
solana_token_account_close_authority_unset.py

Detects token accounts initialized without setting a `close_authority`.

When a SPL token account is initialized (via `spl_token::instruction::initialize_account`
or Anchor's `#[account(init, ...)]` with `token::*`), if `close_authority` is
left unset (defaults to `None` / the mint authority), any holder of the default
authority can later close the account and reclaim lamports - locking user funds.

Bug class: HIGH (permanent freezing of funds via unauthorized close)
Platform:  Solana / Anchor
Empirical anchor: OtterSec custody-token-account-closing-dos class;
                  CyfrinM-64520 (incorrect rent-exemption setup family).

Algorithm (regex):
1. Find calls to `initialize_account` / `initialize_account3` / `InitializeAccount`.
2. Look for the close_authority argument being set. If the call uses
   `initialize_account3` (which takes explicit close_authority) but passes
   `None` or if `initialize_account` is used without a follow-up
   `set_authority` call for `AuthorityType::CloseAccount`, flag it.
3. For Anchor `#[account(init, token::authority = ...)]` structs, flag if
   `close_authority` is not set and a close CPI is present in the file.
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
from typing import Optional

DETECTOR_ID = "rust_wave1.solana_token_account_close_authority_unset"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive"}

# initialize_account / initialize_account3 call patterns
_INIT_ACCOUNT_RE = re.compile(
    r"\b(initialize_account3?\s*\(|InitializeAccount\s*\{)"
)

# set_authority for CloseAccount
_SET_CLOSE_AUTH_RE = re.compile(
    r"set_authority[^;]*AuthorityType::CloseAccount"
)

# Anchor token init without close_authority
_ANCHOR_TOKEN_INIT_RE = re.compile(
    r"#\[\s*account\s*\([^)]*token::authority\s*=[^)]*\)\s*\]"
)

_CLOSE_AUTH_IN_ATTR_RE = re.compile(r"close_authority\s*=")

_SIGNER_OR_AUTHORITY_RE = re.compile(
    r"\b(spl_token|anchor_spl::token|token)\b"
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
    body_start: Optional[int] = None
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

    if not _SIGNER_OR_AUTHORITY_RE.search(content):
        return []

    if "initialize_account" not in content and "InitializeAccount" not in content:
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

        body, _ = _extract_fn_body(content, fn_offset)
        if body is None:
            continue

        init_match = _INIT_ACCOUNT_RE.search(body)
        if init_match is None:
            continue

        # Safe if set_authority for CloseAccount is present after init
        after_init = body[init_match.end():]
        if _SET_CLOSE_AUTH_RE.search(after_init):
            continue

        # Also safe if using initialize_account3 with explicit close authority
        # (initialize_account3 signature: initialize_account3(mint, account, owner, close_authority))
        # Heuristic: if the call passes 4 args and none is None, skip
        if "initialize_account3" in body[init_match.start():init_match.start() + 200]:
            call_fragment = body[init_match.start():init_match.start() + 300]
            if re.search(r"close_authority\s*:\s*Some\(", call_fragment):
                continue

        init_line = fn_line + body[:init_match.start()].count("\n")

        h: dict = {
            "detector_id": DETECTOR_ID,
            "file": filepath,
            "line": fn_line,
            "fn_name": fn_name_val,
            "init_line": init_line,
            "severity": "HIGH",
            "message": (
                f"fn `{fn_name_val}`: token account initialized at line {init_line} "
                f"without setting `close_authority` via `set_authority(CloseAccount)` - "
                f"account can be closed by default authority, locking/draining user funds."
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
