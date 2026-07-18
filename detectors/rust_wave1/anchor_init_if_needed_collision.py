"""
anchor_init_if_needed_collision.py

Detects `init_if_needed` attribute usage in Anchor programs.

`#[account(init_if_needed, ...)]` initializes an account on first use and
silently skips initialization on subsequent calls.  This creates a TOCTOU
race: two concurrent transactions can both see the account as "not yet
initialized" and both attempt initialization, leading to:
  - Double-initialization with different owners / data
  - Attacker pre-initializes the account with attacker-controlled data before
    the legitimate user

The safe pattern is `#[account(init, ...)]` (reverts if already initialized)
or explicit `if account.is_initialized { return Err(...) }` before init.

Bug class: HIGH (account takeover / state confusion via race condition)
Platform:  Solana / Anchor
Empirical anchor: OtterSec ability-to-initialize-multiple-times-h-47543
                  (attacker front-runs the first initializer, taking ownership).

Algorithm:
1. Find all occurrences of `init_if_needed` in attribute positions.
2. Flag each occurrence, noting the field name and struct context.
3. Safe pattern: `#[account(init_if_needed, ...)]` followed immediately by
   explicit discrimination logic in the handler (`if ctx.accounts.X.initialized`).
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
from typing import Optional

DETECTOR_ID = "rust_wave1.anchor_init_if_needed_collision"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive"}

# init_if_needed - find attribute blocks containing it (handles multiline)
# We do not use a single regex; instead we extract all #[account(...)] blocks
# and check if they contain init_if_needed
_ACCOUNT_ATTR_BLOCK_RE = re.compile(
    r"#\[account\(", re.MULTILINE
)

_TEST_RE = re.compile(r"#\[\s*(?:cfg\s*\(\s*test|test)\s*\]")


def scan_file(filepath: str) -> list[dict]:
    try:
        with open(filepath, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
        return []

    if "init_if_needed" not in content:
        return []

    if "anchor_lang" not in content and "#[derive(Accounts)]" not in content:
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

    # Extract all #[account(...)] attribute blocks (handles multiline)
    # Strategy: find each `#[account(` start, then track paren depth to find end
    for m_attr in _ACCOUNT_ATTR_BLOCK_RE.finditer(content):
        attr_start = m_attr.start()
        paren_open = m_attr.end() - 1  # position of the first `(`
        depth = 0
        i = paren_open
        attr_end = paren_open
        while i < len(content):
            ch = content[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    attr_end = i + 1
                    break
            i += 1

        attr_block = content[attr_start:attr_end]

        # Must contain init_if_needed (not just in a comment)
        if "init_if_needed" not in attr_block:
            continue

        # The field name follows the closing `]` of the attribute
        # Find the closing `]` after attr_end
        rest = content[attr_end:]
        close_bracket_match = re.search(r"^\s*\]", rest)
        if close_bracket_match:
            after_attr = rest[close_bracket_match.end():]
        else:
            after_attr = rest

        field_match = re.search(r"^\s*(?:pub\s+)?(\w+)\s*:", after_attr)
        if not field_match:
            continue
        field_name = field_match.group(1)

        pos = attr_start

        # Skip if inside a test block
        surrounding = content[max(0, pos - 200):pos]
        if _TEST_RE.search(surrounding):
            continue

        line = content[:pos].count("\n") + 1

        # Check for safe guard: explicit initialization check in the file
        # after this attribute
        after = content[attr_end:attr_end + 800]
        has_guard = bool(re.search(
            r"\b(is_initialized|already_initialized|initialized\s*==\s*true|"
            r"discriminator\s*!=\s*\[0|require!\s*\([^)]*initialized)",
            after
        ))
        if has_guard:
            continue

        h: dict = {
            "detector_id": DETECTOR_ID,
            "file": filepath,
            "line": line,
            "fn_name": f"<account field {field_name}>",
            "field_name": field_name,
            "severity": "HIGH",
            "message": (
                f"`#[account(init_if_needed)]` on field `{field_name}` at line {line} "
                f"without explicit re-initialization guard - concurrent transactions can "
                f"race to initialize the account with attacker-controlled data (TOCTOU). "
                f"Use `#[account(init)]` or add explicit `is_initialized` check."
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
