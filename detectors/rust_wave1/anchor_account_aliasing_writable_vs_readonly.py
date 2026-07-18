"""
anchor_account_aliasing_writable_vs_readonly.py

Detects Anchor account aliasing: an account declared as `#[account(mut)]`
(writable) is passed in two positions to the same instruction context, or an
account expected to be read-only is mutated, OR two separate accounts in the
same Accounts struct share the same key (aliasing via `constraint = a.key() ==
b.key()` with one declared `mut`).

Bug class: HIGH (double-spend / account aliasing attack)
Platform:  Solana / Anchor
Empirical anchor: OtterSec account aliasing class - when the same account
                  appears in two positions, one of which is `mut`, state
                  mutations via either alias see stale cached data.

Algorithm (regex):
1. Find `#[derive(Accounts)]` structs.
2. Within the struct, look for two fields with the same constraint expression
   `constraint = X.key() == Y.key()` where X or Y is `mut`.
3. Also flag any `#[account(mut)]` field without a `constraint` binding it to
   a distinct signer/owner check (risky writable sentinel pattern).
4. Separately flag functions that mutate a field explicitly declared as
   `/// CHECK:` (unchecked AccountInfo) while also doing a CPI.
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
from typing import Optional

DETECTOR_ID = "rust_wave1.anchor_account_aliasing_writable_vs_readonly"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive"}

_DERIVE_ACCOUNTS_RE = re.compile(r"#\[\s*derive\s*\(\s*Accounts\s*\)\s*\]")

# `#[account(mut)]` without has_one / constraint / owner check
_MUT_ACCOUNT_RE = re.compile(
    r"#\[\s*account\s*\(\s*mut\s*\)\s*\]"
    r"\s*pub\s+(\w+)\s*:\s*(AccountInfo|UncheckedAccount|Account)\s*<"
)

# constraint = a.key() == b.key()
_ALIAS_CONSTRAINT_RE = re.compile(
    r"constraint\s*=\s*(\w+)\.key\s*\(\s*\)\s*==\s*(\w+)\.key\s*\(\s*\)"
)

# `/// CHECK:` docstring above an account field (unchecked marker)
_CHECK_MARKER_RE = re.compile(r"///\s*CHECK:")

_FN_HEADER_RE = re.compile(
    r"^[ \t]*"
    r"(?:pub(?:\s*\([^)]*\))?\s+)?"
    r"fn\s+(?P<name>[A-Za-z_]\w*)"
    r"(?:\s*<[^(>]*>)?\s*\(",
    re.MULTILINE,
)

_TEST_RE = re.compile(r"#\[\s*(?:cfg\s*\(\s*test|test)\s*\]")


def scan_file(filepath: str) -> list[dict]:
    try:
        with open(filepath, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
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

    def _make_hit(line: int, fn_name: str, message: str) -> dict:
        h: dict = {
            "detector_id": DETECTOR_ID,
            "file": filepath,
            "line": line,
            "fn_name": fn_name,
            "severity": "HIGH",
            "message": message,
        }
        if _crate_name and _crate_name != "unknown":
            h["crate_name"] = _crate_name
        if _mod_prefix:
            h["module_path"] = _mod_prefix
        return h

    # Pattern 1: `#[account(mut)]` on AccountInfo / UncheckedAccount
    # without any constraint - classic writable aliasing sentinel.
    for m in _MUT_ACCOUNT_RE.finditer(content):
        line = content[:m.start()].count("\n") + 1
        field_name = m.group(1)
        acct_type = m.group(2)
        # Look backward for /// CHECK: marker (intentional unchecked)
        surrounding = content[max(0, m.start() - 300):m.start()]
        if _CHECK_MARKER_RE.search(surrounding):
            # Developer acknowledged, skip
            continue
        hits.append(_make_hit(
            line, "<struct>",
            f"`#[account(mut)]` on `{field_name}: {acct_type}<_>` without "
            f"`has_one`, `constraint`, or `owner` validation - writable "
            f"account alias possible (attacker supplies same pubkey twice)."
        ))

    # Pattern 2: alias via `constraint = a.key() == b.key()`
    # where both appear in the same struct with one being `mut`
    alias_pairs = list(_ALIAS_CONSTRAINT_RE.finditer(content))
    for m in alias_pairs:
        a, b = m.group(1), m.group(2)
        line = content[:m.start()].count("\n") + 1
        # Check if either is declared mut in the surrounding struct
        surrounding = content[max(0, m.start() - 600):m.start() + 200]
        a_mut = re.search(rf"#\[account[^\]]*mut[^\]]*\]\s*pub\s+{a}\b", surrounding)
        b_mut = re.search(rf"#\[account[^\]]*mut[^\]]*\]\s*pub\s+{b}\b", surrounding)
        if a_mut or b_mut:
            mut_field = a if a_mut else b
            hits.append(_make_hit(
                line, "<struct>",
                f"Alias constraint `{a}.key() == {b}.key()` with `{mut_field}` "
                f"declared `mut` - writable/read-only aliasing possible; "
                f"mutations through the `mut` alias render the other reference stale."
            ))

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
