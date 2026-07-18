"""
anchor_owner_check_missing_on_authority.py

Detects missing owner/program-id validation on authority accounts in Anchor.

An `#[account]` field that represents an authority (by naming convention or
by being referenced in state-mutation logic) MUST be validated via:
  - `has_one = authority` in the account constraint, OR
  - `#[account(signer)]` / `Signer<'info>` type, OR
  - explicit `require_keys_eq!(ctx.accounts.authority.key(), expected, ...)`.

When none of these are present, any pubkey can be passed as authority and will
be silently accepted - allowing fee redirection, config takeover, or fund theft.

Bug class: HIGH (authority bypass → admin config takeover / fund theft)
Platform:  Solana / Anchor
Empirical anchor: OtterSec H-48736 (invalid authority check on pool management
                  - attacker passes arbitrary fee_destination).

Algorithm (regex on Anchor context structs + handler bodies):
1. Locate Accounts structs (after `#[derive(Accounts)]`).
2. Find fields named `authority` / `admin` / `owner` / `manager` / `delegate`.
3. Check whether that field has `Signer<'info>`, `has_one =`, `constraint =`,
   or `#[account(signer)]` in its attribute.
4. If none → flag.
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
from typing import Optional

DETECTOR_ID = "rust_wave1.anchor_owner_check_missing_on_authority"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive"}

_AUTHORITY_NAMES = frozenset(
    {"authority", "admin", "owner", "manager", "delegate", "admin_authority",
     "pool_authority", "vault_authority", "program_authority"}
)

# Matches `pub authority: SomeType<'info>` within a struct
_FIELD_RE = re.compile(
    r"(?P<attrs>(?:#\[[^\]]*\]\s*)*)"
    r"pub\s+(?P<name>\w+)\s*:\s*(?P<typ>[^,\n{]+)",
    re.DOTALL,
)

_SAFE_PATTERNS = (
    r"Signer\s*<",
    r"has_one\s*=\s*\w+",
    r"constraint\s*=",
    r"#\[\s*account\s*\([^)]*signer",
    r"require_keys_eq!\s*\(",
    r"assert_keys_eq!\s*\(",
)

_DERIVE_ACCOUNTS_RE = re.compile(r"#\[\s*derive\s*\(\s*Accounts\s*\)\s*\]")
_TEST_RE = re.compile(r"#\[\s*(?:cfg\s*\(\s*test|test)\s*\]")


def _extract_struct_body(content: str, struct_start: int) -> Optional[str]:
    """Extract the body of a struct starting from struct_start."""
    depth = 0
    i = struct_start
    while i < len(content):
        ch = content[i]
        if ch == "{":
            depth += 1
            if depth == 1:
                start = i + 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return content[start:i]
        i += 1
    return None


def scan_file(filepath: str) -> list[dict]:
    try:
        with open(filepath, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
        return []

    if "#[derive(Accounts)]" not in content and "anchor_lang" not in content:
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

    for m_derive in _DERIVE_ACCOUNTS_RE.finditer(content):
        derive_pos = m_derive.start()
        # Skip test structs
        surrounding = content[max(0, derive_pos - 100):derive_pos]
        if _TEST_RE.search(surrounding):
            continue

        # Find the struct keyword after derive
        struct_match = re.search(r"\bstruct\s+(\w+)", content[derive_pos:derive_pos + 200])
        if not struct_match:
            continue
        struct_name = struct_match.group(1)
        struct_body_start = derive_pos + struct_match.end()

        body = _extract_struct_body(content, struct_body_start)
        if body is None:
            continue

        for m_field in _FIELD_RE.finditer(body):
            field_name = m_field.group("name")
            if field_name not in _AUTHORITY_NAMES:
                continue

            attrs = m_field.group("attrs")
            field_typ = m_field.group("typ")
            combined = attrs + field_typ

            if any(re.search(p, combined) for p in _SAFE_PATTERNS):
                continue

            # Compute line number
            body_offset = content.find(body, struct_body_start)
            field_in_body = body[:m_field.start()]
            line = content[:body_offset].count("\n") + field_in_body.count("\n") + 1

            h: dict = {
                "detector_id": DETECTOR_ID,
                "file": filepath,
                "line": line,
                "fn_name": f"<struct {struct_name}>",
                "field_name": field_name,
                "severity": "HIGH",
                "message": (
                    f"In `{struct_name}`: field `{field_name}` is an authority "
                    f"account without `Signer<'info>`, `has_one`, `constraint`, or "
                    f"`#[account(signer)]` - owner check missing; "
                    f"attacker can substitute arbitrary pubkey."
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
