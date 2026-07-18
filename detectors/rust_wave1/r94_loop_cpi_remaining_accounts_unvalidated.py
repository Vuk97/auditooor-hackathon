"""
r94_loop_cpi_remaining_accounts_unvalidated.py

Flags pub fns that use `ctx.remaining_accounts` / `remaining_accounts`
as a source for CPI invocation OR account-index reads without
an upstream length check AND without per-account validation
(`key() ==`, `owner ==`, `is_signer` on the indexed account).

Source: Solodit #47544 (OtterSec / Composable Vaults).
Rust side of `cpi-remaining-accounts` canonical class.
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)


_REMAINING_RE = re.compile(
    r"\b(ctx\.remaining_accounts|remaining_accounts)\b"
)

# Patterns that indicate SOMEONE validated the remaining_accounts
_VALIDATION_RE = re.compile(
    r"remaining_accounts\.len\s*\(\)\s*(==|>=|<=|>|<)\s*\w|"
    r"remaining_accounts\[[^\]]*\]\.key\s*\(\)\s*==|"
    r"remaining_accounts\[[^\]]*\]\.owner\s*==|"
    r"remaining_accounts\[[^\]]*\]\.is_signer|"
    r"remaining_accounts\[[^\]]*\]\.mint\s*==|"
    r"validate_remaining_accounts|"
    r"require!?\s*\([^)]*remaining_accounts"
)

# Must actually USE remaining_accounts (read or pass to CPI)
_USE_RE = re.compile(
    r"remaining_accounts\s*\.\s*(iter|get|into_iter|as_slice|first|last)|"
    r"remaining_accounts\s*\[\s*\d+\s*\]|"
    r"remaining_accounts\s*:\s*&\s*\[|"
    r"CpiContext::new\s*\([^)]*remaining_accounts|"
    r"CpiContext::new_with_signer\s*\([^)]*remaining_accounts"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)

        if not _REMAINING_RE.search(body_nc):
            continue
        if not _USE_RE.search(body_nc):
            continue
        if _VALIDATION_RE.search(body_nc):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` uses `ctx.remaining_accounts` (iter/index/CPI) "
                f"without validating length or per-account owner/key/mint. "
                f"Attackers can inject arbitrary accounts through the "
                f"remaining_accounts slice. See Solodit #47544 (Composable Vaults)."
            ),
        })
    return hits
