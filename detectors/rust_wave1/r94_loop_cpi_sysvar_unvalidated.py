"""
r94_loop_cpi_sysvar_unvalidated.py

Flags pub fns that accept a caller-supplied sysvar account and pass it
into a CPI context without asserting the account key matches the
canonical sysvar pubkey (instructions / rent / clock / recent_blockhashes).

Source: Solodit #47547 (OtterSec / Composable Vaults).
Rust side of `cpi-sysvar-validation` canonical class.
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)


_SYSVAR_USE_RE = re.compile(
    r"\b(sysvar|instructions_sysvar|rent_sysvar|clock_sysvar|"
    r"recent_blockhashes|sysvar_instructions)\b",
    re.IGNORECASE,
)

_CPI_RE = re.compile(
    r"CpiContext::new|CpiContext::new_with_signer|"
    r"solana_program::program::invoke|invoke_signed|"
    r"::cpi::\w+\s*\(",
)

_VALIDATION_RE = re.compile(
    r"sysvar::instructions::ID|"
    r"sysvar::rent::ID|"
    r"sysvar::clock::ID|"
    r"sysvar::recent_blockhashes::ID|"
    r"sysvar\w*\.key\s*\(\)\s*==|"
    r"assert_eq!?\s*\([^)]*sysvar.*(::ID|instructions)|"
    r"require!?\s*\([^)]*sysvar.*==|"
    r"validate_sysvar|check_sysvar|ensure_sysvar|"
    r"#\[account\(address\s*=\s*sysvar",
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

        if not _SYSVAR_USE_RE.search(body_nc):
            continue
        if not _CPI_RE.search(body_nc):
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
                f"pub fn `{name}` references a sysvar account and issues a "
                f"CPI without validating the sysvar key matches the canonical "
                f"pubkey (sysvar::*::ID). Attacker can substitute a fake sysvar "
                f"to inject unauthorized instructions. See Solodit #47547 "
                f"(Composable Vaults)."
            ),
        })
    return hits
