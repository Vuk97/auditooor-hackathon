"""
r94_loop_bridge_token_mint_not_verified.py

Flags deposit / bridge-inbound functions that accept a user-provided
token account (SPL or equivalent) and transfer from it WITHOUT verifying
that the account's mint matches the configured whitelist mint for the
deposit type.

Source: Solodit #58635 (Sherlock / ZetaChain Cross-Chain).
Rust side of `bridge-token-mismatch` canonical class.

Heuristic:
  1. Function name matches /deposit|bridge_in|inbound|wrap/.
  2. Body contains a `transfer` / `transfer_checked` / `spl_token::` CPI
     that pulls from the user's token account.
  3. Body does NOT contain a mint-equality assertion like
     `assert!(user_token_acc.mint == expected_mint)` /
     `require!(user_ata.mint == pool.mint)` /
     a `.mint != expected_mint` revert path.
"""

from __future__ import annotations

import re

from _util import (
    source_nocomment,
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)


_FN_NAME_RE = re.compile(r"(?i)(deposit|bridge_in|inbound|wrap|lock_tokens)")

_TRANSFER_RE = re.compile(
    r"\b(spl_token::instruction::transfer|token::transfer|"
    r"transfer_checked|\.try_transfer|\.transfer\s*\()",
    re.MULTILINE,
)

_MINT_CHECK_RE = re.compile(
    r"(\.mint\s*==\s*\w|\.mint\s*!=\s*\w|"
    r"mint\s*==\s*\w+\.mint|"
    r"require!?\s*\([^)]*\.mint\s*==|"
    r"assert!?\s*\([^)]*\.mint\s*==|"
    r"ensure_mint|verify_mint|check_mint)",
    re.MULTILINE,
)


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)
        # Strip line comments + block comments before predicate scan (they can
        # describe the bug with phrases like ".mint == expected" that false-
        # trigger the mint-check guard).
        body_text_nocomment = re.sub(r"//[^\n]*", "", body_text)
        body_text_nocomment = re.sub(r"/\*.*?\*/", "", body_text_nocomment, flags=re.DOTALL)

        if not _TRANSFER_RE.search(body_text_nocomment):
            continue
        if _MINT_CHECK_RE.search(body_text_nocomment):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"fn `{name}` pulls tokens from a user-provided account "
                f"without verifying the account's mint matches the "
                f"whitelist/pool mint. Attacker can deposit an unrelated "
                f"SPL mint and have it counted as canonical (wrapped-token "
                f"mint at destination). See Solodit #58635 (ZetaChain)."
            ),
        })
    return hits
