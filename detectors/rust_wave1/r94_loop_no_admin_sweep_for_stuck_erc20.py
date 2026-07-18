"""
r94_loop_no_admin_sweep_for_stuck_erc20.py

Flags a Rust token-wrapper / collateral-holder / vault / adapter
struct that ships a user-facing wrap/unwrap/redeem/release path
(custodies an SPL / Soroban token underlying) but exposes NO
admin-gated sweep/rescue/recover function. Any token mistakenly
sent to the program's ATA — or underlying donated outside the wrap
path — is permanently stuck.

Hit condition (contract-scope, not per-fn):
  1. File declares a Collateral/Wrap/Adapter/Vault/Bridge-style
     struct with wrap/unwrap/redeem/release public fns.
  2. Those fns move a token in/out of the program's balance.
  3. No sweep / rescue / recover / emergency_withdraw / skim /
     salvage / admin_withdraw public fn exists anywhere in the
     file.

This is the Rust sibling of Solidity pattern
`no-admin-sweep-for-stuck-erc20` (Polymarket Drafts 6 & 8 —
CollateralToken wrapper has no recoverERC20 path).

Source: Polymarket Drafts 6+8 (phase 37b/c).
Class: no-admin-sweep-for-stuck-erc20 (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name, line_col,
    snippet_of, is_pub, body_text_nocomment,
)

# Wrap-path entry-points
_WRAP_FN_NAME_RE = re.compile(
    r"(?i)^(wrap|unwrap|redeem|release|withdraw|mint|burn|convert)$"
)

# Admin-sweep shapes that defuse the finding
_SWEEP_FN_NAME_RE = re.compile(
    r"(?i)^(sweep|sweep_tokens|rescue|rescue_tokens|rescue_erc20|"
    r"recover_erc20|recover_tokens|emergency_withdraw|admin_withdraw|"
    r"withdraw_stuck|skim|salvage|sweep_stuck|recover_stuck)$"
)

# Token-movement indicator inside a wrap-fn body.
_TOKEN_MOVE_RE = re.compile(
    r"(?i)(safe_transfer|safe_transfer_from|token::transfer|"
    r"token\.transfer|token\.transfer_from|transfer_checked)"
)

# Context — struct/file must look like a wrapper/collateral/vault.
_CONTEXT_RE = re.compile(
    r"(?i)(Collateral|Wrap|CTF|Bridge|Vault|Pool|Adapter|Token"
    r"Wrapper|WrappedCollateral)"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    src_head = source[:4096].decode("utf-8", errors="replace")
    if not (_CONTEXT_RE.search(src_head) or _CONTEXT_RE.search(filepath)):
        return hits

    # Pass 1: collect every pub fn's name + body_text.
    wrap_fns = []    # (fn_node, name)
    all_names = set()
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        all_names.add(name)
        if _WRAP_FN_NAME_RE.search(name):
            body = fn_body(fn)
            if body is None:
                continue
            body_nc = body_text_nocomment(body, source)
            if _TOKEN_MOVE_RE.search(body_nc):
                wrap_fns.append((fn, name))

    if not wrap_fns:
        return hits

    # Pass 2: does any pub fn look like an admin sweep/rescue?
    has_sweep = any(_SWEEP_FN_NAME_RE.search(n) for n in all_names)
    if has_sweep:
        return hits

    # Fire on the first wrap-path entry-point (representative locus).
    fn, name = wrap_fns[0]
    line, col = line_col(fn)
    hits.append({
        "severity": "low",
        "line": line,
        "col": col,
        "snippet": snippet_of(fn, source)[:200],
        "message": (
            f"struct has pub wrap/unwrap/redeem path `{name}` that "
            f"custodies a token, but no admin sweep/rescue/recover/"
            f"emergency_withdraw fn exists in the file — any token "
            f"mistakenly sent to the program address is permanently "
            f"stuck (no-admin-sweep-for-stuck-erc20). "
            f"See Polymarket Drafts 6+8 (CollateralToken wrapper)."
        ),
    })
    return hits
