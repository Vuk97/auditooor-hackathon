"""
r94_loop_stake_exit_slashing_lag.py

Flags pub fns that update validator-set state (signer verifier, active
set, validator header) AND call a stake-exit/withdraw path in the same
fn OR the module lacks an atomic lock between them.

Source: Solodit #62105 (Sherlock Symbiotic Relay).
Class: stake-exit-slashing-lag (both).
"""

from __future__ import annotations
import re
from _util import (
    source_nocomment, functions_in_contractimpl, fn_body, fn_name, text_of, line_col, snippet_of, is_pub, body_text_nocomment, IDENT,
)

_FN_NAME_RE = re.compile(r"(?i)(set_sig_verifier|commit_val_set_header|update_validator_set|rotate_signer|commit_validator)")

_STAKE_EXIT_RE = re.compile(
    r"\bunstake\s*\(|\bwithdraw_stake\s*\(|\brelease_stake\s*\(|"
    r"\bstake\.exit|\bexit_stake\s*\(|cancel_stake\s*\("
)

_ATOMIC_GUARD_RE = re.compile(
    r"\batomic_(lock|block)\s*\(|in_atomic_set_change|"
    r"slash_window|exit_delay|cooldown_active|"
    fr"require!?\s*\([^)]*exit_{IDENT}locked"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    # Check full source for exit + validator-set coexistence
    src_nc = source_nocomment(source)
    if not _STAKE_EXIT_RE.search(src_nc):
        return hits
    if _ATOMIC_GUARD_RE.search(src_nc):
        return hits

    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "medium",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` updates the validator set / signer verifier. "
                f"Module ALSO exposes a stake-exit/unstake path with no "
                f"atomic-lock / slash-window / exit-delay. Operator can "
                f"commit malicious val-set and then unstake before slashing "
                f"catches them. See Solodit #62105 (Symbiotic Relay)."
            ),
        })
    return hits
