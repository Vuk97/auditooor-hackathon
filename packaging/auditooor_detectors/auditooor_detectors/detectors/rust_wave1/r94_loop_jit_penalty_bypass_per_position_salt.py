"""
r94_loop_jit_penalty_bypass_per_position_salt.py

Flags JIT-liquidity / MEV penalty hook fns that look up the
"last-touched" block per position *keyed by salt* without also
hashing owner/tick-range into the identity — attacker splits a
deposit across multiple salts so each position looks fresh and
no penalty applies.

Source: Solodit #61375 (OpenZeppelin OZ Uniswap Hooks v1.1.0 RC1).
Class: jit-penalty-bypass-per-position-salt (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(before_remove_liquidity|after_remove_liquidity|"
    r"compute_jit_penalty|apply_penalty|penalty_hook|"
    r"record_liquidity_add|record_liquidity_remove)"
)
# Must touch a per-position tracker that uses `salt`.
_SALT_KEY_RE = re.compile(
    fr"(?i)({IDENT}salt\w*|position\.salt|params\.salt|modifyParams\.salt)"
)
# Safe: key includes owner / tick range / hash beyond just salt.
_COMPOSITE_KEY_RE = re.compile(
    r"(?i)(keccak\w*\s*\([^)]*owner|"
    r"keccak\w*\s*\([^)]*tick_lower|"
    r"keccak\w*\s*\([^)]*tickLower|"
    r"position_key\s*\([^)]*owner|"
    r"Pool\.position_key\s*\([^)]*|"
    r"abi\.encode\s*\([^)]*owner[^)]*salt|"
    r"hash\s*\(\s*&?\s*\[\s*owner|"
    r"composite_key|aggregate_key_for_position|"
    r"total_recent_liquidity_for_owner|owner_total_jit|"
    r"sum_salts_for_owner)"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _SALT_KEY_RE.search(body_nc):
            continue
        if _COMPOSITE_KEY_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` keys the JIT-penalty 'last-touched' "
                f"tracker purely on `salt` — attacker splits a deposit "
                f"across multiple salts so each position looks fresh "
                f"and no penalty is ever charged "
                f"(jit-penalty-bypass-per-position-salt). "
                f"See Solodit #61375 (OZ Uniswap Hooks v1.1.0 RC1)."
            ),
        })
    return hits
