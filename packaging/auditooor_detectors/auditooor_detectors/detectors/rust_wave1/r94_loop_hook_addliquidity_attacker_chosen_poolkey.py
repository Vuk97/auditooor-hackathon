"""
r94_loop_hook_addliquidity_attacker_chosen_poolkey.py

Flags Uniswap-V4 style hook addLiquidity / addPoints / claim fns
that accept a caller-supplied `PoolKey` / pool-identifier without
asserting it matches a canonical / registered pool. Attacker feeds
a pool they control (custom hook, fee tier, tickSpacing) to earn
hook rewards / points for liquidity that didn't touch the real
pool.

Source: Solodit #62647 (Spearbit Semantic Layer SVFHook).
Class: hook-addliquidity-attacker-chosen-poolkey (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(add_liquidity|add_points|claim_points|"
    r"deposit_liquidity|earn_points|provide_liquidity|"
    r"credit_liquidity|record_liquidity)"
)
# Signature/body references a PoolKey or pool id supplied by caller.
_CALLER_POOLKEY_RE = re.compile(
    r"(?i)(PoolKey|pool_key|pool_id|poolKey|pool:\s*Pool\s*\{|"
    r"Key\s*\{\s*currency0|Key\s*\{\s*token0)"
)
# Safe: compares caller key to a canonical / known target.
_CANONICAL_CHECK_RE = re.compile(
    fr"(?i)(require\s*\(\s*{IDENT}key\s*==\s*{IDENT}canonical|"
    fr"require\s*\(\s*{IDENT}key\s*==\s*{IDENT}target_pool|"
    fr"require\s*\(\s*{IDENT}key\s*==\s*{IDENT}registered_pool|"
    fr"assert\w*\s*!?\s*\(\s*{IDENT}key\s*==\s*{IDENT}canonical|"
    fr"assert\w*\s*!?\s*\(\s*{IDENT}key\s*==\s*{IDENT}target_pool|"
    fr"assert\w*\s*!?\s*\(\s*{IDENT}key\s*==\s*{IDENT}registered_pool|"
    fr"assert\w*\s*!?\s*\(\s*{IDENT}pool_id\s*==\s*{IDENT}(target|canonical|expected)|"
    fr"is_registered_pool\s*\(|registry\.get\s*\(|"
    fr"canonical_pool_id|expected_pool_key)"
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
        if not _CALLER_POOLKEY_RE.search(body_nc):
            continue
        if _CANONICAL_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` accepts a caller-supplied PoolKey "
                f"/ pool_id but does NOT assert it matches a canonical "
                f"/ registered pool — attacker feeds a custom pool to "
                f"earn hook points / rewards for liquidity that never "
                f"touched the real pool "
                f"(hook-addliquidity-attacker-chosen-poolkey). "
                f"See Solodit #62647 (Spearbit Semantic Layer SVFHook)."
            ),
        })
    return hits
