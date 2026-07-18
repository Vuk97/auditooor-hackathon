"""
r94_loop_reward_hook_duplicate_pool_listed_token_steal.py

Flags reward-emission / DCA-reward hook fns that credit rewards
based on a pool key that only identifies the (token0, token1)
pair — without also matching the canonical pool's fee /
tickSpacing / hook — attacker deploys a lookalike pool on the
same listed-token pair and siphons rewards meant for the
legitimate pool.

Source: Solodit #63420 (Sherlock Super DCA Liquidity Network).
Class: reward-hook-duplicate-pool-listed-token-steal (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(emit_rewards|distribute_rewards|credit_rewards_for_pool|"
    r"reward_for_pair|update_reward_stream|record_reward|"
    r"accumulate_reward|claim_pool_reward)"
)
# Must reference pair token0/token1 lookup.
_TOKEN_PAIR_KEY_RE = re.compile(
    fr"(?i)(token0\s*,\s*token1|key\.currency0\s*,\s*key\.currency1|"
    fr"pair\s*\(\s*{IDENT}token0\s*,\s*{IDENT}token1|"
    fr"listed_tokens\s*\[\s*{IDENT}token0|"
    fr"rewards_per_pair\s*\[)"
)
# Safe: also checks fee / tickSpacing / hook address / canonical registry.
_STRICT_KEY_RE = re.compile(
    fr"(?i)(key\.fee\s*==|key\.tick_spacing\s*==|key\.hook\s*==|"
    fr"canonical_pool_for_pair|"
    fr"require\s*\(\s*{IDENT}pool_id\s*==\s*{IDENT}canonical|"
    fr"assert\w*\s*!?\s*\(\s*{IDENT}pool_id\s*==\s*{IDENT}canonical|"
    fr"registered_pool_for_pair|whitelisted_pool)"
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
        if not _TOKEN_PAIR_KEY_RE.search(body_nc):
            continue
        if _STRICT_KEY_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` credits rewards based only on "
                f"(token0, token1) pair without also matching fee / "
                f"tickSpacing / hook — attacker deploys a lookalike "
                f"pool on the same listed-token pair and siphons "
                f"rewards from the canonical pool "
                f"(reward-hook-duplicate-pool-listed-token-steal). "
                f"See Solodit #63420 (Sherlock Super DCA Liquidity)."
            ),
        })
    return hits
