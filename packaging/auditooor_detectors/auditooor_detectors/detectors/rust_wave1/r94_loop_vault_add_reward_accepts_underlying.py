"""
r94_loop_vault_add_reward_accepts_underlying.py

Flags staking/vault `add_reward_token` fns that don't check
`reward != underlying / stake_token` — attacker registers underlying
as a reward and drains stakers' balance.

Source: Solodit #21994 (Popcorn MultiRewardStaking).
Class: vault-add-reward-accepts-underlying (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(add_reward|register_reward|init_reward|create_reward)")
_NO_SAME_CHECK_RE = re.compile(
    r"(reward_token|reward)\s*(==|!=)\s*(underlying|stake_token|asset|staking_token)|"
    r"assert[!_]?eq\s*\(\s*(reward_token|reward),\s*(underlying|stake_token|asset)|"
    r"require\s*\(\s*(reward_token|reward)\s*!=\s*(underlying|stake_token|asset)"
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
        if _NO_SAME_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` registers reward token without "
                f"asserting it differs from the underlying/stake asset "
                f"— attacker seeds underlying as reward and drains "
                f"stakers (vault-add-reward-accepts-underlying). "
                f"See Solodit #21994 (Popcorn)."
            ),
        })
    return hits
