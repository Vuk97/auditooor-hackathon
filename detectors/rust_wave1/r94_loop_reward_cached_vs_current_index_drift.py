"""
r94_loop_reward_cached_vs_current_index_drift.py

Flags reward fns that read a cached `reward_per_token_stored` field
(or similar) without first calling an update/settle helper — users who
stake between updates get stale index and miss / over-credit rewards.

Source: Solodit #6033 (Redacted Cartel reward miscalc).
Class: reward-cached-vs-current-index-drift (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(claim|earned|reward|get_reward|pending_reward|accrue)")
_CACHED_RE = re.compile(
    r"reward_per_token_stored|rewardPerTokenStored|cached_index|"
    r"reward_per_token_paid|rewardPerTokenPaid|last_reward_index|lastRewardIndex"
)
_UPDATE_CALL_RE = re.compile(
    r"\.update_reward\s*\(|update_rewards?\s*\(|_update_rewards?\s*\(|"
    r"settle_reward\s*\(|accrue_rewards?\s*\(|"
    r"reward_per_token\s*\(\s*\)[^,;]*?[^=!<>]=|"
    r"updateReward\s*\("
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
        if not _CACHED_RE.search(body_nc):
            continue
        if _UPDATE_CALL_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` reads cached `reward_per_token_stored` "
                f"without calling an update/settle helper first — stakers "
                f"between updates see stale index (reward-cached-vs-current-"
                f"index-drift). See Solodit #6033 (Redacted Cartel)."
            ),
        })
    return hits
