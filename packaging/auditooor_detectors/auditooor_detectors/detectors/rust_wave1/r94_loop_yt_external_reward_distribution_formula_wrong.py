"""
r94_loop_yt_external_reward_distribution_formula_wrong.py

Flags YT.claim_external_reward fns that pro-rate rewards via
`user_yt_balance / total_yt_supply` — YT balance grows as users
claim YBT yield, so big-claim-first users get disproportionally
more external rewards.

Source: Solodit #53034 (Cantina Napier Finance).
Class: yt-external-reward-distribution-formula-wrong (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(claim_external_reward|claim_reward|distribute_ext_reward|"
    r"distribute_external_reward|claim_bonus)"
)
_YT_RATIO_RE = re.compile(
    r"(user_yt_balance|yt_balances|yt_of|yt_token\.balance_of)\s*\([^)]*\)\s*[*/]"
    r"[\s\S]{0,80}?(total_yt_supply|yt_total_supply|yt\.total_supply)"
)
_SNAPSHOT_SHARE_RE = re.compile(
    r"(snapshot_yt_balance|yt_balance_at_start|yt_weight_at_issue|reward_weight_cache|"
    r"recorded_yt_balance_when_claim)"
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
        if not _YT_RATIO_RE.search(body_nc):
            continue
        if _SNAPSHOT_SHARE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` pro-rates external rewards via "
                f"user_yt_balance / total_yt_supply — YT balance "
                f"grows on YBT-yield claim, early claimers get "
                f"disproportionally more (yt-external-reward-"
                f"distribution-formula-wrong). See Solodit #53034 "
                f"(Napier Finance)."
            ),
        })
    return hits
