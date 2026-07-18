"""
r94_loop_gauge_reward_stake_withdraw_burst_game.py

Flags gauge reward-rate fns that settle rewards on every
stake/withdraw using the caller's INSTANTANEOUS balance as weight
— without time-weighted averaging — user bursts large
stake/withdraw pairs per block to capture rewards.

Source: Solodit #57302 (Codehawks Regnum RAAC Gauge).
Class: gauge-reward-stake-withdraw-burst-game (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(r"(?i)(stake|withdraw|deposit|exit|update_reward|claim_reward)")
_IMMEDIATE_WEIGHT_RE = re.compile(
    fr"(reward_per_token|rewards?\s*=\s*{IDENT}balance|accrue_for_user)\s*\(\s*{IDENT}balance_of|"
    fr"user_reward\s*\+=\s*{IDENT}current_balance|"
    fr"settle\s*\(\s*{IDENT}balance_of"
)
_TIME_WEIGHTED_RE = re.compile(
    r"(time_weighted|time_weighted_balance|effective_balance|"
    r"average_balance_over|vote_weight_at|stake_duration|"
    r"veBalance|lock_multiplier)"
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
        if not _IMMEDIATE_WEIGHT_RE.search(body_nc):
            continue
        if _TIME_WEIGHTED_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` settles gauge rewards using "
                f"instantaneous balance as weight without time-"
                f"weighted averaging — attacker bursts stake/withdraw "
                f"per block to capture rewards (gauge-reward-stake-"
                f"withdraw-burst-game). See Solodit #57302 (RAAC)."
            ),
        })
    return hits
