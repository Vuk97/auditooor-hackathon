"""
r94_loop_bridge_retry_settlement_award_replay.py

Flags bridge-agent retry_settlement / retry_deposit fns that re-run
the settlement payout path while only gating on settlement_id
(single-shot flag) — if settlement body references a live
`awards_accrued` / `epoch_reward` map, retry after accrual inflates
payout.

Source: Solodit #26045 (C4 Maia RootBridgeAgent).
Class: bridge-retry-settlement-award-replay (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(retry_settlement|retry_deposit|redo_settlement|retry_bridge)")
_USES_LIVE_REWARD_RE = re.compile(
    r"(awards_accrued|epoch_reward|accumulated_reward|pending_award|"
    r"current_reward_balance|live_reward|pending_epoch)"
)
_SNAPSHOT_REWARD_RE = re.compile(
    r"(snapshot_reward|cached_reward|settlement_snapshot|frozen_reward|"
    r"recorded_award_at_submission|initial_reward_slot)"
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
        if not _USES_LIVE_REWARD_RE.search(body_nc):
            continue
        if _SNAPSHOT_REWARD_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` retries settlement using LIVE "
                f"awards_accrued / epoch_reward — attacker triggers "
                f"retry after awards accrue, payout inflated "
                f"(bridge-retry-settlement-award-replay). See "
                f"Solodit #26045 (Maia DAO RootBridgeAgent)."
            ),
        })
    return hits
