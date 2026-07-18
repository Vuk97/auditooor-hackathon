"""
r94_loop_vesting_update_overwrites_unsnapshotted_accrued_vested.py

Flags vesting-update fns that overwrite released/withdrawn counters on a
grant/claim/vesting struct without first snapshotting already-vested
accrual — user loses historical vested amount when the schedule is
amended.

Source: Solodit #3771 (Code4rena VTVL).
Class: vesting-update-overwrites-unsnapshotted-accrued-vested (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(update_vesting|updateVesting|"
    r"modify_vesting|modifyVesting|"
    r"change_vesting|changeVesting|"
    r"amend_grant|amendGrant|"
    r"reschedule_vesting|rescheduleVesting)"
)
_OVERWRITES_RE = re.compile(
    r"(claim\s*\.\s*(amount|released|withdrawn|schedule_start|schedule_end)\s*=\s*\w+|"
    r"grant\s*\.\s*(amount|released|withdrawn|released_at)\s*=\s*\w+|"
    r"vesting\s*\.\s*(amount|released|withdrawn)\s*=)"
)
_SNAPSHOT_RE = re.compile(
    r"(snapshot_vested|snapshotVested|"
    r"accrued_vested\s*\+=|accruedVested\s*\+=|"
    r"pay_pending_vested|payPendingVested|"
    r"sync_released_up_to_now|syncReleasedUpToNow|"
    r"checkpoint_accrued|checkpointAccrued)"
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
        if not _OVERWRITES_RE.search(body_nc):
            continue
        if _SNAPSHOT_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn {name} updates a vesting schedule by "
                f"overwriting released/withdrawn counters without "
                f"first snapshotting already-vested accrual — user "
                f"loses historical vested amount "
                f"(vesting-update-overwrites-unsnapshotted-accrued-vested). "
                f"See Solodit #3771 (Code4rena VTVL)."
            ),
        })
    return hits
