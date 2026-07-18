"""
r94_loop_upgrade_moved_storage_uninitialised_post_upgrade.py

Flags upgradeable-contract storage slots that are *read* by critical
guards (withdrawal_delay, pause, config) but have NO public setter
and NO assignment anywhere — slot was introduced in an upgrade but
can only be set by the `initialize()` flow which has already run,
so the guard silently evaluates to 0 / default.

Source: Solodit #53719 (SigmaPrime EigenLayer M2 withdrawalDelayBlocks).
Class: upgrade-moved-storage-uninitialised-post-upgrade (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, source_nocomment

_READS_RE = re.compile(
    r"(?i)(withdrawal_delay_blocks|withdrawal_delay|"
    r"withdraw_delay_blocks|escape_hatch_delay|"
    r"pause_delay|upgrade_delay_blocks)"
)

_FN_NAME_RE = re.compile(
    r"(?i)(withdraw|complete_queued_withdrawal|initiate_withdrawal|"
    r"queue_withdrawal|finalize|execute_upgrade|claim)"
)


def _contract_has_setter_for(source_text: str, slot: str) -> bool:
    # Any fn containing `self.slot = ` or `env.storage().set(slot_key, ...)` or
    # write to `state.slot = `.
    pat = re.compile(
        r"(?i)(\.\s*" + re.escape(slot) + r"\s*=|"
        r"set_" + re.escape(slot) + r"|"
        r"update_" + re.escape(slot) + r")"
    )
    return bool(pat.search(source_text))


def run(tree, source: bytes, filepath: str):
    hits = []
    source_text = source_nocomment(source)
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
        m = _READS_RE.search(body_nc)
        if not m:
            continue
        slot = m.group(0).lower()
        # If any setter for the slot is present, skip.
        if _contract_has_setter_for(source_text, slot):
            continue
        # If the module has an `initialize` fn that sets it, that counts.
        init_sets = re.search(
            r"(?i)fn\s+initialize[\s\S]{0,2000}?" + re.escape(slot) + r"\s*=",
            source_text,
        )
        if init_sets:
            # Only a concern when initialize already ran and slot wasn't in old init.
            # Heuristic: if initialize sets it, this is safe on first deploy.
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` reads critical guard `{slot}` that "
                f"has no public setter and is not assigned by any "
                f"`initialize` flow — after a storage-move upgrade "
                f"the slot stays 0/default and the invariant it "
                f"guarded is gone "
                f"(upgrade-moved-storage-uninitialised-post-upgrade). "
                f"See Solodit #53719 (SigmaPrime EigenLayer M2)."
            ),
        })
    return hits
