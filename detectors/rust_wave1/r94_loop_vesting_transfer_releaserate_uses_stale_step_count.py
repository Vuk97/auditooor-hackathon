"""
r94_loop_vesting_transfer_releaserate_uses_stale_step_count.py

Flags vesting-transfer fns that recompute `releaseRate = totalAmount / steps`
after transferring a portion of a grant, using the ORIGINAL step count rather
than residual steps — the grantor unlocks more than the initial lock.

Source: Solodit #49536 (Code4rena SecondSwap StepVesting).
Class: vesting-transfer-releaserate-uses-stale-step-count (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(transfer_vesting|transferVesting|"
    r"transfer_grant|transferGrant|"
    r"split_vesting|splitVesting|"
    r"sell_vesting|sellVesting|"
    r"marketplace_transfer)"
)
_RELEASE_RATE_COMPUTE_RE = re.compile(
    fr"({IDENT}releaseRate\s*=\s*{IDENT}totalAmount\s*\/\s*{IDENT}(steps|stepCount|numSteps|N)|"
    fr"{IDENT}release_rate\s*=\s*{IDENT}total_amount\s*\/\s*{IDENT}(steps|step_count|num_steps|n))"
)
_FRESH_STEPS_RE = re.compile(
    r"(residualSteps|residual_steps|"
    r"remainingSteps|remaining_steps|"
    r"updatedStepCount|updated_step_count|"
    r"recompute_steps_from_residual|postTransferSteps)"
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
        if not _RELEASE_RATE_COMPUTE_RE.search(body_nc):
            continue
        if _FRESH_STEPS_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` recomputes releaseRate = totalAmount / steps "
                f"after transferring a portion of a vesting grant, using the "
                f"ORIGINAL step count rather than residual steps — the grantor "
                f"unlocks more than the initial lock "
                f"(vesting-transfer-releaserate-uses-stale-step-count). "
                f"See Solodit #49536 (Code4rena SecondSwap StepVesting)."
            ),
        })
    return hits
