"""
unpause_missing_checkpoint_update.py - Custom Slither detector.

Pattern (Zellic slice_ab Zealous LastRewardBlock-Not-Updated-On-Resume,
MEDIUM): `unpause()` flips the pause flag back to false but does not
refresh the `lastRewardBlock` / `lastUpdateTime` / `lastAccrualTime`
checkpoint used by the reward accrual formula. On the next accrual call
the contract credits users with phantom rewards for the entire paused
duration - exactly the accrual the pause was meant to suspend.

Detection strategy:
    1. Find functions whose name matches `unpause` / `resume` / `unfreeze`
       (case-insensitive), OR whose body sets a state variable named
       `paused`/`isPaused`/`frozen` to `false` (a Constant(False)).
    2. The contract must also declare at least one state variable whose
       name matches a checkpoint pattern:
         last(Reward|Update|Accrual|Block|Time|Epoch|Mint|Harvest).*
    3. The unpause function must NOT write any of those checkpoint state
       variables.
    4. The contract must have some accrual function that READS the
       checkpoint and computes a time-based delta (heuristic: any function
       that both reads the checkpoint AND reads `block.timestamp` or
       `block.number`).
    5. Flag the unpause function.

@author auditooor wave10
@pattern slice_ab zealous-may-25 LastRewardBlock-Not-Updated-On-Resume
"""

import re
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.slithir.operations import Assignment
from slither.slithir.variables import Constant
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_UNPAUSE_NAME_RE = re.compile(
    r"^(unpause|resume|unfreeze|reactivate|restart)$", re.IGNORECASE
)
_CHECKPOINT_RE = re.compile(
    r"^last(Reward|Update|Accrual|Block|Time|Epoch|Mint|Harvest|Emission|Checkpoint)",
    re.IGNORECASE,
)
_PAUSED_FLAG_RE = re.compile(r"^(paused|ispaused|frozen|isfrozen|halted)$", re.IGNORECASE)
_TIME_VARS = frozenset({"block.timestamp", "block.number", "now"})


def _is_unpause_function(function) -> bool:
    if _UNPAUSE_NAME_RE.match(function.name or ""):
        return True
    # Also treat any function that writes paused=false as unpause-like.
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, Assignment):
                lv = ir.lvalue
                if lv is None:
                    continue
                if not _PAUSED_FLAG_RE.match(getattr(lv, "name", "") or ""):
                    continue
                rv = ir.rvalue
                if isinstance(rv, Constant):
                    try:
                        if rv.value is False or int(rv.value) == 0:
                            return True
                    except Exception:
                        pass
    return False


def _collect_checkpoint_vars(contract):
    return [
        sv for sv in contract.state_variables
        if sv.name and _CHECKPOINT_RE.match(sv.name)
    ]


def _function_writes_any(function, vars_) -> bool:
    written = set(function.state_variables_written)
    return any(v in written for v in vars_)


def _function_reads_any(function, vars_) -> bool:
    read = set(function.state_variables_read)
    return any(v in read for v in vars_)


def _function_reads_block_time(function) -> bool:
    for node in function.nodes:
        for sv in node.solidity_variables_read:
            if getattr(sv, "name", None) in _TIME_VARS:
                return True
    return False


class UnpauseMissingCheckpointUpdate(AbstractDetector):
    """Detect unpause/resume functions that don't refresh the reward accrual checkpoint."""

    ARGUMENT = "unpause-missing-checkpoint-update"
    HELP = (
        "unpause()/resume() flips the pause flag but does not refresh "
        "lastRewardBlock/lastUpdateTime - paused period accrues phantom rewards"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Unpause Missing Checkpoint Refresh"
    WIKI_DESCRIPTION = (
        "Reward contracts accrue emissions against a stored checkpoint - "
        "`lastRewardBlock`, `lastUpdateTime`, `lastAccrualTime` - and compute "
        "the next payout as `(block.number - lastRewardBlock) * rewardPerBlock`. "
        "When the protocol pauses and later unpauses, the checkpoint must be "
        "refreshed to `block.number` / `block.timestamp` at resume time; "
        "otherwise the very next accrual call retroactively emits rewards for "
        "every paused block, defeating the entire purpose of the pause. "
        "Zealous (May 2025) shipped this bug."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function unpause() external onlyOwner {
    paused = false;   // BUG: lastRewardBlock not refreshed
}
function updateRewards() external {
    require(!paused);
    totalRewards += (block.number - lastRewardBlock) * rewardPerBlock;
    lastRewardBlock = block.number;
}
```
Admin pauses for 7 days while an oracle is being fixed. At resume, the
first `updateRewards()` call emits 7 days worth of block rewards to active
stakers, diluting every other LP and draining the reward reservoir."""
    WIKI_RECOMMENDATION = (
        "In `unpause()`/`resume()` refresh every accrual checkpoint: "
        "`lastRewardBlock = block.number; lastUpdateTime = block.timestamp;` "
        "before flipping the pause flag off."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            checkpoint_vars = _collect_checkpoint_vars(contract)
            if not checkpoint_vars:
                continue

            # Require at least one accrual function that reads both a
            # checkpoint var and block.timestamp/number - otherwise the
            # checkpoint isn't used for time-based accrual.
            has_accrual_fn = False
            for f in contract.functions_and_modifiers_declared:
                if _function_reads_any(f, checkpoint_vars) and _function_reads_block_time(f):
                    has_accrual_fn = True
                    break
            if not has_accrual_fn:
                continue

            for function in contract.functions_and_modifiers_declared:
                if function.is_constructor:
                    continue
                if not _is_unpause_function(function):
                    continue
                if _function_writes_any(function, checkpoint_vars):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " resumes the contract but does not refresh the reward "
                    "checkpoint ",
                    checkpoint_vars[0],
                    " - phantom rewards accrue for the paused duration.\n",
                ]
                results.append(self.generate_result(info))

        return results
