"""
reward_rate_excludes_rollover.py - Custom Slither detector.

Pattern (Hybra Finance M-05, slice_ad): A Synthetix-style staking contract
exposes `notifyRewardAmount(uint256 amount)` which sets
`rewardRate = amount / duration`. When rewards are added BEFORE the current
period has ended, the leftover reward amount (`rewardRate * remaining`) is
silently discarded - the new rate is computed from the new amount only,
dropping the rollover accumulator.

Canonical safe formulation:
    if (block.timestamp < periodFinish) {
        uint256 remaining = periodFinish - block.timestamp;
        uint256 leftover  = rewardRate * remaining;
        rewardRate = (amount + leftover) / duration;
    } else {
        rewardRate = amount / duration;
    }

Detection strategy:
    1. Iterate every declared function that WRITES a state variable whose
       name matches `rewardrate|rate` (case-insensitive).
    2. That function must contain at least one Binary DIVISION IR whose
       assignment feeds the rewardRate write.
    3. The function body must NOT READ the same rewardRate state variable
       anywhere (a rollover computation would read it). The function must
       also not read any state var whose name matches
       `leftover|remaining|rollover`.
    4. If both conditions hold, flag - the new rate drops the rollover.

@author auditooor wave11
@pattern slice_ad Hybra M-05
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
from slither.slithir.operations import Binary, BinaryType
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_RATE_RE = re.compile(r"(rewardrate|^rate$|_rate$|rate_)", re.IGNORECASE)
_ROLLOVER_HINT_RE = re.compile(r"(leftover|rollover|remaining|carryover)", re.IGNORECASE)


def _is_rate_var(sv) -> bool:
    return bool(_RATE_RE.search(sv.name or ""))


class RewardRateExcludesRollover(AbstractDetector):
    """Flag `rewardRate = amount / duration` that drops the leftover rollover."""

    ARGUMENT = "reward-rate-excludes-rollover"
    HELP = (
        "rewardRate setter computes amount/duration without adding the "
        "leftover rollover - new rewards dropped when called mid-period"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "rewardRate Setter Excludes Rollover Accumulator"
    WIKI_DESCRIPTION = (
        "A Synthetix-style rewards distributor computes "
        "`rewardRate = amount / duration` without adding the leftover from "
        "the previous period (`oldRewardRate * remainingSeconds`). When "
        "`notifyRewardAmount` is called mid-period the rollover amount is "
        "permanently lost - stakers get less than they were promised. "
        "Source: Hybra Finance M-05 (slice_ad)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
uint256 public rewardRate;
uint256 public periodFinish;
uint256 public duration = 7 days;

function notifyRewardAmount(uint256 amount) external {
    rewardRate = amount / duration;               // BUG: leftover dropped
    periodFinish = block.timestamp + duration;
}
```
1. Period 1: owner funds 70 tokens → rewardRate = 10/day, periodFinish = +7d.
2. On day 3, owner adds another 70 tokens. The remaining 40 tokens of
   period 1 (4 days × 10/day) should roll over.
3. Because the function rewrites rewardRate from `amount / duration` only,
   the 40 leftover tokens are orphaned in the contract and never distributed."""
    WIKI_RECOMMENDATION = (
        "Use the canonical Synthetix pattern: if `block.timestamp < "
        "periodFinish` compute `leftover = rewardRate * (periodFinish - "
        "block.timestamp)` and set `rewardRate = (amount + leftover) / "
        "duration`. Always read the existing rewardRate before overwriting."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            rate_state_vars = [sv for sv in contract.state_variables if _is_rate_var(sv)]
            if not rate_state_vars:
                continue
            rate_names = {sv.name for sv in rate_state_vars}

            for function in contract.functions_and_modifiers_declared:
                if function.is_constructor or function.view or function.pure:
                    continue

                writes = {sv.name for sv in function.state_variables_written}
                touched_rate = writes & rate_names
                if not touched_rate:
                    continue

                # Must contain at least one DIVISION IR - otherwise this
                # isn't an arithmetic rewardRate computation.
                has_division = False
                for node in function.nodes:
                    for ir in node.irs:
                        if isinstance(ir, Binary) and ir.type == BinaryType.DIVISION:
                            has_division = True
                            break
                    if has_division:
                        break
                if not has_division:
                    continue

                # Function must NOT read the rate state variable anywhere.
                reads = {sv.name for sv in function.state_variables_read}
                if reads & touched_rate:
                    continue

                # Function must not use leftover/rollover-named locals - if
                # there's a local named leftover/remaining/rollover the
                # author probably handled it via helper.
                local_names = " ".join(
                    (lv.name or "") for lv in function.local_variables
                )
                if _ROLLOVER_HINT_RE.search(local_names):
                    continue

                rate_sv = next(sv for sv in rate_state_vars if sv.name in touched_rate)
                info: DETECTOR_INFO = [
                    function,
                    " overwrites ",
                    rate_sv,
                    " with a division without reading the old value - leftover "
                    "rollover from the previous period is silently dropped. "
                    "Use `(amount + rewardRate * remaining) / duration` instead.\n",
                ]
                results.append(self.generate_result(info))

        return results
