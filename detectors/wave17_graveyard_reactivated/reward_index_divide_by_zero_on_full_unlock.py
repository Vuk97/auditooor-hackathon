"""
reward_index_divide_by_zero_on_full_unlock.py - Custom Slither detector.

Pattern (GTE-launchpad H-07, slice_ac): Reward-per-share calculation uses
`totalStaked` / `totalShares` / `totalSupply` as a divisor without first
checking the value is non-zero. When every staker withdraws mid-epoch and
the next reward distribution lands, the division reverts; the distribution
path is permanently bricked unless someone re-stakes (griefable DoS).

Detection strategy:
    1. Iterate every non-vendored contract.
    2. For each function, walk Binary IR with type DIVISION.
    3. Identify the right-operand: it must be a state variable whose name
       matches "totalStaked" / "totalShares" / "totalSupply" / "totalDeposit"
       / "totalAssets".
    4. Check that the function body does NOT contain a guard for that state
       variable being zero - concretely, no require/if-condition node reads
       the same state var in a Binary EQUAL/NOT_EQUAL.
    5. If the unguarded division is found → flag.

@author auditooor wave9
@pattern slice_ac GTE-launchpad H-07
"""

import sys as _sys
import re
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import Binary, BinaryType
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_DENOM_RE = re.compile(
    r"(totalstaked|totalshares|totalsupply|totaldeposit|totalassets|totalbalance)",
    re.IGNORECASE,
)

_EQ_TYPES = frozenset({BinaryType.EQUAL, BinaryType.NOT_EQUAL})


def _is_total_state_var(var) -> bool:
    if not isinstance(var, StateVariable):
        return False
    return bool(_DENOM_RE.search(var.name or ""))


def _function_has_zero_guard(function, total_var) -> bool:
    """
    Look for require/if comparing total_var to zero (anywhere in function).
    """
    for node in function.nodes:
        if not (node.contains_require_or_assert() or node.contains_if()):
            continue
        if total_var not in node.state_variables_read:
            continue
        for ir in node.irs:
            if isinstance(ir, Binary) and ir.type in _EQ_TYPES:
                return True
    return False


class RewardIndexDivideByZeroOnFullUnlock(AbstractDetector):
    """Flag reward distributions that divide by totalStaked without a zero guard."""

    ARGUMENT = "reward-index-divide-by-zero-on-full-unlock"
    HELP = (
        "Reward distribution divides by totalStaked/totalShares/totalSupply "
        "without a zero guard - bricks the distribution path after full unstake"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Reward Index Divide-By-Zero On Full Unstake"
    WIKI_DESCRIPTION = (
        "A staking / vault reward distributor computes `accRewardPerShare += "
        "reward * 1e18 / totalStaked` without first checking that "
        "`totalStaked != 0`. When every staker exits mid-epoch and the next "
        "`distribute()` call lands, the division reverts. Because the call is "
        "typically invoked by a keeper / cron, the distribution path is "
        "permanently bricked until somebody manages to re-stake. A griefer can "
        "force this state by waiting for the staking pool to empty. Reported "
        "in GTE-launchpad H-07."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
uint256 public totalStaked;
uint256 public accRewardPerShare;

function distribute(uint256 reward) external {
    accRewardPerShare += reward * 1e18 / totalStaked;   // BUG: no guard
}
```
1. All stakers unstake mid-epoch; `totalStaked == 0`.
2. Keeper calls `distribute(reward)` → division reverts.
3. Until somebody re-stakes, every keeper call reverts and reward
   distribution is paused - griefable DoS."""
    WIKI_RECOMMENDATION = (
        "Guard the division: `if (totalStaked == 0) return;` or queue the "
        "pending reward in a buffer that gets drained on the next stake event."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                if function.is_constructor:
                    continue

                flagged = None
                for node in function.nodes:
                    for ir in node.irs:
                        if not isinstance(ir, Binary) or ir.type != BinaryType.DIVISION:
                            continue
                        denom = ir.variable_right
                        if not _is_total_state_var(denom):
                            continue
                        if _function_has_zero_guard(function, denom):
                            continue
                        flagged = (denom, node)
                        break
                    if flagged:
                        break

                if not flagged:
                    continue

                denom, node = flagged
                info: DETECTOR_INFO = [
                    function,
                    " divides by ",
                    denom,
                    " at ",
                    node,
                    " without first checking the denominator is non-zero. "
                    "When all stakers exit, distribution reverts and the "
                    "reward path is bricked.\n",
                ]
                results.append(self.generate_result(info))

        return results
