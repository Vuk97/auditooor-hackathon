"""
period_cache_skip_reward_accumulator.py - Custom Slither detector.

Pattern (Ramses M-01, slice_ab): A reward accumulator updater early-returns
when `reward == 0` (or `amount == 0`) without writing the cache for the
current period. Subsequent reads of `accRewardPerShare[period]` get a
default zero, breaking forward-carry of the previous period's accumulator.

Detection strategy:
    1. Iterate every non-vendored contract.
    2. Find functions whose lowercased name contains "updatereward",
       "accumulate", "updateaccrual", "updateindex".
    3. The function must write to a state variable typed
       `mapping(<uint-like> => <uint>)` whose value type is numeric - that
       is the per-period reward accumulator.
    4. Look at every node that contains an `if` AND a `RETURN`-like exit
       AND a Binary EQUAL whose right operand is a Constant 0 - this is the
       early-return guard.
    5. If such a guard exists in the function and there is no extra
       assignment to the accumulator BEFORE the return → flag.

@author auditooor wave9
@pattern slice_ab Ramses M-01
"""

import sys as _sys
import re
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.core.cfg.node import NodeType
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.core.solidity_types import MappingType, ElementaryType
from slither.slithir.operations import Binary, BinaryType
from slither.slithir.variables import Constant
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_FN_NAME_RE = re.compile(
    r"(updatereward|accumulate|updateaccrual|updateindex|crankreward|notifyreward)",
    re.IGNORECASE,
)


def _is_period_accumulator(sv) -> bool:
    """Return True if state var is mapping(uint... => uint...)."""
    t = getattr(sv, "type", None)
    if not isinstance(t, MappingType):
        return False
    if not isinstance(t.type_from, ElementaryType) or not str(t.type_from).startswith("uint"):
        return False
    if not isinstance(t.type_to, ElementaryType) or not str(t.type_to).startswith("uint"):
        return False
    return True


def _function_writes_period_accumulator(function) -> bool:
    for sv in function.state_variables_written:
        if _is_period_accumulator(sv):
            return True
    return False


def _has_zero_guard_early_return(function) -> bool:
    """
    Walk the CFG. Looking for a pattern:
        IF reward == 0  →  RETURN
    Implementation:
        For every IF node whose IRs include a Binary EQUAL with Constant(0) on
        either side, check whether at least one of its sons is a RETURN node
        (or leads quickly to one without an assignment to a period accumulator).
    """
    for node in function.nodes:
        if node.type != NodeType.IF:
            continue
        # Detect EQUAL-to-zero inside this node's IRs.
        zero_eq = False
        for ir in node.irs:
            if not isinstance(ir, Binary) or ir.type != BinaryType.EQUAL:
                continue
            for side in (ir.variable_left, ir.variable_right):
                if isinstance(side, Constant):
                    val = side.value
                    if val == 0 or val is False:
                        zero_eq = True
                        break
            if zero_eq:
                break
        if not zero_eq:
            continue
        # Check whether THEN-branch leads to a RETURN within ~3 nodes
        # without writing the accumulator.
        for son in node.sons:
            if _branch_returns_without_write(son, depth=4):
                return True
    return False


def _branch_returns_without_write(node, depth: int) -> bool:
    cur = node
    seen = set()
    while cur is not None and depth > 0 and id(cur) not in seen:
        seen.add(id(cur))
        if cur.type == NodeType.RETURN:
            return True
        # If the node writes a period accumulator state var, the branch is OK.
        for sv in cur.state_variables_written:
            if _is_period_accumulator(sv):
                return False
        # Move to first son if linear.
        if len(cur.sons) == 1:
            cur = cur.sons[0]
            depth -= 1
        else:
            return False
    return False


class PeriodCacheSkipRewardAccumulator(AbstractDetector):
    """Flag reward updater functions that early-return on zero without writing the cache."""

    ARGUMENT = "period-cache-skip-reward-accumulator"
    HELP = (
        "updateReward early-returns on (reward == 0) without writing the "
        "current period's accumulator - subsequent reads return uninitialised 0"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Period Reward Cache Skipped When Reward Is Zero"
    WIKI_DESCRIPTION = (
        "A reward accumulator stores `accRewardPerShare[period]` keyed by epoch / "
        "period. When the updater takes an early-return branch on `reward == 0`, "
        "it never writes the cache for the current period, so any later read for "
        "that period returns an uninitialised zero instead of forward-carrying the "
        "previous accumulator. Stakers reading the period miss intermediate "
        "rewards or hit divide-by-zero downstream. Reported in Ramses M-01."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
mapping(uint256 => uint256) public accRewardPerShare;
uint256 public currentPeriod;

function updateReward(uint256 reward, uint256 totalStaked) external {
    if (reward == 0) return;             // BUG: cache for currentPeriod not written
    accRewardPerShare[currentPeriod] += reward * 1e18 / totalStaked;
}
```
1. Period N opens; no rewards distributed (`reward == 0`) - updater early-returns.
2. Later, period N+1 reads `accRewardPerShare[N]`. It returns 0.
3. Forward-carry of the previous accumulator is broken; reward maths drift."""
    WIKI_RECOMMENDATION = (
        "Either remove the early-return on zero, or first forward-carry the "
        "previous period's accumulator: "
        "`accRewardPerShare[currentPeriod] = accRewardPerShare[currentPeriod-1];` "
        "before exiting."
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
                if not _FN_NAME_RE.search(function.name or ""):
                    continue
                if not _function_writes_period_accumulator(function):
                    continue
                if not _has_zero_guard_early_return(function):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " early-returns on a (reward == 0) guard without writing "
                    "the period accumulator. The current period's cache is "
                    "left at the default zero and forward-carry breaks.\n",
                ]
                results.append(self.generate_result(info))

        return results
