"""
withdraw_index_off_by_one.py - Custom Slither detector.

Pattern (Zellic slice_ad - Chateau WithdrawIndexBug, CRITICAL):
    A withdrawal or swap entrypoint uses an "end" / "next" pointer as a
    post-increment counter: it points to the next slot to be filled, not
    the last slot written. On withdraw, the contract sets
        indexStar = indexEnd;
    which intends "mark all filled slots consumed". But because `indexEnd`
    points one past the last filled slot, the first post-withdraw stake
    (which lands at the old `indexEnd`) is permanently skipped by both
    the unstake and the swap iteration - funds are orphaned.

Detection strategy:
    1. Walk contracts. For each function whose name contains a withdraw /
       redeem / exit / settle hint, inspect its nodes.
    2. Find Assignment IRs where:
         - lvalue is a StateVariable whose name matches "index" hints
           (indexStar, indexStart, indexHead, startIndex, headIndex, ...)
         - rvalue is a StateVariable whose name matches an opposing
           "end" hint (indexEnd, tailIndex, endIndex, nextIndex, ...)
    3. Require that the assignment has NO subtraction / decrement on the
       RHS - a correct fix is `indexStar = indexEnd - 1`. The presence of
       a Binary SUBTRACTION IR in the SAME node suppresses the finding.

@author auditooor wave11
@pattern slice_ad Chateau WithdrawIndexBug
"""

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import Assignment, Binary, BinaryType
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_FUNCTION_HINTS = (
    "withdraw",
    "redeem",
    "exit",
    "settle",
    "unstake",
    "swap",
)

# "Start" / "head" / "begin" pointers (the one being WRITTEN).
_START_HINTS = (
    "indexstar",
    "indexstart",
    "startindex",
    "headindex",
    "indexhead",
    "beginindex",
    "indexbegin",
    "firstindex",
    "indexfirst",
)

# "End" / "tail" / "next" pointers (the one being READ and potentially
# one-past-the-end).
_END_HINTS = (
    "indexend",
    "endindex",
    "tailindex",
    "indextail",
    "nextindex",
    "indexnext",
    "lastindex",
    "indexlast",
)


def _matches_hint(name, hints):
    if not name:
        return False
    nm = name.lower()
    return any(h in nm for h in hints)


def _node_has_subtraction(node):
    for ir in node.irs:
        if isinstance(ir, Binary) and ir.type == BinaryType.SUBTRACTION:
            return True
    return False


class WithdrawIndexOffByOne(AbstractDetector):
    """Detect start-pointer = end-pointer assignment in withdraw flow."""

    ARGUMENT = "withdraw-index-off-by-one"
    HELP = (
        "Withdraw function sets start-index := end-index where end is a "
        "next-to-fill pointer - first post-withdraw slot is orphaned"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Start-Index = End-Index Off-By-One in Withdraw Flow"
    WIKI_DESCRIPTION = (
        "Queue-backed staking / swap contracts typically keep two index "
        "variables: `indexStart` (or `head`) marking the oldest unconsumed "
        "slot, and `indexEnd` (or `tail`) marking the NEXT slot to be filled. "
        "When withdraw / settle code sets `indexStart = indexEnd` it intends "
        "to mark every filled slot consumed - but because `indexEnd` points "
        "one past the last filled slot, the first post-withdraw deposit lands "
        "at the exact index the contract now considers 'already consumed', "
        "permanently orphaning those funds. The canonical Chateau bug."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
uint256 public indexStar;   // oldest unconsumed (head)
uint256 public indexEnd;    // next to fill (tail, post-increment)

function stake(uint256 amt) external {
    stakes[indexEnd] = amt;
    indexEnd += 1;
}

function withdraw() external onlyOwner {
    // BUG: end is the next-to-fill slot; this skips the first
    // post-withdraw stake forever.
    indexStar = indexEnd;
}
```
1. Owner withdraws → `indexStar = indexEnd = 5` (say).
2. Alice stakes → `stakes[5] = 1e18`, `indexEnd = 6`.
3. Swap iterates from `indexStar (5)` but the function reads
   `<` not `<=` → Alice's stake at index 5 is permanently skipped."""
    WIKI_RECOMMENDATION = (
        "When `indexEnd` is a post-increment (next-to-fill) pointer, fix "
        "with `indexStar = indexEnd - 1` or rework the loop bounds to use "
        "`indexStart ... indexEnd` exclusive of both, or re-align indexEnd "
        "to the last-filled slot."
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
                if function.view or function.pure:
                    continue
                nm = (function.name or "").lower()
                if not any(h in nm for h in _FUNCTION_HINTS):
                    continue

                for node in function.nodes:
                    if _node_has_subtraction(node):
                        continue
                    for ir in node.irs:
                        if not isinstance(ir, Assignment):
                            continue
                        lv = ir.lvalue
                        rv = ir.rvalue
                        if not isinstance(lv, StateVariable):
                            continue
                        if not isinstance(rv, StateVariable):
                            continue
                        if not _matches_hint(lv.name, _START_HINTS):
                            continue
                        if not _matches_hint(rv.name, _END_HINTS):
                            continue

                        info: DETECTOR_INFO = [
                            function,
                            " sets ",
                            lv,
                            " := ",
                            rv,
                            " at ",
                            node,
                            " without decrementing. If the end-pointer is a "
                            "post-increment (next-to-fill) the first post-"
                            "withdraw slot is permanently orphaned.\n",
                        ]
                        results.append(self.generate_result(info))

        return results
