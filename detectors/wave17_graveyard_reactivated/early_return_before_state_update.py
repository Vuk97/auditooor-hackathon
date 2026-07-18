"""
early_return_before_state_update.py - Custom Slither detector.

Pattern: A distributor / reward / accrual function takes an early `return`
inside a top-level `if (...)` branch. AFTER the early return, the function
writes critical bookkeeping state (e.g. `lastUpdateTime`,
`accumulatedPerShare`, `index`, `cumulativeReward`). The early-return branch
inadvertently skips the bookkeeping update - so on the next call the
bookkeeping variable is stale and the elapsed-time / accrual calculation is
wrong (typically double-counting or zero-counting).

Source: Morpheus M-04 (slice_ad).

Detection (CFG-based):
    1. Walk every function (non-view, non-pure, non-constructor).
    2. For each function, locate the FIRST RETURN node (if any).
    3. Determine the set of state-variable names written by nodes BEFORE
       the return and the set written AFTER the return.
    4. Filter "after" writes to only bookkeeping-style names:
       (last|cumulative|index|accumulated|updatedAt).
    5. If those bookkeeping vars are NOT also in the "before" set, flag -
       the early-return branch skipped them.

Confidence: MEDIUM. We only flag when the early-return precedes a write
to a bookkeeping-named state var that is not also written before the return.

@author auditooor wave9
"""

import re
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.core.cfg.node import NodeType
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "deploy", "script", "setup")

_BOOKKEEPING_RE = re.compile(
    r"(lastupdate|updatedat|lasttime|lastclaim|lastaccrue|cumulative|"
    r"globalindex|accindex|lastsync|lastrebase)",
    re.IGNORECASE,
)


def _looks_like_bookkeeping(sv_name: str) -> bool:
    return bool(_BOOKKEEPING_RE.search(sv_name or ""))


class EarlyReturnBeforeStateUpdate(AbstractDetector):
    """Detect early returns that skip critical bookkeeping state writes."""

    ARGUMENT = "early-return-before-state-update"
    HELP = (
        "Function takes an early return inside an if-branch, and bookkeeping "
        "state variables are written only AFTER that return - the early "
        "branch skips the update"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Early Return Skips Bookkeeping State Update"
    WIKI_DESCRIPTION = (
        "A distributor or reward-accrual function uses an `if (cond) return;` "
        "early-exit pattern that bypasses critical bookkeeping state writes "
        "(`lastUpdateTime`, `accumulatedPerShare`, `index`, "
        "`cumulativeReward`) located later in the function body. On the "
        "early-return branch the bookkeeping is left stale, so the next call "
        "computes elapsed time / accrual from the wrong baseline. "
        "Source: Morpheus M-04 (slice_ad)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
uint256 public lastUpdateTime;
uint256 public accumulatedPerShare;

function distribute() external {
    uint256 elapsed = block.timestamp - lastUpdateTime;
    uint256 reward  = elapsed * 1e18;
    if (reward == 0) {
        return;                       // BUG: lastUpdateTime not refreshed
    }
    lastUpdateTime = block.timestamp;
    accumulatedPerShare += reward;
}
```
1. Call `distribute()` rapidly so `elapsed * 1e18 == 0` (e.g. same block).
2. The function returns without updating `lastUpdateTime`.
3. Some blocks later, the *next* call computes elapsed from the OLD
   timestamp - but the value of `1e18` per second has now compounded. Total
   reward differs from the linearly-accrued amount."""
    WIKI_RECOMMENDATION = (
        "Move the bookkeeping state write (e.g. `lastUpdateTime = "
        "block.timestamp`) BEFORE the early return, or refactor the function "
        "to always update bookkeeping in a `_sync()` helper that runs first."
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

                nodes = list(function.nodes)
                # Find the first RETURN node (the early-return).
                return_idx = None
                for idx, n in enumerate(nodes):
                    if n.type == NodeType.RETURN:
                        return_idx = idx
                        break
                if return_idx is None:
                    continue
                # Need at least one IF node before the return - otherwise
                # this is just the function's terminal return, not an early
                # exit guarded by a condition.
                has_if_before = any(
                    n.type == NodeType.IF for n in nodes[:return_idx]
                )
                if not has_if_before:
                    continue
                # Need at least one node after the return that is not pure
                # control flow (otherwise the return is at the bottom).
                tail = nodes[return_idx + 1:]
                if not any(n.type not in (NodeType.ENDIF, NodeType.ENDLOOP) for n in tail):
                    continue

                pre_writes = set()
                for n in nodes[:return_idx]:
                    for sv in n.state_variables_written:
                        if sv.name:
                            pre_writes.add(sv.name)

                post_bookkeeping_writes = set()
                bookkeeping_svs = {}
                for n in tail:
                    for sv in n.state_variables_written:
                        if sv.name and _looks_like_bookkeeping(sv.name):
                            post_bookkeeping_writes.add(sv.name)
                            bookkeeping_svs[sv.name] = sv

                # Skipped bookkeeping = post-bookkeeping writes that are not
                # also done before the early return.
                skipped = post_bookkeeping_writes - pre_writes
                if not skipped:
                    continue

                missing_sv = bookkeeping_svs[next(iter(skipped))]
                info: DETECTOR_INFO = [
                    function,
                    " in ",
                    contract,
                    " takes an early return inside an if-branch but writes "
                    "bookkeeping state variable ",
                    missing_sv,
                    " (and possibly others: {",
                    ", ".join(sorted(skipped)),
                    "}) only AFTER the return. The early-exit branch leaves "
                    "this state stale, so the next call computes accrual "
                    "from a wrong baseline.\n",
                ]
                results.append(self.generate_result(info))

        return results
