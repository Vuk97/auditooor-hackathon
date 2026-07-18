"""
trade_index_reuse_first_empty.py - Custom Slither detector.

Pattern (Zellic slice_ad - Bloom Trading TradeIndexReuse, HIGH):
    `openTrade` / `storeTrade` style functions assign a trade to the first
    EMPTY slot of a storage array using a helper named
    `firstEmptyTradeIndex` (or `findEmpty*Slot`). Because the same index
    is reused once a prior trade closes, a pending async callback that
    stored `tradeId = 17` can land on a DIFFERENT freshly-opened trade at
    index 17, causing cross-trade state overwrites and operator griefing.

    The correct fix is a monotonically-increasing counter: `nextId += 1;
    trades[nextId] = ...;`

Detection strategy:
    1. For each contract, find internal functions whose name contains any
       of the "empty-search" hints: firstempty, findempty, nextempty,
       emptyslot, emptyindex, nextfreeindex, firstfreeindex.
    2. These helpers must have a loop iterating over a storage array and
       return an index. We approximate "is a search helper" by the name
       alone - the pattern is specific enough.
    3. For each PUBLIC function that CALLS one of these helpers, check
       that the contract has NO state variable whose name contains a
       monotonic-counter hint (nextId, trade_counter, tradeNonce,
       totaltrades, tradescount, numtrades).
    4. If the helper is called AND no monotonic counter exists → flag.

@author auditooor wave11
@pattern slice_ad Bloom Trading TradeIndexReuse
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
from slither.core.declarations import Function
from slither.slithir.operations import InternalCall
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_EMPTY_SEARCH_HINTS = (
    "firstempty",
    "findempty",
    "nextempty",
    "emptyslot",
    "emptyindex",
    "nextfree",
    "firstfree",
    "findfree",
    "findslot",
)

_MONOTONIC_COUNTER_HINTS = (
    "nextid",
    "nexttradeid",
    "tradenonce",
    "tradecounter",
    "numtrades",
    "totaltrades",
    "tradescount",
    "_tradecounter",
    "tradesequence",
    "lasttradeid",
    "nextorderid",
    "ordercounter",
    "numorders",
    "orderid",
)


def _name_matches(name, hints):
    if not name:
        return False
    nm = name.lower().replace("_", "")
    return any(h in nm for h in hints)


def _contract_has_monotonic_counter(contract) -> bool:
    for sv in contract.state_variables:
        if _name_matches(sv.name, _MONOTONIC_COUNTER_HINTS):
            return True
    return False


def _function_calls_empty_search(function):
    """Return the callee Function object (or None) if this function calls
    an internal helper whose name matches the empty-search hints."""
    for ir in function.all_slithir_operations():
        if not isinstance(ir, InternalCall):
            continue
        callee = ir.function
        if not isinstance(callee, Function):
            continue
        if _name_matches(callee.name, _EMPTY_SEARCH_HINTS):
            return callee
    return None


class TradeIndexReuseFirstEmpty(AbstractDetector):
    """Detect trade/order creation using first-empty-slot search with no monotonic counter."""

    ARGUMENT = "trade-index-reuse-first-empty"
    HELP = (
        "Trade/order opened via firstEmpty* slot search while contract has "
        "no monotonic counter - callback can match a different trade"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Trade Index Reuse via First-Empty-Slot Search"
    WIKI_DESCRIPTION = (
        "Perpetual / margin platforms that store pending trades in a "
        "fixed-size mapping sometimes assign new trades to the first "
        "'empty' slot returned by a helper such as `firstEmptyTradeIndex`. "
        "Since the index is reused as soon as a prior trade closes, a "
        "pending async callback that captured `tradeId = 17` can land on a "
        "DIFFERENT freshly-opened trade at the same index. The correct "
        "pattern is a monotonically-increasing counter (nextTradeId++). "
        "Reported in Bloom Trading (Zellic)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function openTrade(Trade memory t) external {
    uint256 idx = firstEmptyTradeIndex(msg.sender);   // BUG
    trades[msg.sender][idx] = t;
    _requestPriceCallback(msg.sender, idx);
}
```
1. Alice opens trade → idx = 17, callback scheduled.
2. Alice closes trade 17 → slot freed.
3. Alice opens a new trade → idx = 17 again.
4. Original callback fires against NEW trade 17 → wrong state applied."""
    WIKI_RECOMMENDATION = (
        "Use a monotonically-increasing `nextTradeId` counter so each "
        "trade has a globally unique id; never reuse an index across "
        "trade lifecycles. Existing async callbacks referring to a closed "
        "trade should no-op against the new id."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            if _contract_has_monotonic_counter(contract):
                continue

            for function in contract.functions_and_modifiers_declared:
                if function.is_constructor:
                    continue
                if function.view or function.pure:
                    continue

                helper = _function_calls_empty_search(function)
                if helper is None:
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " assigns a trade/order using ",
                    helper,
                    " (first-empty-slot search) while ",
                    contract,
                    " has no monotonic counter - callbacks referencing a "
                    "prior trade at the same slot can land on a new trade.\n",
                ]
                results.append(self.generate_result(info))

        return results
