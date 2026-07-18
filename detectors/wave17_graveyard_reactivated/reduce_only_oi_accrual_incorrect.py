"""
reduce_only_oi_accrual_incorrect.py - Custom Slither detector.

Pattern (GTE-perps M-08 / slice_ac):
    A perps order/position function increments an open-interest state
    variable (`totalOI`, `openInterest`, ...) on every new position -
    including REDUCE-ONLY orders that are closing existing exposure
    rather than adding new. OI gets double-counted on closeouts; risk
    metrics, funding-rate calculations, and OI caps are corrupted.

Detection strategy:
    1. For each non-vendored contract, find functions whose name matches
       `(?i)(openposition|placeorder|updateoi|fillorder|matchorder)` and
       which take a boolean parameter named like `reduceonly` /
       `isreduceonly` / `closeonly`.
    2. Inside the function body, find a Binary +/+= write to a state var
       whose name matches `(?i)(openinterest|totaloi|^oi$|grossoi)`.
    3. Flag if the OI write node is NOT inside any `if` that reads the
       reduceOnly param (best-effort: the function contains the increment
       and the function does NOT contain any `if` node whose
       solidity/local variables include `reduceOnly`).

@author auditooor wave9
@pattern GTE-perps M-08 / slice_ac
"""

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

import re

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.core.cfg.node import NodeType
from slither.core.solidity_types import ElementaryType
from slither.core.variables.state_variable import StateVariable
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_FN_NAME_RE = re.compile(
    r"(openposition|placeorder|updateoi|fillorder|matchorder|increasepos|opentrade)",
    re.IGNORECASE,
)
_OI_NAME_RE = re.compile(
    r"(openinterest|totaloi|^oi$|grossoi|netoi|positionsize)",
    re.IGNORECASE,
)
_REDUCE_PARAM_NAMES = {
    "reduceonly", "isreduceonly", "closeonly", "iscloseonly", "isreducing", "reduce"
}


def _find_reduce_only_param(function):
    for p in function.parameters:
        nm = (p.name or "").lower()
        t = getattr(p, "type", None)
        if isinstance(t, ElementaryType) and t.name == "bool" and nm in _REDUCE_PARAM_NAMES:
            return p
    return None


def _writes_oi_var(function):
    matches = []
    for sv in function.state_variables_written:
        if isinstance(sv, StateVariable) and _OI_NAME_RE.search(sv.name or ""):
            matches.append(sv)
    return matches


def _function_branches_on_reduce(function, reduce_param) -> bool:
    """Return True if any IF node in the function reads reduce_param."""
    for node in function.nodes:
        if node.type != NodeType.IF:
            continue
        if reduce_param in node.local_variables_read:
            return True
        # reduce_param.name may also appear via parameter alias; fall through
    return False


class ReduceOnlyOiAccrualIncorrect(AbstractDetector):
    """OI accrual ignores reduceOnly flag - double-counts close-out positions."""

    ARGUMENT = "reduce-only-oi-accrual-incorrect"
    HELP = (
        "openPosition / placeOrder writes openInterest unconditionally "
        "while accepting a reduceOnly bool - closeouts double-count OI"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Reduce-Only OI Accrual Incorrect"
    WIKI_DESCRIPTION = (
        "A perps order/position function takes a `reduceOnly` boolean "
        "(meaning the order may only CLOSE existing exposure, never open "
        "new) and yet unconditionally increments the open-interest state "
        "variable. Reduce-only fills are double-counted: they consume "
        "existing OI (via the position's own size) AND inflate the total. "
        "Risk metrics, funding-rate calculations, and OI caps are all "
        "corrupted. Reported in GTE-perps M-08."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
uint256 public totalOI;
function openPosition(uint256 size, bool reduceOnly) external {
    totalOI += size;  // reduceOnly ignored
    // ...
}
```
1. Alice opens a 100-size LONG → totalOI = 100.
2. Alice fills a 100-size reduceOnly SHORT to close → totalOI = 200.
3. Pool reads totalOI=200 and triggers OI-cap risk shutdown."""
    WIKI_RECOMMENDATION = (
        "Wrap the OI write in `if (!reduceOnly) { totalOI += size; }`, or "
        "subtract from OI on reduceOnly fills."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions_declared:
                if function.is_constructor:
                    continue
                if function.view or function.pure:
                    continue
                if function.visibility not in ("public", "external", "internal"):
                    continue
                if not _FN_NAME_RE.search(function.name or ""):
                    continue

                reduce_param = _find_reduce_only_param(function)
                if reduce_param is None:
                    continue

                oi_writes = _writes_oi_var(function)
                if not oi_writes:
                    continue

                # Function branches on reduceOnly anywhere → consider safe.
                if _function_branches_on_reduce(function, reduce_param):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " writes open-interest state variable ",
                    oi_writes[0],
                    f" while accepting a `{reduce_param.name}` bool, but "
                    "never branches on it - reduce-only orders that "
                    "CLOSE exposure are double-counted into total OI.\n",
                ]
                results.append(self.generate_result(info))

        return results
