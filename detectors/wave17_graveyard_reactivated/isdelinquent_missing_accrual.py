"""
isdelinquent_missing_accrual.py - Custom Slither detector.

Pattern: A debt-health check function (e.g. `_isDelinquent`, `_isHealthy`,
`_isLiquidatable`) reads `loan.amount` / `borrows[user]` / `debt[user]` WITHOUT
first calling an accrual function (`accrueInterest()`, `_updateIndex()`,
`sync()`). The loan appears healthy until someone independently triggers
accrual, at which point the borrower is already delinquent.

Source: Zellic slice_aa RFIN-26 (CRITICAL).

Detection:
    1. Find functions whose name matches (case-insensitive) one of:
       isdelinquent, ishealthy, isliquidatable, checkhealth.
    2. The function must read a state variable whose name suggests debt
       balance (loan, loans, borrow, borrows, debt, debts) OR read a local
       variable field named `amount` (for `loan.amount`).
    3. Function must NOT contain an internal or HighLevelCall to any function
       whose name matches accrue.*/updateIndex/sync.*.
    4. If (1) and (2) hold and (3) is absent → flag.

Confidence: MEDIUM. Name-based match on both health function and accrue
helper. Protocols using bespoke names may produce FNs; the common Compound /
Morpho / lending vernacular covers most cases.
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
from slither.slithir.operations import InternalCall, HighLevelCall
from slither.utils.output import Output


SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")

_HEALTH_FN_RE = re.compile(
    r'(isdelinquent|ishealthy|isliquidatable|checkhealth)',
    re.IGNORECASE,
)

_ACCRUE_CALL_RE = re.compile(
    r'(accrue|updateindex|_updateindex|sync)',
    re.IGNORECASE,
)

_DEBT_VAR_RE = re.compile(
    r'^(loan|loans|borrow|borrows|debt|debts|borrowbalance|borrowbalances)$',
    re.IGNORECASE,
)


def _reads_debt_state(function) -> bool:
    """Return True if function reads a state var whose name looks like debt accounting."""
    for sv in function.state_variables_read:
        if _DEBT_VAR_RE.match(sv.name or ""):
            return True
    return False


def _calls_accrue(function) -> bool:
    """Return True if function makes an internal or external call to an accrue-style fn."""
    for ir_node in function.nodes:
        for ir in ir_node.irs:
            if isinstance(ir, InternalCall):
                callee = getattr(ir, "function", None)
                if callee is None:
                    continue
                nm = getattr(callee, "name", "") or ""
                if _ACCRUE_CALL_RE.search(nm):
                    return True
            elif isinstance(ir, HighLevelCall):
                callee = getattr(ir, "function", None)
                if callee is None:
                    continue
                nm = getattr(callee, "name", "") or ""
                if _ACCRUE_CALL_RE.search(nm):
                    return True
    return False


class IsDelinquentMissingAccrual(AbstractDetector):
    """Detect debt-health checks that read loan state without first accruing interest."""

    ARGUMENT = "isdelinquent-missing-accrual"
    HELP = (
        "Debt-health check reads loan/borrow state without first calling "
        "accrueInterest/updateIndex - loan appears healthy until accrual runs"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Debt Health Check Missing Interest Accrual"
    WIKI_DESCRIPTION = (
        "Lending protocols track borrow amounts via a time-accruing index. A "
        "function that answers `isDelinquent(loan)` / `isHealthy(loan)` must "
        "first push the global index forward (via accrueInterest / updateIndex) "
        "before reading the loan amount, otherwise the comparison uses stale "
        "principal and silently classifies a delinquent loan as healthy. This "
        "blocks liquidations until another call happens to trigger accrual. "
        "Source: Zellic RFIN-26 (CRITICAL)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function _isHealthy(uint256 id) internal view returns (bool) {
    // BUG: loans[id].amount is stale - accrueInterest never called
    return loans[id].amount * 100 <= collaterals[id] * 80;
}
```
1. Borrower's position sits at the liquidation edge when accrued.
2. Liquidator calls a function that internally gates on `_isHealthy(id)`.
3. `_isHealthy` reads stale principal - returns true.
4. Liquidation reverts. Borrower remains unliquidated while bad debt grows."""
    WIKI_RECOMMENDATION = (
        "Call `accrueInterest()` / `_updateIndex(id)` at the top of any "
        "health-check function that reads debt state. Remove `view` if the "
        "accrual mutates state; callers can still use it by eth_call simulation."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                if function.is_constructor:
                    continue
                if not _HEALTH_FN_RE.search(function.name or ""):
                    continue
                if not _reads_debt_state(function):
                    continue
                if _calls_accrue(function):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " is a debt-health check that reads borrow/loan state "
                    "without first calling accrueInterest/_updateIndex. Stale "
                    "principal causes delinquent loans to appear healthy - "
                    "add an accrual call at the top of the function.\n",
                ]
                results.append(self.generate_result(info))

        return results
