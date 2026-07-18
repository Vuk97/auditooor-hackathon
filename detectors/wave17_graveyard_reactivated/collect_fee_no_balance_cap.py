"""
collect_fee_no_balance_cap.py - Custom Slither detector.

Pattern (BendDAO M-02, slice_ab): A `collectFee*` / `claimFee*` /
`withdrawFee*` function transfers a stored fee counter (e.g. `totalFees`,
`reserveFees`, `protocolFees`) to a treasury without capping the amount by
the actual token balance of the contract. When outstanding loans or
in-flight redemptions temporarily reduce the contract's balance below the
accounting counter, the transfer either reverts (DoS) or siphons funds
earmarked for other claimants.

Detection strategy:
    1. Find external/public functions whose lowercased name matches
       `(collect|claim|withdraw).*fee`.
    2. The function must include a HighLevelCall to
       `transfer(address,uint256)` OR `safeTransfer(address,uint256)`.
    3. The function must NOT contain any HighLevelCall to `balanceOf`
       (the proxy for the `min(fee, balance)` cap). This single check
       captures both the "if (amt > balanceOf(...)) amt = bal;" and the
       "balanceOf(...) >= amt" styles.
    4. The function must read at least one non-constant state variable
       (the fee counter).
    5. Flag.

@author auditooor wave11
@pattern slice_ab BendDAO M-02 collectFeeToTreasury balance vs. claim
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
from slither.core.declarations import Function
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import HighLevelCall
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")
_FN_NAME_RE = re.compile(r"(collect|claim|withdraw).*fee", re.IGNORECASE)
_TRANSFER_SIGS = frozenset({
    "transfer(address,uint256)",
    "safeTransfer(address,uint256)",
})


class CollectFeeNoBalanceCap(AbstractDetector):
    """collectFee/claimFee transfers a counter without capping by actual balance."""

    ARGUMENT = "collect-fee-no-balance-cap"
    HELP = (
        "collectFee/claimFee transfers a stored fee counter without calling "
        "balanceOf - reverts on shortfalls or siphons funds earmarked elsewhere"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Fee Collector Missing Balance Cap"
    WIKI_DESCRIPTION = (
        "A fee-collection function transfers a stored accrual counter to "
        "the treasury without capping the transfer by `token.balanceOf("
        "address(this))`. When the contract's liquid balance is below the "
        "counter (outstanding loans, in-flight redemptions, depositor "
        "queue, etc.), the transfer either reverts (DoS) or drains funds "
        "earmarked for other claimants. Reported in BendDAO M-02."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function collectFeeToTreasury() external onlyOwner {
    uint256 amt = totalFees;
    totalFees = 0;
    token.transfer(treasury, amt);   // BUG: may revert or overdraw
}
```
If outstanding borrows / withdrawals drop the pool balance below
`totalFees`, any attempt to call this function reverts and fees become
stuck, or - in pooled-liquidity settings - the transfer succeeds but
silently drains funds that belong to depositors."""
    WIKI_RECOMMENDATION = (
        "Cap the transferred amount: `amt = min(amt, token.balanceOf("
        "address(this)));` before decrementing the counter and pushing "
        "the funds to the treasury."
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
                if function.visibility not in ("public", "external"):
                    continue
                if not function.name or not _FN_NAME_RE.search(function.name):
                    continue

                # Must read at least one non-const state var (the counter).
                counter_reads = [
                    v for v in (function.state_variables_read or [])
                    if isinstance(v, StateVariable)
                    and not getattr(v, "is_constant", False)
                    and not getattr(v, "is_immutable", False)
                ]
                if not counter_reads:
                    continue

                # Require a transfer / safeTransfer call.
                transfer_node = None
                has_balanceof = False
                for node in function.nodes:
                    for ir in node.irs:
                        if not isinstance(ir, HighLevelCall):
                            continue
                        callee = getattr(ir, "function", None)
                        if not isinstance(callee, Function):
                            continue
                        nm = getattr(callee, "name", "") or ""
                        if nm == "balanceOf":
                            has_balanceof = True
                            continue
                        sig = getattr(callee, "solidity_signature", None)
                        if sig in _TRANSFER_SIGS and transfer_node is None:
                            transfer_node = node
                if transfer_node is None:
                    continue
                if has_balanceof:
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " transfers fee counter to treasury at ",
                    transfer_node,
                    " without calling `balanceOf(address(this))` first - "
                    "the transfer reverts on shortfall (DoS) or pulls funds "
                    "earmarked for other claimants.\n",
                ]
                results.append(self.generate_result(info))

        return results
