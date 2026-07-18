"""
reentrancy_eth_refund_before_debt_update.py - Custom Slither detector.

Pattern (Sumer Money 2024-04 - $350K, Compound-fork variant):
    `repayBorrow{value: amount}` / `mint{value: amount}` functions that
    refund excess ETH back to `msg.sender` via `.call{value: refund}("")`
    BEFORE decrementing `totalBorrows` / updating the exchange-rate state.
    The refund hook re-enters the market (or a sibling market) while the
    debt state is still stale, letting the attacker observe an inflated
    `exchangeRate` (getCash grew, totalBorrows unchanged) and borrow
    against the miscalculated collateral before the original call
    finishes.

Compound's canonical `repayBorrowFresh` decrements `totalBorrows` BEFORE
any external call. Forks that rearranged CEI - often as a 'gas
optimization' - reintroduced this class.

Detection strategy:
    1. Iterate external/public functions whose name matches
       `repay|mint|redeem|supply|liquidate`.
    2. Require the function is `payable` OR calls `msg.value`.
    3. Walk the function's IR linearly, ordered by node id. Track
       whether a low-level `.call{value: ...}` / `.transfer` / `.send`
       to `msg.sender` (or any address) happens BEFORE a write to a
       state var whose name contains `total`, `borrow`, `debt`,
       `exchange`, `index`, or `reserve`.
    4. Flag only when the ETH send is observed before ALL such writes.
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
from slither.slithir.operations import LowLevelCall, Transfer, Send
from slither.utils.output import Output


_NAME_RE = re.compile(
    r"^(repay|mint|redeem|supply|liquidate|borrow|refund)",
    re.IGNORECASE,
)
_DEBT_STATE_FRAGMENTS = (
    "total",
    "borrow",
    "debt",
    "exchangerate",
    "exchange_rate",
    "cash",
    "reserve",
    "index",
    "accrual",
)

SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")


def _is_eth_send_ir(ir) -> bool:
    """True if IR is a low-level ETH-sending call / transfer / send."""
    if isinstance(ir, (Transfer, Send)):
        return True
    if isinstance(ir, LowLevelCall):
        # call{value: X}
        call_value = getattr(ir, "call_value", None)
        if call_value is not None:
            return True
    return False


def _is_debt_state_write(ir_node) -> bool:
    """True if the given node writes to a state variable whose name
    contains one of the debt-state fragments."""
    for sv in ir_node.state_variables_written:
        name = (sv.name or "").lower()
        if any(frag in name for frag in _DEBT_STATE_FRAGMENTS):
            return True
    return False


class ReentrancyEthRefundBeforeDebtUpdate(AbstractDetector):
    """Detect repay/mint functions that refund ETH before updating debt state."""

    ARGUMENT = "reentrancy-eth-refund-before-debt-update"
    HELP = (
        "repay/mint payable function refunds ETH to msg.sender BEFORE "
        "decrementing totalBorrows / updating exchangeRate"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "ETH Refund Before Debt State Update"
    WIKI_DESCRIPTION = (
        "Compound-fork money markets that accept native ETH for repayments "
        "or mints must decrement `totalBorrows` (and update the stored "
        "exchange-rate components) BEFORE returning any excess ETH to the "
        "caller. Sending ETH first creates a reentrancy window in which "
        "the market observes stale debt: `getCash()` has already grown "
        "from the incoming msg.value, but `totalBorrows` has not yet been "
        "reduced, so `exchangeRate = (cash + borrows - reserves)/supply` "
        "is inflated. An attacker exploits this by borrowing against a "
        "sibling market that reads the same exchange rate. See Sumer "
        "Money 2024-04 (~$350K)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function repayBorrowBehalf(address borrower) external payable {
    uint256 repayAmount = borrowBalanceStored(borrower);
    uint256 refund = msg.value - repayAmount;
    (bool ok,) = msg.sender.call{value: refund}("");  // refund FIRST
    require(ok);
    totalBorrows -= repayAmount;                       // state AFTER
    accountBorrows[borrower].principal = 0;
}
```
During the refund callback the attacker re-enters a sibling market
whose `exchangeRateStored()` reads the still-stale `totalBorrows` and
`getCash()` - the inflated exchange rate is used to mint/borrow
more than the collateral actually supports."""
    WIKI_RECOMMENDATION = (
        "Follow strict CEI: decrement `totalBorrows`, update the stored "
        "exchange-rate components, then refund ETH. Also add a "
        "`nonReentrant` modifier that guards both `mint` and `repay`."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in (contract.name or "").lower() for k in SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                if function.is_constructor:
                    continue
                if function.visibility not in ("external", "public"):
                    continue
                if not _NAME_RE.match(function.name or ""):
                    continue
                if not function.payable:
                    continue

                # Walk nodes in source order.
                eth_send_node = None
                debt_write_node = None
                for node in function.nodes:
                    # Check ETH send in this node's IRs.
                    if eth_send_node is None:
                        for ir in node.irs:
                            if _is_eth_send_ir(ir):
                                eth_send_node = node
                                break
                    # Check debt state write in this node.
                    if _is_debt_state_write(node) and debt_write_node is None:
                        debt_write_node = node

                if eth_send_node is None or debt_write_node is None:
                    continue
                # Need: ETH send occurs BEFORE debt write.
                if eth_send_node.node_id >= debt_write_node.node_id:
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " sends ETH at ",
                    eth_send_node,
                    " before updating debt state at ",
                    debt_write_node,
                    " - reentrancy window lets an attacker observe an "
                    "inflated exchange rate (getCash grew, totalBorrows "
                    "unchanged) and borrow against the manipulated value. "
                    "Follow strict CEI: update totalBorrows first.\n",
                ]
                results.append(self.generate_result(info))

        return results
