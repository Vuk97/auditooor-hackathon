"""
self_liquidation_profitable.py - Custom Slither detector.

Pattern (DittoETH H-04, LoopFi slice_aa P49): An external `liquidate*`
function receives `borrower` / `user` as a parameter and pays the liquidation
bonus to `msg.sender`, but never requires that `msg.sender != borrower`. A
borrower can deliberately let their position become unhealthy and self-
liquidate to pocket the bonus risk-free.

Detection strategy:
    1. Iterate every non-vendored contract.
    2. Find external/public functions whose name (lowercased) starts with
       "liquidate".
    3. Inspect the parameter list for one whose name matches
       "borrower" / "user" / "account" / "victim".
    4. Walk every node containing a require/assert/if and look for a Binary
       NOT_EQUAL where one operand is `msg.sender` (SolidityVariable
       msg.sender) and the other operand is the borrower-named parameter.
    5. If the parameter exists and the guard is missing → flag the function.

@author auditooor wave9
@pattern slice_aa P49 / DittoETH H-04 / LoopFi
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
from slither.slithir.operations import Binary, BinaryType
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_BORROWER_PARAM_NAMES = ("borrower", "user", "account", "victim", "target", "debtor")


def _find_borrower_param(function):
    for p in function.parameters:
        if (p.name or "").lower() in _BORROWER_PARAM_NAMES:
            type_str = str(getattr(p, "type", "")).lower()
            if "address" in type_str:
                return p
    return None


def _has_self_neq_check(function, borrower_param) -> bool:
    """Look for require(msg.sender != borrower) in the function body."""
    for node in function.nodes:
        if not (node.contains_require_or_assert() or node.contains_if()):
            continue
        # Quick filter: node must read msg.sender AND the borrower local var.
        sender_read = any(
            (sv.name or "") == "msg.sender"
            for sv in node.solidity_variables_read
        )
        if not sender_read:
            continue
        if borrower_param not in node.local_variables_read:
            continue
        # Look for a NOT_EQUAL binary IR on this node.
        for ir in node.irs:
            if isinstance(ir, Binary) and ir.type == BinaryType.NOT_EQUAL:
                return True
    return False


class SelfLiquidationProfitable(AbstractDetector):
    """Flag liquidate() functions that allow msg.sender == borrower."""

    ARGUMENT = "self-liquidation-profitable"
    HELP = (
        "liquidate(borrower) does not require(msg.sender != borrower) - "
        "borrower can self-liquidate and pocket the bonus risk-free"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Profitable Self-Liquidation"
    WIKI_DESCRIPTION = (
        "A liquidation function pays a bonus to `msg.sender` while accepting "
        "the borrower address as a parameter, but never requires that the "
        "caller is a third party. Reported in DittoETH H-04 and LoopFi: a "
        "borrower opens a deliberately unhealthy position, calls `liquidate` "
        "on themselves, and extracts the liquidation bonus as a profit, "
        "effectively minting value out of the protocol's penalty pot."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function liquidate(address borrower, uint256 repayAmount) external {
    uint256 bonus = repayAmount * 110 / 100;
    debts[borrower] -= repayAmount;
    payments[msg.sender] += bonus;       // bonus to caller
    // BUG: no require(msg.sender != borrower)
}
```
1. Attacker opens a position and lets it cross the liquidation line.
2. Attacker calls `liquidate(attacker, repayAmount)` - bonus goes to attacker.
3. Net effect: attacker repays X and receives 1.1*X, draining the bonus pool."""
    WIKI_RECOMMENDATION = (
        "Add `require(msg.sender != borrower, \"self-liquidation\");` at the top "
        "of the liquidation function so a borrower cannot pay themselves the "
        "liquidation incentive."
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
                if not (function.name or "").lower().startswith("liquidate"):
                    continue

                borrower_param = _find_borrower_param(function)
                if borrower_param is None:
                    continue

                if _has_self_neq_check(function, borrower_param):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " accepts borrower parameter ",
                    borrower_param,
                    " but does not require msg.sender != borrower - borrower "
                    "can self-liquidate and pocket the liquidation bonus.\n",
                ]
                results.append(self.generate_result(info))

        return results
