"""
health_check_bypass_pay_interest.py — Custom Slither detector.

Pattern: A function decrements a collateral-backing mapping
(`accountTokens[user]`, `balances[user]`, `collateral[user]`) WITHOUT calling
a pre-reduction health hook such as `isRedeemAllowed` / `beforeRedeem` /
`checkHealth` / `redeemAllowed`. This lets borrowers spend collateral on
interest payments, bypassing the comptroller-level redeem check and
undercollateralising the position.

Source: Zellic slice_aa FNG-17 (CRITICAL).

Detection:
    1. Iterate functions (non-view, non-constructor, non-accrue helpers).
    2. Find nodes that write to a state-variable mapping whose name contains
       `account`, `balance`, or `collateral`.
    3. Check that the function contains at least one HighLevelCall to a fn
       whose name matches isRedeemAllowed / beforeRedeem / checkHealth /
       redeemAllowed / healthCheck / canRedeem (the health hook).
    4. If a qualifying write exists but no health-hook call → flag.

Confidence: MEDIUM. Name-based matching; we avoid flagging pure
mint/transfer by filtering out functions already containing a health hook
call ANYWHERE in their body (preceding or following).
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
from slither.slithir.operations import HighLevelCall, InternalCall
from slither.utils.output import Output


SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")

# Variable names (as full match, case-insensitive) whose decrement signals
# collateral reduction.
_COLLATERAL_VAR_RE = re.compile(
    r'(account|balance|collateral)',
    re.IGNORECASE,
)

_HEALTH_HOOK_RE = re.compile(
    r'(isredeemallowed|beforeredeem|checkhealth|redeemallowed|healthcheck|canredeem)',
    re.IGNORECASE,
)

# Skip these function names (they are the accrual / mint side, not an
# interest-payment path).
_SKIP_FN_NAMES = (
    "mint",
    "deposit",
    "_mint",
    "_deposit",
)


def _writes_collateral(function):
    """Return the first state var (written by function) that looks like a collateral mapping, else None."""
    for sv in function.state_variables_written:
        if sv.name and _COLLATERAL_VAR_RE.search(sv.name):
            # Only mapping-typed writes are interesting; the field may be a
            # direct scalar decrement too — accept either.
            return sv
    return None


def _calls_health_hook(function) -> bool:
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, (HighLevelCall, InternalCall)):
                callee = getattr(ir, "function", None)
                if callee is None:
                    continue
                nm = getattr(callee, "name", "") or ""
                if _HEALTH_HOOK_RE.search(nm):
                    return True
    return False


class HealthCheckBypassPayInterest(AbstractDetector):
    """Detect collateral decrements lacking a pre-reduction comptroller health hook."""

    ARGUMENT = "health-check-bypass-pay-interest"
    HELP = (
        "Function reduces accountTokens/balances/collateral without calling "
        "isRedeemAllowed/beforeRedeem — lets borrowers bypass the health check"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Collateral Decrement Bypasses Comptroller Health Hook"
    WIKI_DESCRIPTION = (
        "Compound-style lending markets protect collateral reductions by "
        "asking the comptroller `isRedeemAllowed(user, amount)` before "
        "lowering `accountTokens[user]`. A function that decrements a "
        "collateral-backing mapping (accountTokens, balances, collateral) "
        "without the hook allows a borrower to spend collateral on interest "
        "payments, liquidations, or fees, undercollateralising the position "
        "and bypassing the liquidation threshold. Source: Zellic FNG-17 "
        "(CRITICAL)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function payInterest(uint256 amount) external {
    // BUG: decrements accountTokens without comptroller.isRedeemAllowed()
    accountTokens[msg.sender] -= amount;
    totalInterest += amount;
}
```
1. Borrower's position is exactly on the liquidation edge.
2. Borrower calls `payInterest(amount)` — collateral balance drops.
3. No health hook runs, so the borrower can pay interest with collateral
   they should not be able to touch. Position is now under water but
   the accounting hides it from liquidators until the next accrual."""
    WIKI_RECOMMENDATION = (
        "Add `require(comptroller.isRedeemAllowed(msg.sender, amount))` "
        "(or the equivalent hook) BEFORE decrementing collateral-backing "
        "balances. Mirror Compound's CToken.redeemFresh implementation."
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
                if function.view or function.pure:
                    continue
                if function.visibility not in ("public", "external"):
                    continue
                nm = (function.name or "").lower()
                if nm in _SKIP_FN_NAMES:
                    continue

                sv = _writes_collateral(function)
                if sv is None:
                    continue

                if _calls_health_hook(function):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " decrements collateral-backing state variable ",
                    sv,
                    " without calling a comptroller health hook "
                    "(isRedeemAllowed/beforeRedeem/checkHealth). Add the "
                    "health check before the decrement to prevent collateral "
                    "spend that bypasses liquidation gating.\n",
                ]
                results.append(self.generate_result(info))

        return results
