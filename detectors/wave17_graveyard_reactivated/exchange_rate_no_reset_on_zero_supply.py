"""
exchange_rate_no_reset_on_zero_supply.py - Custom Slither detector.

Pattern (Zealous ExchangeRateInflation / slice_ac): A vault's redeem/withdraw
function decrements totalSupply (supply -= amount) but does NOT conditionally
reset the exchange rate / floor state variable when supply reaches zero.

After a total redemption (supply → 0), if the exchange rate stored in a state
variable is not reset, the first new depositor will compute their shares against
a stale (potentially inflated) rate, causing them to receive far fewer shares
than expected, or the vault permanently locks deposits at an unachievable rate.

This is DISTINCT from wave6 `exchange-rate-inflation-floor`:
- wave6 checks if a RATE COMPUTATION function guards against totalSupply == 0.
- THIS detector checks if a REDEEM function resets the rate when supply hits 0.
These are complementary: wave6 catches unguarded computation; this catches
unguarded state persistence after full exit.

Source: slice_ac Zealous "ExchangeRateInflation" - distinct from wave6 floor guard.

Dedup check: distinct from wave6 exchange-rate-inflation-floor.
    slither --list-detectors | grep -iE 'rate|exchange|supply|redeem' → 0 new match.

Detection strategy:
    1. Find functions named redeem / withdraw / _redeem / _withdraw / exit
       (case-insensitive prefix match).
    2. In those functions, find state variable writes to a supply-named variable
       (totalSupply, shares, supply) - confirms the function modifies supply.
    3. Check whether the function ALSO contains a conditional (IF) node that:
       (a) reads the supply state variable AND
       (b) writes to a rate/floor state variable.
       If such a conditional reset is ABSENT → flag.

Approximation:
    - We check: function writes a supply-hinted sv AND writes a rate-hinted sv
      inside an IF node. If no rate sv is written at all → we only flag if a
      rate sv EXISTS in the contract (i.e., the pattern is applicable).
    - Alternatively: function writes supply sv but no conditional write of any
      rate sv → flag IF the contract has a rate sv.
    - Confidence: LOW - false positives if rate is reset by a separate function
      (not inline in redeem) or if the vault intentionally leaves rate set.

Key insight from wave6 exchange_rate_inflation_floor.py:
    _has_zero_supply_guard checks IF node reading supply sv.
    This detector checks whether after writing supply, an IF resets a rate sv.

@author auditooor wave7
@pattern slice_ac Zealous ExchangeRateInflation - rate not reset after total redemption
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
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")

# Redeem/withdraw function name prefixes (lowercased).
_REDEEM_PREFIXES = (
    "redeem",
    "_redeem",
    "withdraw",
    "_withdraw",
    "exit",
    "_exit",
    "burn",
    "_burn",
    "unstake",
    "_unstake",
)

# State variable name substrings indicating total supply / shares.
_SUPPLY_HINTS = ("totalsupply", "totalshares", "supply", "shares", "totalstaked")

# State variable name substrings indicating an exchange rate / floor variable.
_RATE_HINTS = (
    "exchangerate",
    "lastrate",
    "ratefloor",
    "minrate",
    "highestrate",
    "currentrate",
    "storedrate",
    "pricepershare",
    "ratepershare",
    "rate",
    "price",
    "floor",
)


def _is_supply_sv(sv) -> bool:
    if not isinstance(sv, StateVariable):
        return False
    name = (sv.name or '').lower()
    return any(h in name for h in _SUPPLY_HINTS)


def _is_rate_sv(sv) -> bool:
    if not isinstance(sv, StateVariable):
        return False
    name = (sv.name or '').lower()
    return any(h in name for h in _RATE_HINTS)


def _is_redeem_function(function) -> bool:
    lower = function.name.lower()
    return any(lower.startswith(pfx) for pfx in _REDEEM_PREFIXES)


def _get_supply_sv_written(function):
    """Return first supply-hinted StateVariable written by the function, or None."""
    for sv in function.state_variables_written:
        if _is_supply_sv(sv):
            return sv
    return None


def _has_conditional_rate_reset(function, supply_sv: StateVariable) -> bool:
    """
    Return True if the function has an IF node that reads supply_sv AND
    the function writes a rate-hinted state variable inside a conditional context.

    Conservative approximation: we check if ANY conditional node in the function
    reads the supply sv, AND the function as a whole writes a rate sv.
    Slither's state_variables_written is per-function, not per-branch, so we
    check the combination of:
      - an IF/require node that reads supply_sv (the zero-supply condition)
      - AND the function writes a rate sv (confirms the reset happens)
    If both are present, we consider the reset guarded.
    """
    function_writes_rate = any(_is_rate_sv(sv) for sv in function.state_variables_written)
    if not function_writes_rate:
        return False

    # Check for a conditional guard on supply_sv
    for node in function.nodes:
        if node.contains_if() or node.contains_require_or_assert():
            if supply_sv in node.state_variables_read:
                return True
    return False


def _contract_has_rate_sv(contract) -> bool:
    """Return True if the contract has any rate-hinted state variable."""
    for sv in contract.state_variables_ordered:
        if _is_rate_sv(sv):
            return True
    return False


def _get_rate_sv(contract):
    """Return first rate-hinted state variable in the contract, for info list."""
    for sv in contract.state_variables_ordered:
        if _is_rate_sv(sv):
            return sv
    return None


class ExchangeRateNoResetOnZeroSupply(AbstractDetector):
    """
    Detect redeem/withdraw functions that decrement totalSupply but do not
    conditionally reset the exchange rate state variable when supply hits zero.
    """

    ARGUMENT = "rate-no-reset-on-zero-supply"
    HELP = (
        "Redeem function decrements totalSupply but does not reset exchange rate "
        "when supply reaches zero - stale rate inflates or locks out first depositor"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Exchange Rate Not Reset When Total Supply Reaches Zero"
    WIKI_DESCRIPTION = (
        "A vault's redeem or withdraw function decrements totalSupply but does not "
        "check whether supply has reached zero and reset the exchange rate state "
        "variable accordingly. When all shares are redeemed, the stored rate "
        "reflects the last active epoch's rate. The next depositor will have their "
        "shares calculated against this potentially inflated or otherwise stale rate, "
        "causing them to receive an unexpected share amount or triggering a floor "
        "violation revert. The fix is to add `if (totalSupply == 0) exchangeRate = "
        "INITIAL_RATE;` inside the redeem function. "
        "Distinct from wave6 `exchange-rate-inflation-floor` which checks the "
        "COMPUTATION guard; this checks the POST-REDEMPTION STATE reset."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
uint256 public totalSupply;
uint256 public exchangeRate = 1e18;

function redeem(address user, uint256 amount) external {
    balances[user] -= amount;
    totalSupply -= amount;  // BUG: no reset of exchangeRate when totalSupply == 0
}

function deposit(uint256 assets) external returns (uint256 shares) {
    shares = assets * 1e18 / exchangeRate;  // uses stale rate
    totalSupply += shares;
}
```
1. Initially: totalSupply = 1000 shares, exchangeRate = 10e18 (inflated over time).
2. All holders redeem: totalSupply = 0, but exchangeRate is still 10e18.
3. New depositor calls deposit(1000e18). Receives 1000e18 / 10e18 = 100 shares.
   With a reset rate of 1e18 they would have received 1000 shares - 10x fewer.
4. Original holders can re-enter at the inflated rate and immediately withdraw,
   extracting value from the new depositor."""
    WIKI_RECOMMENDATION = (
        "Add a zero-supply reset inside the redeem/withdraw function: "
        "`if (totalSupply == 0) { exchangeRate = INITIAL_RATE; }`. "
        "This ensures the first new depositor after a full redemption always "
        "starts with the canonical initial rate. Reference: ERC4626 and "
        "OpenZeppelin Vault implementations reset virtual shares on zero supply."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            # Contract must have a rate-hinted state variable to be applicable
            if not _contract_has_rate_sv(contract):
                continue

            rate_sv = _get_rate_sv(contract)

            for function in contract.functions_and_modifiers_declared:
                if not _is_redeem_function(function):
                    continue
                if function.view or function.pure:
                    continue

                # Must write a supply-hinted state variable
                supply_sv = _get_supply_sv_written(function)
                if supply_sv is None:
                    continue

                # If the function contains a conditional reset of the rate sv → safe
                if _has_conditional_rate_reset(function, supply_sv):
                    continue

                if rate_sv is not None:
                    info: DETECTOR_INFO = [
                        function,
                        " decrements supply variable ",
                        supply_sv,
                        " but never conditionally resets rate variable ",
                        rate_sv,
                        " when supply reaches zero. A stale rate after total "
                        "redemption will misprice shares for the next depositor. "
                        "Add `if (totalSupply == 0) exchangeRate = INITIAL_RATE;`.\n",
                    ]
                else:
                    info = [
                        function,
                        " decrements supply variable ",
                        supply_sv,
                        " without a conditional exchange-rate reset on zero supply. "
                        "Stale rate after total redemption misprices first new depositor.\n",
                    ]
                results.append(self.generate_result(info))

        return results
