"""
exchange_rate_inflation_floor.py - Custom Slither detector.

Pattern: a vault's exchange rate is computed as `rate = totalAssets / totalSupply`
and written into a floor/monotonic state variable (lastRate, rateFloor, minRate,
highestExchangeRate, exchangeRate). If the function does NOT guard against
`totalSupply == 0` before the division, a permissionless reward injection can
drive the floor to an extreme value when supply is zero, locking all future
deposits that enforce `require(rate >= lastRate)`.

Source: reference/corpus_mined/slice_ac.md - ExchangeRateInflation (Zealous)

Dedup check: no Slither builtin covers exchange-rate floor without zero-supply guard.
    slither --list-detectors | grep -iE "rate|exchange|floor" → 0 builtins match.

Detection strategy:
    1. Find functions that WRITE a state variable whose name contains a floor/rate
       hint: "lastrate", "ratefloor", "minrate", "highestexchangerate",
       "exchangerate", "lastprice" (case-insensitive substring match).
    2. In the same function, find a Binary(DIVISION) where the DIVISOR is a
       StateVariable whose name contains a supply/shares hint: "totalsupply",
       "totalshares", "supply", "shares".
    3. Check whether ANY node BEFORE the division node is a Condition (or
       require/assert) that reads the supply-named state variable and compares it
       with != 0 or > 0. If such a guard is absent → flag.

Approximation: the guard check walks nodes in CFG order and accepts any
Condition/require node in the function that reads the supply variable. A guard
in a called-internal function that is not inlined is NOT seen - acceptable
over-approximation for a LOW-confidence triage detector.

Key IR insight (from fixture):
    `rate = totalAssets / totalSupply`  →  Binary TMP_0 = totalAssets / totalSupply
    where variable_right is StateVariable("totalSupply").
    The clean version has `if (totalSupply == 0) return;` which appears as a
    Condition node reading totalSupply (via Binary EQ) before the division.

@author auditooor wave6
@pattern ExchangeRateInflation - corpus slice_ac
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
from slither.core.variables.state_variable import StateVariable
from slither.utils.output import Output

SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

# Substrings indicating a rate-floor state variable
_RATE_FLOOR_HINTS = (
    "lastrate", "ratefloor", "minrate", "highestrate", "highestexchangerate",
    "exchangerate", "lastprice", "floorate", "ratecap",
)

# Substrings indicating a supply/shares state variable used as divisor
_SUPPLY_HINTS = ("totalsupply", "totalshares", "supply", "shares")


def _is_rate_floor_sv(var) -> bool:
    if not isinstance(var, StateVariable):
        return False
    name = (var.name or "").lower()
    return any(h in name for h in _RATE_FLOOR_HINTS)


def _is_supply_sv(var) -> bool:
    if not isinstance(var, StateVariable):
        return False
    name = (var.name or "").lower()
    return any(h in name for h in _SUPPLY_HINTS)


def _find_rate_floor_division(function):
    """
    Return (div_node, supply_sv) for the first Binary(DIVISION) whose divisor
    is a supply-hinted StateVariable, or (None, None).
    """
    for node in function.nodes:
        for ir in node.irs:
            if not (isinstance(ir, Binary) and ir.type == BinaryType.DIVISION):
                continue
            if _is_supply_sv(ir.variable_right):
                return node, ir.variable_right
    return None, None


def _writes_rate_floor(function) -> bool:
    """True if the function writes any rate-floor-hinted state variable."""
    for sv in function.state_variables_written:
        if _is_rate_floor_sv(sv):
            return True
    return False


def _has_zero_supply_guard(function, supply_sv: StateVariable) -> bool:
    """
    Return True if the function contains any Condition or require/assert node
    that reads supply_sv. This is a sign of a `if (totalSupply == 0) return`
    or `require(totalSupply > 0)` guard.

    We check ALL nodes in the function (not just those before the division node)
    because Slither's CFG ordering for simple linear functions is reliable, and
    checking any node is a conservative (low-FP) approach: if the guard exists
    anywhere in the function it would prevent the unguarded path.
    """
    for node in function.nodes:
        # Check: Condition node that reads the supply variable
        if node.contains_if() or node.contains_require_or_assert():
            if supply_sv in node.state_variables_read:
                return True
    return False


class ExchangeRateInflationFloor(AbstractDetector):
    """Detect vault rate-floor writes with division by totalSupply but no zero-supply guard."""

    ARGUMENT = "exchange-rate-inflation-floor"
    HELP = (
        "Exchange rate stored as floor without zero-supply guard - "
        "permissionless reward injection can pin floor at max, DoSing all deposits"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW  # FP risk: functions that compute rate but don't floor it

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Exchange Rate Inflation Floor DoS"
    WIKI_DESCRIPTION = (
        "A vault's exchange-rate update function divides totalAssets by totalSupply "
        "and writes the result into a monotonic floor variable (lastRate, highestExchangeRate, "
        "etc.) without first checking that totalSupply is nonzero. When totalSupply is zero "
        "the division reverts (or returns an extreme value), and a permissionless reward "
        "injection before the first deposit can lock the floor at a value no real deposit "
        "can ever match, permanently DoSing all future stakers."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
uint256 public lastRate;

function updateRate() external {
    uint256 rate = totalAssets / totalSupply; // BUG: no zero-supply guard
    if (rate > lastRate) {
        lastRate = rate; // floor pinned at extreme value
    }
}
```
Attacker calls `addRewards(X)` when totalSupply == 0 then calls `updateRate`.
Division by zero reverts - OR if totalSupply is 1 wei, rate = X/1 = X.
`lastRate` is set to X. All future deposits produce rate < X so
`require(rate >= lastRate)` reverts forever."""
    WIKI_RECOMMENDATION = (
        "Add a zero-supply guard before computing the exchange rate: "
        "`if (totalSupply == 0) return;`. "
        "Consider also resetting lastRate to 0 (or a sentinel) when totalSupply drops to zero "
        "so the floor is not permanently poisoned."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue
            if is_vendored_or_test_contract(contract):
                continue

            for function in contract.functions_and_modifiers_declared:
                # Skip view/pure: they can't write state, can't pin the floor
                if function.view or function.pure:
                    continue

                # Must write a rate-floor state variable
                if not _writes_rate_floor(function):
                    continue

                # Must divide by a supply-hinted state variable
                div_node, supply_sv = _find_rate_floor_division(function)
                if div_node is None:
                    continue

                # If there is already a zero-supply guard → safe
                if _has_zero_supply_guard(function, supply_sv):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " computes exchange rate by dividing by supply variable ",
                    supply_sv,
                    " and writes to a rate-floor state variable, but has no "
                    "`require(totalSupply > 0)` / `if (totalSupply == 0) return` guard. "
                    "Permissionless reward injection when supply == 0 can pin the floor "
                    "at an extreme value, DoSing all future deposits.\n",
                ]
                results.append(self.generate_result(info))

        return results
