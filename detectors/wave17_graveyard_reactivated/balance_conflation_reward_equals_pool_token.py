"""
balance_conflation_reward_equals_pool_token.py - Custom Slither detector.

Pattern (Hybra M-06, slice_ad): A reward-sweep function computes
`idle = IERC20(rewardToken).balanceOf(address(this)) - tracked` and transfers
the result. If `rewardToken` happens to be the same address as one of the
pool tokens (`poolToken0` / `poolToken1`) the contract holds, the "idle"
balance includes the pool's intended-to-hold balance - the sweep silently
drains user funds.

Detection strategy:
    1. Contract has at least one `address`-typed state variable whose name
       matches /(token0|token1|poolToken|reserveToken)/i.
    2. Function calls `balanceOf(address(this))` (HighLevelCall to a
       function with solidity_signature `balanceOf(address)` and an arg
       that comes from `address(this)`).
    3. Function contains a Binary SUBTRACTION whose left operand is the
       result of that balanceOf call.
    4. Function ALSO transfers ERC20 (HighLevelCall to `transfer(...)`).
    5. Function does NOT contain a Binary NOT_EQUAL where BOTH operands
       are state variables - the canonical mitigation
       `require(rewardToken != poolToken0)`.

@author auditooor wave9
@pattern slice_ad Hybra M-06
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
from slither.core.solidity_types.elementary_type import ElementaryType
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import (
    Binary,
    BinaryType,
    HighLevelCall,
    TypeConversion,
)
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")
_POOL_TOKEN_RE = re.compile(
    r"(token0|token1|pooltoken|reservetoken|underlying|asset)",
    re.IGNORECASE,
)


def _is_address_state_var(sv) -> bool:
    t = sv.type
    return isinstance(t, ElementaryType) and t.name == "address"


def _has_balance_of_self(function):
    """Return the HighLevelCall IR if the function calls
    `balanceOf(address(this))`, else None."""
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, HighLevelCall):
                continue
            fn = ir.function
            sig = ""
            if isinstance(fn, Function):
                sig = fn.solidity_signature or ""
            else:
                fname = getattr(ir, "function_name", None) or ""
                sig = f"{fname}(address)"
            if not sig.startswith("balanceOf("):
                continue
            return ir
    return None


def _has_transfer_call(function) -> bool:
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, HighLevelCall):
                continue
            fn = ir.function
            sig = ""
            if isinstance(fn, Function):
                sig = fn.solidity_signature or ""
            else:
                sig = (getattr(ir, "function_name", None) or "") + "(?)"
            if sig.startswith("transfer(") or sig.startswith("safeTransfer("):
                return True
    return False


def _has_state_var_inequality_check(function) -> bool:
    """True if the function has a Binary NOT_EQUAL where BOTH operands are
    address state variables (rewardToken != poolToken0 etc.)."""
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, Binary):
                continue
            if ir.type != BinaryType.NOT_EQUAL:
                continue
            l = ir.variable_left
            r = ir.variable_right
            if isinstance(l, StateVariable) and isinstance(r, StateVariable):
                return True
    return False


def _balance_feeds_subtraction(function, balance_ir) -> bool:
    """True if the result of `balance_ir` flows into a Binary SUBTRACTION
    as the left operand."""
    target = balance_ir.lvalue
    if target is None:
        return False
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, Binary) and ir.type == BinaryType.SUBTRACTION:
                if ir.variable_left is target:
                    return True
    return False


class BalanceConflationRewardEqualsPoolToken(AbstractDetector):
    """Sweep function trusts `balanceOf(this) - tracked` as idle reward,
    but the reward token may equal a pool token the contract is meant to
    hold for users."""

    ARGUMENT = "balance-conflation-reward-equals-pool-token"
    HELP = (
        "sweep computes idle = balanceOf(this) - tracked and transfers it, "
        "but the reward token may collide with a pool token the contract holds"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Balance Conflation: Reward Token Coincides With Pool Token"
    WIKI_DESCRIPTION = (
        "A reward sweeper that treats `balanceOf(self) - trackedRewards` as "
        "idle balance silently drains user funds when the reward token is "
        "also one of the pool's underlying tokens. The contract's balance "
        "includes the pool's intended-to-hold balance, but the sweep cannot "
        "tell them apart. Hybra M-06 is the canonical example."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function sweepRewards() external {
    uint256 idle = IERC20(rewardToken).balanceOf(address(this)) - trackedRewards;
    IERC20(rewardToken).transfer(msg.sender, idle);  // BUG
}
```
If `rewardToken == poolToken0`, the contract's balance is
`pool_holdings + reward_residue`. `trackedRewards` only accounts for the
reward residue, so `idle` includes the entire pool position. The sweeper
walks away with depositors' funds."""
    WIKI_RECOMMENDATION = (
        "Either (a) require `rewardToken != poolToken0 && rewardToken != "
        "poolToken1` in the constructor / setter and re-check at sweep time, "
        "or (b) track `rewardBalance` independently of `balanceOf(self)` and "
        "sweep only the explicitly-tracked amount."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            pool_vars = [
                sv for sv in contract.state_variables
                if _is_address_state_var(sv)
                and _POOL_TOKEN_RE.search(sv.name or "")
            ]
            if not pool_vars:
                continue

            for function in contract.functions_and_modifiers_declared:
                if function.is_constructor:
                    continue
                bal_ir = _has_balance_of_self(function)
                if bal_ir is None:
                    continue
                if not _balance_feeds_subtraction(function, bal_ir):
                    continue
                if not _has_transfer_call(function):
                    continue
                if _has_state_var_inequality_check(function):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " sweeps balanceOf(this) minus a tracked counter and "
                    "transfers the difference, but contract ",
                    contract,
                    " holds pool token state variables (",
                    ", ".join(sv.name for sv in pool_vars),
                    ") that may coincide with the swept token - risk of "
                    "draining user funds.\n",
                ]
                results.append(self.generate_result(info))

        return results
