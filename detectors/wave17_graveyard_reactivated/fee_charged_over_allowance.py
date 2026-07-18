"""
fee_charged_over_allowance.py - Custom Slither detector.

Pattern (Next Generation M-01, slice_ab): A fee-on-transfer ERC-20 overrides
`transferFrom` and charges a fee to the `from` balance on top of the user-
supplied `amount`, but decrements the allowance by only `amount`. A spender
who is approved for `X` ends up debiting `X + fee` from the owner's balance
- the allowance is silently over-drawn.

Detection strategy:
    1. Contract defines `transferFrom(address,address,uint256)` directly.
    2. Inside the body, there must be a state-variable subtraction whose
       subtrahend is a Binary ADDITION on the SAME node, where one operand
       of the addition is the `amount` function parameter.
    3. The same function must ALSO contain an allowance-style write whose
       RHS is derived from the `amount` parameter WITHOUT an intervening
       addition (i.e. the allowance is debited by the plain `amount`, not
       by the extended total).
    4. If both are true → flag.

The implementation is structural: we don't need to guess which state var is
allowance vs. balance. We check that (a) a debit of a state var uses
`add(amount, X)` locally, and (b) at least one other node decrements a
state var using `amount` alone (or a local variable trivially equal to
`amount`). The mismatch is what matters.

@author auditooor wave11
@pattern slice_ab Next Generation M-01 fee surcharge over allowance
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
from slither.core.variables.local_variable import LocalVariable
from slither.slithir.operations import Binary, BinaryType, Assignment
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")
_TRANSFERFROM_SIG = "transferFrom(address,address,uint256)"


def _is_state_ref_written(ir):
    """True if this IR writes to a state variable reference (storage mapping)."""
    written = getattr(ir, "lvalue", None)
    if written is None:
        return False
    # Heuristic: the lvalue-op is used as an index reference to a state var.
    try:
        pts = getattr(written, "points_to_origin", None)
        if pts is not None:
            from slither.core.variables.state_variable import StateVariable
            if isinstance(pts, StateVariable):
                return True
    except Exception:
        pass
    return False


class FeeChargedOverAllowance(AbstractDetector):
    """transferFrom debits from-balance by amount+fee but allowance by only amount."""

    ARGUMENT = "fee-charged-over-allowance"
    HELP = (
        "transferFrom debits `from` balance by `amount + fee` but decrements "
        "allowance by only `amount` - spender over-draws the owner's approval"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Fee Charged Over Allowance"
    WIKI_DESCRIPTION = (
        "A fee-on-transfer ERC-20 overrides `transferFrom` to take a fee out "
        "of the sender's balance on top of the amount requested by the "
        "spender, while decrementing the allowance by only `amount`. A "
        "spender approved for N can therefore extract up to `N + fee(N)` "
        "from the owner's balance across repeated calls. Reported in Next "
        "Generation M-01."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function transferFrom(address from, address to, uint256 amount) external {
    uint256 fee = amount * FEE_BPS / 10000;
    require(allowance[from][msg.sender] >= amount);
    allowance[from][msg.sender] -= amount;      // BUG: not `amount + fee`
    balanceOf[from] -= amount + fee;            // over-draws
    balanceOf[to]   += amount;
    balanceOf[tres] += fee;
}
```
Owner approves spender for 100. Spender calls transferFrom(owner, attacker, 100)
and ends up debiting 101 from the owner. Over many calls this can drain
additional funds above what was approved."""
    WIKI_RECOMMENDATION = (
        "Decrement the allowance by the same total that is debited from the "
        "owner's balance, OR charge the fee against `to` / the protocol, "
        "never silently above the spender's approval."
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
                if getattr(function, "solidity_signature", None) != _TRANSFERFROM_SIG:
                    continue
                if len(function.parameters) < 3:
                    continue
                amount_param = function.parameters[2]
                if not isinstance(amount_param, LocalVariable):
                    continue

                # Collect the set of local variables that are trivially
                # `amount` (either amount itself or a local assigned from
                # amount with no arithmetic - via an Assignment IR).
                amount_aliases = {amount_param}
                for node in function.nodes:
                    for ir in node.irs:
                        if isinstance(ir, Assignment):
                            if ir.rvalue in amount_aliases and isinstance(
                                ir.lvalue, LocalVariable
                            ):
                                amount_aliases.add(ir.lvalue)

                # 1. Find a state-var subtraction where the subtrahend is
                #    computed on the SAME node as a Binary ADDITION whose
                #    operands include `amount`.
                extended_debit_node = None
                for node in function.nodes:
                    # Gather additions on this node whose operands include amount.
                    add_results = []
                    for ir in node.irs:
                        if (
                            isinstance(ir, Binary)
                            and ir.type == BinaryType.ADDITION
                        ):
                            if (
                                ir.variable_left in amount_aliases
                                or ir.variable_right in amount_aliases
                            ):
                                add_results.append(ir.lvalue)
                    if not add_results:
                        continue
                    # Look for a state-var subtraction using one of those
                    # add results as its right operand.
                    for ir in node.irs:
                        if not (
                            isinstance(ir, Binary)
                            and ir.type == BinaryType.SUBTRACTION
                        ):
                            continue
                        if ir.variable_right not in add_results:
                            continue
                        if not node.state_variables_written:
                            continue
                        extended_debit_node = node
                        break
                    if extended_debit_node:
                        break
                if extended_debit_node is None:
                    continue

                # 2. Find a DIFFERENT node that decrements a state var by
                #    an amount alias WITHOUT any addition involving amount
                #    on that node (i.e. plain `x -= amount`).
                plain_debit_node = None
                for node in function.nodes:
                    if node is extended_debit_node:
                        continue
                    if not node.state_variables_written:
                        continue
                    # Skip nodes that contain an amount-addition (those
                    # are extended debits too).
                    add_with_amount = any(
                        isinstance(ir, Binary)
                        and ir.type == BinaryType.ADDITION
                        and (
                            ir.variable_left in amount_aliases
                            or ir.variable_right in amount_aliases
                        )
                        for ir in node.irs
                    )
                    if add_with_amount:
                        continue
                    has_amount_sub = False
                    for ir in node.irs:
                        if not (
                            isinstance(ir, Binary)
                            and ir.type == BinaryType.SUBTRACTION
                        ):
                            continue
                        if ir.variable_right in amount_aliases:
                            has_amount_sub = True
                            break
                    if has_amount_sub:
                        plain_debit_node = node
                        break
                if plain_debit_node is None:
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " debits a state variable by `amount + fee` at ",
                    extended_debit_node,
                    " but decrements another state variable by only "
                    "`amount` at ",
                    plain_debit_node,
                    " - spender can over-draw the owner's approval by "
                    "the fee portion.\n",
                ]
                results.append(self.generate_result(info))

        return results
