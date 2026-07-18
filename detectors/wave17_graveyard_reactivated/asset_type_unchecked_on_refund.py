"""
asset_type_unchecked_on_refund.py - Custom Slither detector.

Pattern (Zellic slice_ab t3rn, CRITICAL): a refund / claim path checks a
`claimed[id]` / `isRefundable[id]` flag but transfers the stored reward
asset WITHOUT asserting that the stored asset matches a protocol-level
expected reward asset. Because the order creator controls the asset
field, an attacker can craft an order referencing an asset they don't
own; when the refund path fires, the protocol delivers the wrong token.

Detection strategy:
    1. Walk user functions whose name matches refund / claim / withdraw.
    2. Require the function reads a mapping-style state variable whose
       name hints at "claimed" / "isClaimable" / "isRefundable" /
       "settled" (indicating refund bookkeeping).
    3. Require the function makes a HighLevelCall to `transfer(address,
       uint256)` (ERC-20 style).
    4. Require the function does NOT contain any Binary(EQUAL) comparison
       whose operands involve a StateVariable or constant address whose
       name hints at an expected asset ("asset", "token", "reward",
       "expected"). This is the missing `require(o.asset == expectedAsset)`.
    5. Flag if all of the above hold.

@author auditooor wave8
@pattern slice_ab t3rn AssetTypeUnchecked
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
from slither.slithir.operations import Binary, BinaryType, HighLevelCall
from slither.core.variables.state_variable import StateVariable
from slither.core.declarations import Function
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_REFUND_FN_HINTS = ("refund", "claim", "withdraw", "reclaim", "cancel")

_CLAIMED_HINTS = ("claimed", "isclaimable", "isrefundable", "settled", "refunded", "cancelled")

_ASSET_HINTS = ("asset", "token", "reward", "expected")


def _is_refund_fn(function) -> bool:
    name = (function.name or "").lower()
    return any(h in name for h in _REFUND_FN_HINTS)


def _reads_claimed_mapping(function) -> bool:
    for sv in function.state_variables_read:
        name = (getattr(sv, "name", "") or "").lower()
        if any(h in name for h in _CLAIMED_HINTS):
            return True
    return False


def _calls_erc20_transfer(function) -> bool:
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, HighLevelCall) and isinstance(ir.function, Function):
                sig = getattr(ir.function, "solidity_signature", None)
                if sig == "transfer(address,uint256)":
                    return True
    return False


def _has_expected_asset_equality(function) -> bool:
    """
    Return True if the function contains a Binary(EQUAL) whose operands
    include a StateVariable whose name hints at 'asset'/'token'/'reward'/
    'expected'. This approximates a `require(stored_asset == expected_asset)`
    check.
    """
    for node in function.nodes:
        for ir in node.irs:
            if not (isinstance(ir, Binary) and ir.type == BinaryType.EQUAL):
                continue
            for side in (ir.variable_left, ir.variable_right):
                if isinstance(side, StateVariable):
                    nm = (side.name or "").lower()
                    if any(h in nm for h in _ASSET_HINTS):
                        return True
    return False


class AssetTypeUncheckedOnRefund(AbstractDetector):
    """Detect refund/claim paths that transfer a user-supplied asset without asset-type check."""

    ARGUMENT = "asset-type-unchecked-on-refund"
    HELP = (
        "Refund/claim transfers an order-stored asset without asserting it "
        "equals the protocol's expected reward asset - wrong-asset refund"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Refund Path Missing Asset-Type Check"
    WIKI_DESCRIPTION = (
        "A refund/claim function reads a `claimed[id]` flag for replay "
        "protection and then transfers `orders[id].asset` to the caller - "
        "but never asserts that `orders[id].asset` matches the protocol's "
        "expected reward asset. Since the attacker controls the asset "
        "field at order-creation time, they can point it at any token and "
        "have the protocol deliver the wrong asset on refund. Found as the "
        "t3rn CRITICAL in Zellic slice_ab."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function refund(uint256 id) external {
    require(!claimed[id]);
    claimed[id] = true;
    // BUG: no check that orders[id].asset is the intended reward token
    IERC20(orders[id].asset).transfer(msg.sender, orders[id].amount);
}
```
Attacker creates an order whose `asset` field points at a high-value token
the protocol does not expect. On refund, the protocol transfers that token
to the attacker. Repeated calls drain the protocol's inventory of
unanticipated assets."""
    WIKI_RECOMMENDATION = (
        "Before the transfer, enforce the asset invariant: "
        "`require(orders[id].asset == expectedRewardAsset, \"wrong asset\")`. "
        "If the refund must support multiple assets, maintain an allowlist and "
        "check membership - never trust a user-controlled address field."
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
                if function.view or function.pure:
                    continue
                if function.visibility not in ("public", "external"):
                    continue
                if not _is_refund_fn(function):
                    continue
                if not _reads_claimed_mapping(function):
                    continue
                if not _calls_erc20_transfer(function):
                    continue
                if _has_expected_asset_equality(function):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " transfers an order-stored asset on the refund/claim "
                    "path but does not check it against an expected reward "
                    "asset. Attacker-controlled asset field in the order "
                    "struct can cause the wrong token to be delivered.\n",
                ]
                results.append(self.generate_result(info))

        return results
