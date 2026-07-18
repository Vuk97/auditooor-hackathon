"""
order_status_non_monotonic.py - Custom Slither detector.

Pattern: a function writes a zero / false constant to an order-like state
variable (name contains 'status', 'order', 'filled', 'nonce'). orderStatus
should be monotonically forward - any reset is a ghost-fill vector
(partially filled order gets re-used).

IR reality (verified against fixture):
    orderStatus[id] = 0;
  compiles to:
    Index: REF_0 -> orderStatus[id]
    Assignment: REF_0 := 0(uint256)   rvalue type=Constant

Dedup check: no Slither builtin for order-state monotonicity.

@author auditooor
@pattern iter20 C3
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.slithir.operations import Assignment
from slither.slithir.variables import Constant, ReferenceVariable
from slither.core.variables.state_variable import StateVariable
from slither.utils.output import Output


SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")

# State-var name substrings considered order-status-like.
# Keep these narrow and order-specific - broad terms like "paused", "pause",
# "cancel" caused 5 FPs on Polymarket v2 (paused[_asset] = false, etc).
# NOTE: "used" is intentionally excluded because it is a suffix of "paused" /
# "userPausedBlockAt", causing false positives on pause-reset patterns.
_STATUS_HINTS = (
    "orderstatus",
    "order_status",
    "filled",
    "remaining",
    "consumed",
    "settled",
    "nonce",
    "orderfilled",
)


def _looks_like_status_var(var) -> bool:
    if not isinstance(var, StateVariable):
        return False
    name = (var.name or "").lower()
    return any(h in name for h in _STATUS_HINTS)


def _is_zero_or_false_constant(v) -> bool:
    if not isinstance(v, Constant):
        return False
    val = v.value
    if val is False or val == 0:
        return True
    return False


def _reference_points_to_state_var(ref):
    """Walk a ReferenceVariable chain to find the underlying StateVariable."""
    cur = ref
    # points_to_origin gives us the root variable the reference resolves to
    for _ in range(5):
        if isinstance(cur, StateVariable):
            return cur
        if not isinstance(cur, ReferenceVariable):
            return None
        nxt = getattr(cur, "points_to_origin", None) or getattr(cur, "points_to", None)
        if nxt is None or nxt is cur:
            return None
        cur = nxt
    return None


class OrderStatusNonMonotonic(AbstractDetector):
    """Detect writes of 0/false to order-status-like state variables."""

    ARGUMENT = "order-status-non-monotonic"
    HELP = "Function resets an order-status state variable to zero/false"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW  # Intentionally broad

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Non-monotonic order status write"
    WIKI_DESCRIPTION = (
        "A function writes the literal 0 or false to a state variable whose "
        "name suggests order/fill/status/nonce semantics. orderStatus should "
        "be monotonically forward - resetting it allows a previously-processed "
        "order or signature to be replayed (ghost-fill)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
mapping(bytes32 => uint256) public orderStatus;
function cancelOrder(bytes32 id) external {
    orderStatus[id] = 0;  // reset - ghost-fill vector
}
```
An operator cancels a partially-filled order. The attacker re-submits the
original signed order - `orderStatus[id] == 0` so it passes the "not yet
processed" check, and the attacker drains the remaining fill again."""
    WIKI_RECOMMENDATION = (
        "Make order state monotonically forward. Use distinct sentinel values "
        "(1 = open, 2 = filled, 3 = cancelled) and forbid writes that move "
        "backwards. Or track cancellation in a separate mapping that can only "
        "increment."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []
        for contract in self.contracts:
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue
            if is_vendored_or_test_contract(contract):
                continue
            for function in contract.functions_and_modifiers_declared:
                for node in function.nodes:
                    for ir in node.irs:
                        if not isinstance(ir, Assignment):
                            continue
                        if not _is_zero_or_false_constant(ir.rvalue):
                            continue
                        lv = ir.lvalue
                        sv = None
                        if isinstance(lv, StateVariable):
                            sv = lv
                        elif isinstance(lv, ReferenceVariable):
                            sv = _reference_points_to_state_var(lv)
                        if sv is None or not _looks_like_status_var(sv):
                            continue
                        info: DETECTOR_INFO = [
                            function,
                            " writes 0/false to order-status-like state variable ",
                            sv,
                            ". This is a non-monotonic reset - may enable ghost-fill replay.",
                        ]
                        results.append(self.generate_result(info))
                        break  # one flag per function is enough
                    else:
                        continue
                    break
        return results
