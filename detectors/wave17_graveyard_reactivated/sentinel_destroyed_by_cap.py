"""
sentinel_destroyed_by_cap.py - Custom Slither detector.

Pattern (P27 - BasisOS "Sentinel-Clamped-Before-Branch"):
    type(uint256).max is used as a "close-all" / "unbounded" sentinel.
    Before the branch that detects this sentinel, a Math.min/max / clamping
    call or a LESS/GREATER binary with a state-variable cap strips infinity,
    turning the sentinel into a finite number. The downstream
    `if (x == type(uint256).max)` check then always evaluates false, and
    the close-all path never executes.

Detection strategy:
    Walk every function's nodes IN ORDER (node_id order approximates execution
    order for linear functions). For each node, record the minimum node_id at
    which:
      (a) a clamping event occurs - an InternalCall/LibraryCall whose callee
          name contains "min", "max", or "clamp"; OR a Binary(LESS/GREATER/
          LESS_EQUAL/GREATER_EQUAL) that involves a state variable on one side
          (state-variable cap check).
      (b) a sentinel comparison occurs - a Binary(EQUAL or NOT_EQUAL) where one
          operand is the Constant 2^256-1 (type(uint256).max).

    If clamp_node_id < sentinel_node_id → flag (clamp destroys sentinel before
    the branch can detect it).

Dedup check (slither --list-detectors | grep -iE 'sentinel|cap|clamp'):
    No matching builtin. NOVEL.

Source: reference/corpus_mined/slice_aa.md - BasisOS "Sentinel-Clamped-Before-Branch", P27.
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
from slither.slithir.operations import (
    Binary,
    BinaryType,
    InternalCall,
    LibraryCall,
    HighLevelCall,
)
from slither.slithir.variables import Constant
from slither.core.variables.state_variable import StateVariable
from slither.utils.output import Output

# 2^256 - 1: the numeric value of type(uint256).max / UINT256_MAX
_UINT256_MAX = (1 << 256) - 1

# Binary op types that constitute a "cap check" against a state variable
_CAP_CMP_OPS = {
    BinaryType.LESS,
    BinaryType.LESS_EQUAL,
    BinaryType.GREATER,
    BinaryType.GREATER_EQUAL,
}

# Binary op types that constitute a "sentinel equality check"
_SENTINEL_EQ_OPS = {
    BinaryType.EQUAL,
    BinaryType.NOT_EQUAL,
}

# Callee name substrings that indicate a clamping function
_CLAMP_NAME_HINTS = ("min", "max", "clamp")

SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")


def _is_uint256_max_constant(var) -> bool:
    """True if var is a Constant with value == 2^256 - 1."""
    if not isinstance(var, Constant):
        return False
    val = getattr(var, "value", None)
    if val is None:
        return False
    try:
        return int(val) == _UINT256_MAX
    except (TypeError, ValueError):
        return False


def _node_has_clamp(node) -> bool:
    """Return True if any IR in the node represents a clamping operation:
       - InternalCall / LibraryCall / HighLevelCall to a function whose name
         contains 'min', 'max', or 'clamp'.
       - Binary(LESS/GREATER/LESS_EQUAL/GREATER_EQUAL) where one operand is a
         StateVariable (direct cap check against a stored limit).
    """
    for ir in node.irs:
        # Call-based clamp: Math.min / internal _min / _clamp etc.
        if isinstance(ir, (InternalCall, LibraryCall, HighLevelCall)):
            fn = getattr(ir, "function", None)
            fn_name = (fn.name if fn else "") or ""
            if any(hint in fn_name.lower() for hint in _CLAMP_NAME_HINTS):
                return True
        # Comparison-based cap: x > cap or x < maxSizeDelta (state var on one side)
        if isinstance(ir, Binary) and ir.type in _CAP_CMP_OPS:
            for v in ir.read:
                if isinstance(v, StateVariable):
                    return True
    return False


def _node_has_sentinel_check(node) -> bool:
    """Return True if any IR in the node involves type(uint256).max as part of
    an equality check.

    Slither IR pattern for `x == type(uint256).max`:
      Assignment TMP_n := 115792...9935   (Constant in .read)
      Binary(EQUAL) TMP_m = x == TMP_n

    The Constant does NOT appear directly in the Binary.read list; it appears
    as the rhs of the Assignment that produces the TemporaryVariable consumed
    by the Binary. We therefore look for ANY Assignment whose .read list
    contains the UINT256_MAX Constant - if found in a node, that node performs
    a sentinel-value materalization (which is only useful for a subsequent
    equality test in the same node).

    As an additional safety check we also look for the Constant appearing
    directly in any Binary.read (handles compiler variants or future changes).
    """
    for ir in node.irs:
        # Primary path: Constant(UINT256_MAX) appears in Assignment.read
        reads = getattr(ir, "read", [])
        for v in reads:
            if _is_uint256_max_constant(v):
                return True
        # Secondary path: Constant appears directly in Binary.read (fallback)
        if isinstance(ir, Binary) and ir.type in _SENTINEL_EQ_OPS:
            for v in ir.read:
                if _is_uint256_max_constant(v):
                    return True
    return False


class SentinelDestroyedByCap(AbstractDetector):
    """Detect clamping operations that strip type(uint256).max before sentinel check."""

    ARGUMENT = "sentinel-destroyed-by-cap"
    HELP = (
        "type(uint256).max sentinel stripped by Math.min/cap before the sentinel-detection branch"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Sentinel Value Destroyed by Clamping (P27)"
    WIKI_DESCRIPTION = (
        "type(uint256).max is commonly used as a sentinel meaning 'close all' or "
        "'unbounded'. If a clamping call (Math.min, Math.max, internal _clamp, or a "
        "direct comparison against a state-variable cap) appears BEFORE the branch "
        "that tests whether the value equals type(uint256).max, the sentinel is silently "
        "stripped to a finite number and the close-all path never executes. This can "
        "permanently prevent position closure, loss-limitation, or any logic that depends "
        "on the infinity sentinel."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
uint256 public maxSizeDelta = 1_000_000e18;

function adjustPosition(uint256 sizeDelta) external {
    // BUG: _min strips type(uint256).max to maxSizeDelta
    uint256 clamped = _min(sizeDelta, maxSizeDelta);
    // This check is now unreachable when sizeDelta == type(uint256).max
    if (clamped == type(uint256).max) { closeAll(); }
}
```
Caller sends sizeDelta == type(uint256).max intending to trigger closeAll().
_min returns maxSizeDelta instead. The sentinel check always evaluates false.
closeAll() never executes, leaving the position open."""
    WIKI_RECOMMENDATION = (
        "Always check for the type(uint256).max sentinel BEFORE applying any clamping "
        "operation: `if (sizeDelta == type(uint256).max) { closeAll(); return; }` followed "
        "by `sizeDelta = _min(sizeDelta, cap);`. Alternatively, do not use type(uint256).max "
        "as a sentinel if the parameter is also subject to clamping."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue
            if is_vendored_or_test_contract(contract):
                continue

            for function in contract.functions_and_modifiers_declared:
                # Collect the first (lowest node_id) clamp event and sentinel check event.
                # node.node_id is an integer assigned in CFG construction order;
                # for linear functions it reliably reflects execution order.
                first_clamp_node = None      # node where clamping first occurs
                first_sentinel_node = None   # node where sentinel check first occurs

                for node in function.nodes:
                    if first_clamp_node is None and _node_has_clamp(node):
                        first_clamp_node = node
                    if first_sentinel_node is None and _node_has_sentinel_check(node):
                        first_sentinel_node = node

                # Both must be present; clamp must precede sentinel check
                if first_clamp_node is None or first_sentinel_node is None:
                    continue
                if first_clamp_node.node_id >= first_sentinel_node.node_id:
                    continue  # sentinel check comes first - clean pattern

                info: DETECTOR_INFO = [
                    function,
                    " clamps the value at node ",
                    first_clamp_node,
                    " (node_id=",
                    str(first_clamp_node.node_id),
                    ") BEFORE checking for the type(uint256).max sentinel at node ",
                    first_sentinel_node,
                    " (node_id=",
                    str(first_sentinel_node.node_id),
                    "). The sentinel is destroyed before it can be detected.\n",
                ]
                results.append(self.generate_result(info))

        return results
