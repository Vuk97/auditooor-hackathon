"""
bonding_curve_zero_cost_buy.py - Custom Slither detector.

Pattern: A bonding curve pricing function (_calculateY / getCost / getPrice /
priceOf) performs integer division (`BinaryType.DIVISION`) without a guard
that reverts when the result is zero.  For tiny input amounts, integer
division truncates to 0, letting callers acquire tokens for free by paying
nothing.

Source: reference/corpus_mined/slice_ae.md - GTE Launchpad (CRITICAL).
In that codebase, `_calculateY(x)` returned 0 for small `x`, and because
`finalIdx` was not updated on a partial step traversal, the attacker could
repeat the same tiny buy indefinitely accumulating tokens at zero cost.

Detection strategy:
  1. Match functions by name: name (lowercased) is one of or starts with:
       _calculatey, getcost, getprice, priceof, calculateprice, computeprice,
       bondingprice, curveprice, quoteprice, calcprice, calculatecost.
     OR the function name contains both "price" / "cost" / "curve" AND
     "calc" / "get" / "compute" / "quote" / "bonding".
  2. The function must declare a return value of uint type (checked via
     return_type string representation).
  3. Walk the function's nodes for any `Binary(DIVISION)` IR.
  4. Check for a zero-guard: look for any node in the function that
     (a) `contains_require_or_assert()` AND
     (b) has a `Binary` IR with type GREATER, GREATER_EQUAL, NOT_EQUAL,
         or a SolidityCall(require) where the argument contains a comparison.
     We check more concretely: scan ALL Binary IRs in require/assert nodes
     for comparisons against Constant(0).
  5. If division found AND no zero-guard found → flag.

IR note:
  `require(price > 0)` compiles to:
    Binary(GREATER)  price_tmp  [price_result, Constant(0)]
    SolidityCall(require)       [price_tmp]
  `require(amount >= MIN)` compiles to:
    Binary(GREATER_EQUAL)  ...  [amount, Constant(MIN)]

  A zero-guard exists if ANY require/assert node contains a Binary with
  GREATER / GREATER_EQUAL / NOT_EQUAL whose `.read` includes a Constant(0)
  OR a Binary with LESS / LESS_EQUAL / EQUAL whose `.read` includes a
  Constant(0) (covers `require(0 < price)` or `if (price == 0) revert()`).

  We use a broad guard: ANY comparison Binary in the function body
  whose one operand is Constant(0). This catches:
    require(price > 0)
    require(price != 0)
    if (price == 0) revert(...)
    require(amount > MIN_AMOUNT)   ← MIN_AMOUNT is NOT 0 but prevents dust;
      we only flag if NO zero-comparison exists.

Confidence: MEDIUM - name-based function matching; operators should verify
that the matched function is actually a pricing function on the buy path.
Impact: HIGH - free token acquisition drains bonding curve reserves.

@author auditooor
@pattern wave6 bonding-curve-zero-cost-buy
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
from slither.slithir.variables import Constant
from slither.utils.output import Output


SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")

# Exact lowercased function names to match.
_EXACT_NAMES = frozenset({
    "_calculatey",
    "getcost",
    "getprice",
    "priceof",
    "calculateprice",
    "computeprice",
    "bondingprice",
    "curveprice",
    "quoteprice",
    "calcprice",
    "calculatecost",
    "computecost",
    "quotecost",
    "_calculateprice",
    "_getcost",
    "_getprice",
    "buyprice",
    "sellprice",
})

# Substrings for the "contains both X and Y" heuristic.
_PRICE_TOKENS = ("price", "cost", "curve", "bonding")
_VERB_TOKENS = ("calc", "get", "compute", "quote", "bonding", "buy", "sell")

# Guard comparison types - any of these near Constant(0) means a zero-guard exists.
_GUARD_OPS = frozenset({
    BinaryType.GREATER,
    BinaryType.GREATER_EQUAL,
    BinaryType.NOT_EQUAL,
    BinaryType.LESS,
    BinaryType.LESS_EQUAL,
    BinaryType.EQUAL,
})


def _is_pricing_function(func) -> bool:
    """Return True if the function name looks like a bonding-curve pricing function."""
    low = func.name.lower()
    if low in _EXACT_NAMES:
        return True
    # Heuristic: name contains a price token AND a verb token.
    has_price = any(t in low for t in _PRICE_TOKENS)
    has_verb = any(t in low for t in _VERB_TOKENS)
    return has_price and has_verb


def _returns_uint(func) -> bool:
    """Return True if the function has a uint return type."""
    try:
        ret_type = func.return_type
        if not ret_type:
            return False
        # return_type is a list of Type objects for multiple return values,
        # or a single Type for single-return functions.  Handle both.
        if not isinstance(ret_type, list):
            ret_type = [ret_type]
        for t in ret_type:
            t_str = str(t).lower()
            if t_str.startswith("uint") or t_str == "uint":
                return True
    except Exception:
        pass
    return False


def _has_division_ir(func) -> "object | None":
    """Return the first node containing a DIVISION Binary IR, or None."""
    for node in func.nodes:
        for ir in node.irs:
            if isinstance(ir, Binary) and ir.type == BinaryType.DIVISION:
                return node
    return None


def _has_zero_guard(func) -> bool:
    """
    Return True if ANY node in the function has a comparison Binary op
    where one of the operands is a Constant with value 0.

    This catches:
      require(price > 0)            → Binary(GREATER, ..., [price_tmp, Constant(0)])
      require(price != 0)           → Binary(NOT_EQUAL, ...)
      if (price == 0) revert(...)   → Binary(EQUAL, ..., [price_tmp, Constant(0)])
      require(amount >= MIN_AMOUNT) → Binary(GREATER_EQUAL) with non-zero constant
        → only flagged if a Constant(0) is present; MIN_AMOUNT != 0 → no guard match
    """
    for node in func.nodes:
        # Check all nodes (require or not) since revert-if-zero can appear
        # as an if-branch with explicit revert, not just require().
        for ir in node.irs:
            if not isinstance(ir, Binary):
                continue
            if ir.type not in _GUARD_OPS:
                continue
            # Check if Constant(0) is one of the operands.
            for var in ir.read:
                if isinstance(var, Constant) and var.value == 0:
                    return True
    return False


class BondingCurveZeroCostBuy(AbstractDetector):
    """
    Detect bonding curve pricing functions that contain integer division without
    a revert-on-zero guard, enabling zero-cost token purchases.
    """

    ARGUMENT = "bonding-curve-zero-cost-buy"
    HELP = (
        "Bonding curve pricing function performs division without a zero-result "
        "guard; tiny inputs round price to 0, enabling free token acquisition"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Zero-Cost Token Purchase via Bonding Curve Rounding"
    WIKI_DESCRIPTION = (
        "A bonding curve pricing function (getCost, getPrice, _calculateY, etc.) "
        "computes the cost of a token purchase using integer division. For small "
        "input amounts, the division truncates to 0 without reverting. The "
        "calling buy function then accepts msg.value >= 0, and the attacker "
        "receives tokens for free. Repeating the attack with the same tiny "
        "amount accumulates unlimited tokens at zero cost. This exact pattern "
        "was observed as CRITICAL in the GTE Launchpad audit (Zellic, 2024): "
        "`_calculateY(x)` returned 0 for small `x`, and `finalIdx` was not "
        "updated, allowing infinite repeat buys."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
uint256 public totalSupply = 1_000_000e18;

function getPrice(uint256 amount) public view returns (uint256) {
    // For tiny amount (e.g. 1 wei), result rounds to 0
    return (amount * 1e18) / totalSupply;
}

function buy(uint256 amount) external payable {
    uint256 cost = getPrice(amount);
    require(msg.value >= cost, "insufficient");  // 0 >= 0 → passes
    // tokens minted to attacker for free
}
```
1. Attacker calls `buy(1)` with `msg.value = 0`.
2. `getPrice(1)` returns `(1 * 1e18) / 1_000_000e18 = 0` (integer division truncation).
3. `require(0 >= 0)` passes.
4. Attacker receives tokens for free. Repeating drains the bonding curve."""
    WIKI_RECOMMENDATION = (
        "Add `require(price > 0, \"dust amount\")` or `require(amount >= MIN_BUY, "
        "\"below minimum\")` immediately after the price computation. The minimum "
        "buy amount should be large enough that the computed price is always at "
        "least 1 wei. Alternatively, use a fixed-point math library (e.g. "
        "PRBMath, Solady FixedPointMathLib) that provides overflow-safe and "
        "rounding-safe division."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue
            if is_vendored_or_test_contract(contract):
                continue

            for func in contract.functions_and_modifiers_declared:
                # Step 1: name must look like a pricing function
                if not _is_pricing_function(func):
                    continue

                # Step 2: must return a uint type
                if not _returns_uint(func):
                    continue

                # Step 3: must contain a DIVISION Binary IR
                div_node = _has_division_ir(func)
                if div_node is None:
                    continue

                # Step 4: must NOT have a zero-guard
                if _has_zero_guard(func):
                    continue

                info: DETECTOR_INFO = [
                    func,
                    " performs integer division in a bonding curve pricing context "
                    "without a zero-result guard. ",
                    "Division at ",
                    div_node,
                    " can return 0 for small inputs, enabling zero-cost token "
                    "purchases. Add `require(price > 0)` or enforce a minimum "
                    "input amount.\n",
                ]
                results.append(self.generate_result(info))

        return results
