"""
partial_slippage_uncapped.py - Custom Slither detector.

Pattern (Usual / slice_ac): When a swap function supports partial fill via a
bool parameter (`allowPartial`, `partial`, `isPartial`), the amount spent
must be scaled proportionally to the fill fraction (fillAmount / totalOrder).
If the code writes the full `maxAmountToSpend` (or equivalent cap) to a
spent/filled state variable WITHOUT applying a proportional scaling division,
the attacker can request a partial fill but spend the full cap - effectively
getting a discount.

Source: slice_ac Usual - partial fill path does not scale maxAmountToSpend.

Dedup check: no Slither builtin covers partial-fill cap scaling.
    slither --list-detectors | grep -iE 'partial|slippage|fill|swap' → 0 match
    (missing-slippage builtin exists but targets zero slippage arg, not partial fill).
    ARGUMENT differs from wave2 "missing-slippage" (glider-unchecked-transfer).

Detection strategy:
    1. Find functions with a bool parameter whose name (lowercased) contains
       "partial" or "allowpartial".
    2. In the same function, find state variable writes to a variable whose
       lowercased name contains a spent/filled hint:
       "spent", "filled", "amountspent", "totalspent", "amountout",
       "amountused", "amountpaid".
    3. For each such write, inspect the node in which it occurs. Check whether
       the node that WRITES the spent/filled variable (when inside a partial-
       branch) contains a Binary(DIVISION) IR - proxy for proportional scaling.
       If the write node (in the partial branch) does NOT contain a division → flag.

Approximation:
    - We identify the "partial branch" heuristically as any node in the function
      that (a) comes after an IF node reading the partial bool parameter AND
      (b) writes to the spent/filled state variable.
    - We check whether that node contains a DIVISION as a proxy for proportional
      scaling.  A mul-then-div pattern is the canonical fix; absence of division
      in the write node means raw cap is used.
    - Confidence: LOW - false positives possible on functions where division
      happens in a called internal function (not inlined).
    - We only check state variable writes (not local var writes) for precision.

IR insight:
    `amountSpent = maxAmountToSpend;` inside partial branch:
        node.state_variables_written contains amountSpent
        node.irs has no Binary(DIVISION) - flagged.

    `amountSpent = maxAmountToSpend * fillAmount / totalOrder;` inside partial branch:
        node.irs has Binary(MULTIPLICATION) then Binary(DIVISION) - safe.

@author auditooor wave7
@pattern slice_ac Usual partial fill maxSpend not scaled
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
from slither.core.cfg.node import NodeType
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")

# Parameter name substrings that indicate a partial-fill flag.
_PARTIAL_PARAM_HINTS = ("partial", "allowpartial", "ispartial", "isfill", "partialfill")

# State variable name substrings indicating an amount-spent / filled tracking var.
_SPENT_HINTS = (
    "spent",
    "filled",
    "amountspent",
    "amountout",
    "amountused",
    "amountpaid",
    "totalspent",
    "totalfilled",
    "amountin",
)


def _get_partial_param(function):
    """Return the bool parameter with a partial-fill name, or None."""
    for param in function.parameters:
        name = (param.name or '').lower()
        if any(h in name for h in _PARTIAL_PARAM_HINTS):
            return param
    return None


def _is_spent_sv(sv) -> bool:
    """Return True if the state variable name matches a spent/filled hint."""
    name = (sv.name or '').lower()
    return any(h in name for h in _SPENT_HINTS)


def _node_has_division(node) -> bool:
    """Return True if any IR in the node is a Binary(DIVISION)."""
    for ir in node.irs:
        if isinstance(ir, Binary) and "DIVISION" in str(ir.type).upper():
            return True
    return False


def _node_writes_spent_sv(node):
    """Return the first spent/filled StateVariable written in this node, or None."""
    for sv in node.state_variables_written:
        if _is_spent_sv(sv):
            return sv
    return None


def _node_reads_var(node, var) -> bool:
    """Return True if node reads the given variable (by identity)."""
    return var in node.local_variables_read


class PartialSlippageUncapped(AbstractDetector):
    """
    Detect swap functions with a partial-fill bool that write maxAmountToSpend
    to a spent/filled state variable without proportional scaling (no division).
    """

    ARGUMENT = "partial-slippage-uncapped"
    HELP = (
        "Swap function with partial-fill bool writes full max-spend cap to "
        "spent/filled state variable without proportional scaling - "
        "partial fill spends full cap"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Partial Fill Slippage Cap Not Scaled Proportionally"
    WIKI_DESCRIPTION = (
        "When a swap function supports partial fill (controlled by an `allowPartial` "
        "bool), the amount spent or filled must be scaled proportionally to the "
        "fraction of the order that was executed: "
        "`amountSpent = maxAmountToSpend * fillAmount / totalOrder`. "
        "If the code instead writes the full `maxAmountToSpend` to the spent state "
        "variable when a partial fill is taken, the caller is charged the full cap "
        "for a fractional execution - or an attacker can exploit the mismatch to "
        "receive more output tokens than the input entitles them to. "
        "Observed in Usual (slice_ac)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
uint256 public amountSpent;

function swap(
    uint256 totalOrder,
    uint256 fillAmount,
    uint256 maxAmountToSpend,
    bool allowPartial
) external {
    if (allowPartial && fillAmount < totalOrder) {
        amountSpent = maxAmountToSpend;  // BUG: should be proportional
    } else {
        amountSpent = maxAmountToSpend * fillAmount / totalOrder;
    }
}
```
1. Attacker creates an order with `totalOrder = 1000`, `maxAmountToSpend = 100`,
   `fillAmount = 1`, `allowPartial = true`.
2. Partial fill path executes: `amountSpent = 100` (the full cap).
3. Attacker received output for `fillAmount = 1` but was charged for `100` units
   (or, depending on direction, received 100 worth of output for 1 unit of input).
4. Attacker repeats until the pool is drained."""
    WIKI_RECOMMENDATION = (
        "Always scale the spend cap proportionally to the fill fraction in the "
        "partial-fill branch: "
        "`amountSpent = maxAmountToSpend * fillAmount / totalOrder`. "
        "Use a fixed-point library (e.g. PRBMath, Solady FixedPointMath) for "
        "precision if fillAmount/totalOrder is small."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                if function.view or function.pure:
                    continue

                # Must have a partial-fill bool parameter
                partial_param = _get_partial_param(function)
                if partial_param is None:
                    continue

                nodes = function.nodes

                # Locate the IF node that checks the partial param - after it
                # we are in the partial branch.
                partial_if_idx = None
                for i, node in enumerate(nodes):
                    if node.type != NodeType.IF:
                        continue
                    if _node_reads_var(node, partial_param):
                        partial_if_idx = i
                        break

                if partial_if_idx is None:
                    continue

                # Look for a spent/filled state variable write in nodes after
                # the partial IF that does NOT include a division.
                for i in range(partial_if_idx + 1, len(nodes)):
                    node = nodes[i]
                    sv = _node_writes_spent_sv(node)
                    if sv is None:
                        continue

                    # If the write node contains a division → properly scaled → safe
                    if _node_has_division(node):
                        continue

                    info: DETECTOR_INFO = [
                        function,
                        " writes ",
                        sv,
                        " at ",
                        node,
                        " in the partial-fill branch (after partial param check at node "
                        + str(partial_if_idx) + ") without a proportional division. "
                        "The full cap is charged on a partial fill - scale by "
                        "`fillAmount / totalOrder`.\n",
                    ]
                    results.append(self.generate_result(info))
                    break  # one report per function

        return results
