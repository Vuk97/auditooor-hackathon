"""
fee_deducted_before_noop_branch.py - Custom Slither detector.

Pattern (Bloom / Avantis SLUpdateFeeDoubleAccrual): A function calls a fee-accrual
helper (name contains "fee" or "accrue") UNCONDITIONALLY, then later contains a
conditional early-return that makes the rest of the function a no-op for certain
inputs (e.g. `if (amount == 0) return;`). When the no-op path is taken, the fee
has already been charged on a transaction that does nothing - double-charging or
spurious fee accrual.

Source: slice_ad Bloom/Avantis - SLUpdateFeeDoubleAccrual.
"handleFees() called before amount == 0 guard; fee accrued on no-op deposit path."

Dedup check: no Slither builtin covers fee-before-noop-branch ordering.
    slither --list-detectors | grep -iE 'fee|accrue|noop' → 0 builtins match.

Detection strategy:
    1. Walk functions. For each function, collect in node order:
       a. FEE_NODES: nodes that contain an InternalCall to a function whose
          name (lowercased) contains "fee" or "accrue".
       b. NOOP_NODES: nodes that (a) contain an IF condition AND (b) have a
          successor path that leads to a RETURN node without further state writes
          - i.e., an early-return guard.
          Approximation: we simply check for nodes that contain_if() AND whose
          source contains "return" OR we check: any node in function.nodes that is
          a NodeType.IF immediately followed by a RETURN node in the node list.
    2. If any FEE_NODE appears at a lower index than any NOOP_NODE → flag.

Node ordering: function.nodes gives CFG order. For linear functions (typical for
fee+early-return patterns) this approximates execution order. NodeType.IF is the
conditional branch point; a following NodeType.RETURN node (often the IF's
"true" branch) indicates the early-return path.

API notes:
    - NodeType is imported from slither.core.cfg.node.
    - InternalCall.function gives the callee Function; check .name.lower().
    - We collect FEE_NODE index and NOOP_NODE index (positions in function.nodes)
      and compare them.

Approximation:
    - Fee helper must be INTERNAL (InternalCall). External fee helpers (not
      InternalCall) are not caught - acceptable heuristic.
    - We require the noop to be an IF node followed by a RETURN-type node to
      reduce false positives from normal conditional logic.
    - Confidence: LOW - false positives on intentional "fee first, then validate"
      patterns (e.g. fee taken before amount validation for gas efficiency).

@author auditooor wave7
@pattern slice_ad FeeBeforeNoopBranch
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
from slither.slithir.operations import InternalCall
from slither.core.cfg.node import NodeType
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")

# Name fragments (lowercased) that identify a fee/accrue helper.
_FEE_HINTS = ("fee", "accrue", "handlefee", "collectfee", "chargefee",
              "deductfee", "distributyfee", "addtofee", "updatefee")


def _is_fee_call(ir) -> bool:
    """Return True if ir is an InternalCall to a fee/accrue-named function."""
    if not isinstance(ir, InternalCall):
        return False
    callee = getattr(ir, 'function', None)
    if callee is None:
        return False
    name = (getattr(callee, 'name', None) or '').lower()
    return any(h in name for h in _FEE_HINTS)


def _node_has_fee_call(node) -> bool:
    """Return True if any IR in this node is a fee/accrue InternalCall."""
    return any(_is_fee_call(ir) for ir in node.irs)


def _get_fee_callee(node):
    """Return the callee function of the first fee InternalCall in the node."""
    for ir in node.irs:
        if _is_fee_call(ir):
            return getattr(ir, 'function', None)
    return None


class FeeDeductedBeforeNoopBranch(AbstractDetector):
    """
    Detect functions that call a fee/accrue helper before an early-return guard -
    fee is charged even on the no-op code path.
    """

    ARGUMENT = "fee-deducted-before-noop-branch"
    HELP = (
        "Fee/accrue helper called before an early-return guard - "
        "fee is deducted on the no-op path (e.g. amount == 0)"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Fee Deducted Before No-Op Branch Guard"
    WIKI_DESCRIPTION = (
        "A function calls a fee-accrual helper (e.g. handleFees, accrueFees) "
        "unconditionally before an early-return guard such as "
        "`if (amount == 0) return;`. When the guard triggers and the transaction "
        "is a no-op, the fee was already accrued - the caller pays a fee for a "
        "transaction that did nothing. In protocols with automated callers this "
        "can be exploited to drain the fee accumulator via zero-amount no-op calls. "
        "Observed in Bloom / Avantis (SLUpdateFeeDoubleAccrual, slice_ad)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
uint256 public accruedFees;

function _handleFees(uint256 amount) internal {
    accruedFees += amount / 100;  // fee accrued unconditionally
}

function processDeposit(address user, uint256 amount) external {
    _handleFees(amount);      // BUG: fee charged before guard
    if (amount == 0) return;  // no-op path - fee already taken
    balances[user] += amount;
}
```
1. Attacker calls `processDeposit(attacker, 0)` in a loop.
2. Each call: `_handleFees(0)` accrues `accruedFees += 0/100 = 0` (or non-zero
   if rounding differs), then `if (amount == 0) return` exits.
3. In variants with a flat fee (not proportional): each no-op call deducts a
   fixed fee from the caller for zero value received."""
    WIKI_RECOMMENDATION = (
        "Move all early-return guards to the TOP of the function, before any "
        "fee or accrue calls: `if (amount == 0) return; _handleFees(amount);`. "
        "The canonical CEI (Checks-Effects-Interactions) pattern applies to "
        "fee accrual too: check validity first, then apply effects."
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
                if function.is_constructor:
                    continue

                nodes = function.nodes
                if len(nodes) < 3:
                    continue

                # Find first fee-call node index
                fee_node_idx = None
                fee_node = None
                for i, node in enumerate(nodes):
                    if _node_has_fee_call(node):
                        fee_node_idx = i
                        fee_node = node
                        break  # only care about the FIRST fee call

                if fee_node_idx is None:
                    continue

                # Find first IF node AFTER the fee node that is followed by
                # a RETURN-type node (early return guard).
                noop_node = None
                for i in range(fee_node_idx + 1, len(nodes)):
                    node = nodes[i]
                    if node.type != NodeType.IF:
                        continue
                    # Check if any successor is a RETURN node
                    for succ in node.sons:
                        if succ.type == NodeType.RETURN:
                            noop_node = node
                            break
                    if noop_node is not None:
                        break

                if noop_node is None:
                    continue

                # Fee call appears BEFORE the early-return IF → flag
                callee = _get_fee_callee(fee_node)
                callee_name = (getattr(callee, 'name', None) or 'fee helper') if callee else 'fee helper'

                info: DETECTOR_INFO = [
                    function,
                    " calls fee helper `",
                    callee_name,
                    "` at ",
                    fee_node,
                    " before the early-return guard at ",
                    noop_node,
                    ". Fee is accrued even on the no-op path - "
                    "move the guard above the fee call.\n",
                ]
                results.append(self.generate_result(info))

        return results
