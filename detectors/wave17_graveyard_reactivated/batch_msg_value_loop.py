"""
batch_msg_value_loop.py - Custom Slither detector.

Pattern (Zellic slice_ab t3rn Batch-Native-Value-Always-Sent, MEDIUM):
A batch/confirm function forwards `msg.value` to an external call INSIDE a
loop over user-supplied orders. Every iteration receives the full msg.value,
so:
  1. ERC20-only orders accidentally receive native ETH that is either silently
     lost inside the target or reverts the whole batch.
  2. If the target contract believes the full msg.value each time, invariant
     math is double-counted.
  3. In the best case the second iteration's call has zero balance and
     reverts - a DoS on all multi-order batches.

The same class appears whenever a "batch" endpoint is added to a single-order
entrypoint and the author forgets that `msg.value` is a constant across the
entire transaction and cannot be re-used per-iteration.

Detection strategy:
    1. Find every HighLevelCall whose `call_value` is a SolidityVariable named
       "msg.value".
    2. The node containing that IR must be on a CFG path reachable from a
       STARTLOOP node - i.e. the call is inside a loop body.
    3. The loop body must not include an `msg.value -= X`-style write, because
       `msg.value` is a Solidity variable and cannot be re-assigned; the only
       safe fix is a per-order value accumulator. So if we see `{value: msg.value}`
       inside a loop at all, it is almost certainly wrong.
    4. Flag the call.

@author auditooor wave10
@pattern slice_ab t3rn Batch-Native-Value-Always-Sent
"""

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.core.cfg.node import NodeType
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.slithir.operations import HighLevelCall
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")


def _nodes_in_any_loop(function):
    """Return set of node ids that are reachable from any STARTLOOP node via
    CFG successors (excluding the STARTLOOP itself and any ENDLOOP terminators)."""
    in_loop = set()
    for start in function.nodes:
        if start.type != NodeType.STARTLOOP:
            continue
        visited = set()
        stack = [start]
        while stack:
            n = stack.pop()
            nid = id(n)
            if nid in visited:
                continue
            visited.add(nid)
            if n.type == NodeType.ENDLOOP and n is not start:
                # don't cross out of this loop
                continue
            if n is not start:
                in_loop.add(nid)
            for son in (getattr(n, "sons", []) or []):
                stack.append(son)
    return in_loop


def _is_msg_value(var) -> bool:
    if var is None:
        return False
    return getattr(var, "name", None) == "msg.value"


class BatchMsgValueLoop(AbstractDetector):
    """Detect {value: msg.value} forwarding inside a loop body."""

    ARGUMENT = "batch-msg-value-loop"
    HELP = (
        "External call inside a loop forwards msg.value on every iteration; "
        "multi-item batches will double-send / revert / lose funds"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "msg.value Forwarded Inside Batch Loop"
    WIKI_DESCRIPTION = (
        "`msg.value` is a transaction-level constant - the same value is visible "
        "on every line of the transaction. When a batch/confirm function calls "
        "an external target with `{value: msg.value}` inside a `for` loop, each "
        "iteration attempts to forward the full msg.value. The second iteration "
        "either reverts (contract balance insufficient) or, for payable targets "
        "that accept overpayment, silently eats the native value that belonged "
        "to the ERC-20 leg of the batch. t3rn's `confirmOrderBatch` shipped with "
        "this exact bug (Zellic June 2025)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function confirmOrderBatch(Order[] calldata orders) external payable {
    for (uint256 i = 0; i < orders.length; ++i) {
        // BUG: msg.value forwarded every iteration
        target.execute{value: msg.value}(orders[i].id, orders[i].recipient);
    }
}
```
User sends 1 ETH with a 3-order batch. Iteration 0 forwards 1 ETH to the
target. Iteration 1 reverts on `OutOfFunds` because the contract no longer
holds 1 ETH - or worse, the target is permissive and credits 1 ETH to every
order, so the relayer can claim 3 ETH worth of native payouts for a 1 ETH
deposit."""
    WIKI_RECOMMENDATION = (
        "Accumulate a per-order value field (`orders[i].value`) and forward "
        "that instead. Assert that the sum equals msg.value at the top of "
        "the function so unused native value cannot leak."
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
                loop_nodes = _nodes_in_any_loop(function)
                if not loop_nodes:
                    continue

                for node in function.nodes:
                    if id(node) not in loop_nodes:
                        continue
                    for ir in node.irs:
                        if not isinstance(ir, HighLevelCall):
                            continue
                        cv = getattr(ir, "call_value", None)
                        if not _is_msg_value(cv):
                            continue
                        info: DETECTOR_INFO = [
                            function,
                            " forwards msg.value inside a loop at ",
                            node,
                            " - every iteration re-sends the full native value. "
                            "Track a per-item value and sum-check msg.value.\n",
                        ]
                        results.append(self.generate_result(info))

        return results
