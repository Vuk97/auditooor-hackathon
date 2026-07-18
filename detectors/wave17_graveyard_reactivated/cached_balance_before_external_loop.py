"""
cached_balance_before_external_loop.py - Custom Slither detector.

Pattern (Zellic slice_aa line 350, CRITICAL): A helper function caches
`bal = token.balanceOf(address(this))` BEFORE a loop that calls external
contracts. Each iteration uses the stale cached `bal` while computing deltas
against the current `token.balanceOf(...)`. A rogue callee can reentrantly
change the real balance mid-loop; the cached value no longer reflects truth
and subsequent deltas are wrong - either over- or under-counting funds.

Detection strategy:
    1. Find a local variable assigned from a HighLevelCall whose
       `solidity_signature == "balanceOf(address)"`.
    2. That assignment node must occur at an index BEFORE the first
       STARTLOOP node in the function's node list.
    3. Within the loop (any STARTLOOP..ENDLOOP span that the assignment
       precedes), at least one HighLevelCall must occur to a DIFFERENT
       function name than `balanceOf` - i.e. an external call that could
       mutate the token balance.
    4. The cached local must NOT be re-assigned inside the loop (otherwise
       the developer is refreshing the cache manually).

@author auditooor wave8
@pattern slice_aa line 350
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
from slither.core.cfg.node import NodeType
from slither.core.declarations import Function
from slither.core.variables.local_variable import LocalVariable
from slither.slithir.operations import HighLevelCall, Assignment
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")
_BALANCE_SIG = "balanceOf(address)"


def _find_cached_balance(function):
    """
    Return list of (idx, node, local_var) for every local variable assigned
    from a `balanceOf(address)` HighLevelCall at that node.
    """
    results = []
    for idx, node in enumerate(function.nodes):
        # Collect tmp lvalues from balanceOf HLCs in this node.
        balance_tmps = set()
        for ir in node.irs:
            if isinstance(ir, HighLevelCall):
                callee = ir.function
                sig = getattr(callee, "solidity_signature", None)
                if sig == _BALANCE_SIG:
                    lv = getattr(ir, "lvalue", None)
                    if lv is not None:
                        balance_tmps.add(id(lv))
        if not balance_tmps:
            continue
        for ir in node.irs:
            if isinstance(ir, Assignment):
                rv = ir.rvalue
                if rv is None:
                    continue
                if id(rv) in balance_tmps and isinstance(ir.lvalue, LocalVariable):
                    results.append((idx, node, ir.lvalue))
    return results


def _first_loop_index(function):
    for idx, node in enumerate(function.nodes):
        if node.type == NodeType.STARTLOOP:
            return idx
    return None


def _collect_loop_body_nodes(function, start_idx):
    """
    Return nodes reachable from the STARTLOOP at start_idx via CFG successors.
    Slither's node-list order interleaves STARTLOOP/ENDLOOP headers with loop
    bodies in a way that makes simple index slicing unreliable, so we walk the
    CFG instead. We stop at function.nodes boundaries and drop the STARTLOOP
    itself. Cycles are tracked via a visited set.
    """
    start = function.nodes[start_idx]
    visited = set()
    stack = [start]
    body = []
    while stack:
        n = stack.pop()
        nid = id(n)
        if nid in visited:
            continue
        visited.add(nid)
        if n is not start:
            body.append(n)
        for son in getattr(n, "sons", []) or []:
            stack.append(son)
    return body


class CachedBalanceBeforeExternalLoop(AbstractDetector):
    """Detect balanceOf caching before a loop that makes external calls."""

    ARGUMENT = "cached-balance-before-external-loop"
    HELP = (
        "Local balance cache captured before a loop that makes external "
        "calls - reentrant callees can stale-out the cached value"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Cached Balance Before External Loop - Stale Delta"
    WIKI_DESCRIPTION = (
        "When a helper caches `bal = token.balanceOf(address(this))` once before "
        "a loop that calls external contracts (pods, strategies, hooks), any "
        "callee that mutates the token balance leaves the cached variable out of "
        "sync with reality. Subsequent `bal - balanceOf()` deltas inside the loop "
        "then mis-attribute funds. The bug is particularly dangerous when the "
        "helper is used for fee accounting or strategy accounting because the "
        "downstream writes persist the wrong numbers to storage."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
uint256 bal = token.balanceOf(address(this));        // cached once
for (uint256 i = 0; i < pods.length; i++) {
    IPod(pods[i]).update();                          // reentrant
    deltas[i] = bal - token.balanceOf(address(this));// uses stale bal
}
```
A rogue pod contract reentrantly pulls tokens from the manager during its
`update()` call. The cached `bal` still reflects the pre-loop balance, so the
delta for every subsequent pod is inflated - a later write that trusts the
delta mis-credits or double-counts token flows."""
    WIKI_RECOMMENDATION = (
        "Re-read the balance before and after EACH external call inside the "
        "loop, or use a reentrancy guard and avoid relying on balance deltas."
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

                cached = _find_cached_balance(function)
                if not cached:
                    continue

                loop_start = _first_loop_index(function)
                if loop_start is None:
                    continue
                body_nodes = _collect_loop_body_nodes(function, loop_start)

                for c_idx, c_node, c_local in cached:
                    # Must be assigned BEFORE the loop.
                    if c_idx >= loop_start:
                        continue

                    # Inside the loop, look for any HighLevelCall that is NOT
                    # to balanceOf. That's our "external mutation" signal.
                    has_external_mutator = False
                    re_assigned_in_loop = False
                    for node in body_nodes:
                        # Re-assignment of the cached local inside the loop?
                        if c_local in node.local_variables_written:
                            re_assigned_in_loop = True
                        for ir in node.irs:
                            if isinstance(ir, HighLevelCall):
                                callee = ir.function
                                if not isinstance(callee, Function):
                                    continue
                                sig = getattr(callee, "solidity_signature", None)
                                if sig == _BALANCE_SIG:
                                    continue
                                has_external_mutator = True
                    if not has_external_mutator:
                        continue
                    if re_assigned_in_loop:
                        continue

                    info: DETECTOR_INFO = [
                        function,
                        " caches balanceOf into local ",
                        c_local,
                        " at ",
                        c_node,
                        " before a loop that makes external calls - a reentrant "
                        "callee can stale the cached value, producing wrong "
                        "deltas. Re-read balanceOf inside the loop body.\n",
                    ]
                    results.append(self.generate_result(info))

        return results
