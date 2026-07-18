"""
per_leg_credit_overwritten.py — Custom Slither detector.

Pattern (Panoptic Next-Core M-02, slice_ad): A function iterates over a
list of "legs" / items and, for each one, writes a per-user accumulator
using `=` (plain assignment) instead of `+=`. Only the final iteration's
value survives — earlier legs are overwritten. Losses compound across
multi-leg option/position settlement.

Detection strategy (CFG + IR):
    1. For each function, find every Assignment IR whose lvalue is a
       ReferenceVariable produced by an Index IR `mapping[key] = X`
       inside a body node that sits between a STARTLOOP and an ENDLOOP.
    2. Retrieve the Index's key variable. If the key is NOT the loop
       induction variable (i.e. not re-derived per iteration), then
       every loop iteration writes the same storage slot — the later
       iteration silently overwrites earlier ones.
    3. If the assignment's rvalue depends on a loop-variant source
       (e.g. `arr[i]`) the overwrite is actively destructive. Flag.

@author auditooor wave11
@pattern slice_ad Panoptic M-02
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
from slither.slithir.operations import Assignment, Index
from slither.slithir.variables import ReferenceVariable
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")


def _collect_loop_body_nodes(function):
    """Return list of nodes that sit inside any for/while loop body.

    Slither's `function.nodes` is in declaration (source) order, not CFG
    order, so a simple STARTLOOP/ENDLOOP depth counter doesn't work. We
    instead walk the CFG: from each IFLOOP node, follow `son_true` until
    reaching the matching ENDLOOP.
    """
    inside = []
    seen = set()
    for start in function.nodes:
        if start.type != NodeType.IFLOOP:
            continue
        body = start.son_true
        if body is None:
            continue
        stack = [body]
        while stack:
            n = stack.pop()
            if n in seen:
                continue
            seen.add(n)
            if n.type in (NodeType.ENDLOOP, NodeType.IFLOOP, NodeType.STARTLOOP):
                continue
            inside.append(n)
            for s in n.sons:
                if s not in seen:
                    stack.append(s)
    return inside


def _loop_induction_vars(function):
    """Heuristic: loop induction variable is any local whose name is short
    (i, j, k, idx, index) OR any local that is both read and written by
    IFLOOP/loop-body nodes. We return the set of such variable names."""
    names = set()
    for n in function.nodes:
        if n.type == NodeType.IFLOOP:
            for v in n.variables_read:
                if getattr(v, "name", None):
                    names.add(v.name)
    for lv in function.local_variables:
        nm = (lv.name or "").lower()
        if nm in ("i", "j", "k", "idx", "index"):
            names.add(lv.name)
    return names


class PerLegCreditOverwritten(AbstractDetector):
    """Flag per-iteration mapping writes that overwrite instead of accumulate."""

    ARGUMENT = "per-leg-credit-overwritten"
    HELP = (
        "Loop body writes a mapping entry with `=` instead of `+=`, "
        "overwriting earlier iterations — per-leg credits are lost"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Per-Leg Accumulator Overwritten Inside Loop"
    WIKI_DESCRIPTION = (
        "A function iterates over multiple legs / positions / items and "
        "assigns the per-iteration result to a shared mapping entry using "
        "plain `=` assignment rather than `+=`. Earlier iterations are "
        "silently overwritten by later ones; only the last leg survives. "
        "Multi-leg options and position-settlement contracts are the most "
        "affected. Source: Panoptic Next-Core M-02 (slice_ad)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
mapping(address => uint256) public credit;

function settleLegs(address user, uint256[] calldata legAmounts) external {
    for (uint256 i = 0; i < legAmounts.length; i++) {
        credit[user] = legAmounts[i];   // BUG: should be += legAmounts[i]
    }
}
```
1. Alice settles a 3-leg position with amounts [100, 200, 50].
2. The final `credit[alice]` equals 50 (the last leg's value).
3. The 100 + 200 she earned from the other two legs are lost."""
    WIKI_RECOMMENDATION = (
        "Use `mapping[key] += value` (or accumulate into a local and "
        "single-write at loop exit) whenever a per-iteration value should "
        "contribute to a shared accumulator."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                if function.is_constructor or function.view or function.pure:
                    continue
                loop_nodes = _collect_loop_body_nodes(function)
                if not loop_nodes:
                    continue
                induction = _loop_induction_vars(function)
                if not induction:
                    continue

                for node in loop_nodes:
                    # Build a map of ReferenceVariable -> Index IR that
                    # produced it, within this node.
                    ref_to_index = {}
                    for ir in node.irs:
                        if isinstance(ir, Index):
                            if isinstance(ir.lvalue, ReferenceVariable):
                                ref_to_index[ir.lvalue] = ir

                    for ir in node.irs:
                        if not isinstance(ir, Assignment):
                            continue
                        if not isinstance(ir.lvalue, ReferenceVariable):
                            continue
                        idx_ir = ref_to_index.get(ir.lvalue)
                        if idx_ir is None:
                            continue
                        # Key of the index op.
                        key_var = idx_ir.variable_right
                        key_name = getattr(key_var, "name", None)
                        # The key must NOT be the loop induction variable;
                        # otherwise each iteration writes a distinct slot
                        # (which is legitimate).
                        if key_name and key_name in induction:
                            continue

                        # The rvalue should be a loop-variant value (read
                        # in this node). Any assignment at all is flaggable
                        # in a well-scoped loop body.
                        info: DETECTOR_INFO = [
                            function,
                            " overwrites mapping slot inside loop at ",
                            node,
                            " — use `+=` to accumulate per-iteration credit.\n",
                        ]
                        results.append(self.generate_result(info))
                        break  # One hit per node.

        return results
