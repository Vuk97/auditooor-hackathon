"""
silent_fee_fallback_clamp.py - Custom Slither detector.

Pattern (Hybra Finance M-01, slice_ad): A fee / parameter setter silently
clamps an out-of-range input to a default fallback value (or early-returns)
instead of reverting. This masks governance mis-configuration - the caller
believes they set `fee = X` but the contract quietly installed the default.

Detection strategy:
    1. Iterate functions whose name matches `(set|update|configure).*(fee|
       rate|bps|percent|limit|cap)`.
    2. Walk each function for an IF node whose binary condition is a
       GREATER / GREATER_EQUAL against a parameter (user-supplied value).
    3. Follow the true-branch successors until the matching endif. If the
       true-branch contains a RETURN without any require/assert / revert
       AND contains at least one state/local assignment (the silent clamp),
       flag - the function swallowed the out-of-range input.

@author auditooor wave11
@pattern slice_ad Hybra M-01
"""

import re
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
from slither.slithir.operations import Binary, BinaryType, Assignment
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_NAME_RE = re.compile(
    r"^(set|update|configure|change|apply).*(fee|rate|bps|percent|limit|cap|basis)",
    re.IGNORECASE,
)

_COMPARE_TYPES = frozenset({BinaryType.GREATER, BinaryType.GREATER_EQUAL,
                            BinaryType.LESS, BinaryType.LESS_EQUAL})


def _walk_true_branch(if_node, max_nodes=32):
    """
    Walk successors of `if_node` along the true-branch (son_true) until we
    reach the matching END_IF or exhaust max_nodes. Returns the visited node
    list (excluding the IF itself and the terminating END_IF).
    """
    visited = []
    seen = {if_node}
    true_son = if_node.son_true
    if true_son is None:
        return visited
    stack = [true_son]
    while stack and len(visited) < max_nodes:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        if n.type == NodeType.ENDIF:
            # Don't cross the end of the if.
            continue
        visited.append(n)
        for s in n.sons:
            if s not in seen:
                stack.append(s)
    return visited


class SilentFeeFallbackClamp(AbstractDetector):
    """Flag fee setters that silently fall back to a default instead of reverting."""

    ARGUMENT = "silent-fee-fallback-clamp"
    HELP = (
        "Fee / rate setter silently clamps out-of-range input to a default "
        "(early-return) instead of reverting - masks governance misconfiguration"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Silent Fallback Clamp In Fee Setter"
    WIKI_DESCRIPTION = (
        "A fee / rate / percentage setter silently replaces an out-of-range "
        "input with a hard-coded fallback value and early-returns, instead "
        "of reverting the transaction. Governance call-sites therefore "
        "believe the parameter was installed, while the contract quietly "
        "uses the fallback. Source: Hybra Finance M-01 (slice_ad)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
uint256 public constant MAX_FEE = 100_000;   // 10%
uint256 public defaultFee = 3_000;
uint256 public fee;

function setFee(uint256 newFee) external {
    if (newFee > MAX_FEE) {
        fee = defaultFee;                     // BUG: silent clamp
        return;
    }
    fee = newFee;
}
```
1. Governance intends to raise the fee to 15%, calls `setFee(150_000)`.
2. The transaction does NOT revert; instead fee is silently set to the
   3% default and the tx completes.
3. Off-chain dashboards show the transaction as successful; the real fee
   parameter is wrong. Undetected for days."""
    WIKI_RECOMMENDATION = (
        "Revert on out-of-range input: `require(newFee <= MAX_FEE, \"fee "
        "too high\");`. Never silently substitute a default."
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
                if not _NAME_RE.search(function.name or ""):
                    continue
                if function.visibility not in ("public", "external"):
                    continue

                param_names = {p.name for p in (function.parameters or []) if p.name}
                if not param_names:
                    continue

                for node in function.nodes:
                    if node.type != NodeType.IF:
                        continue
                    # Look for a GREATER/LESS compare that references a parameter.
                    compares_param = False
                    for ir in node.irs:
                        if not isinstance(ir, Binary):
                            continue
                        if ir.type not in _COMPARE_TYPES:
                            continue
                        operand_names = set()
                        for v in (ir.variable_left, ir.variable_right):
                            nm = getattr(v, "name", None)
                            if nm:
                                operand_names.add(nm)
                        if operand_names & param_names:
                            compares_param = True
                            break
                    if not compares_param:
                        continue

                    branch_nodes = _walk_true_branch(node)
                    has_return = any(n.type == NodeType.RETURN for n in branch_nodes)
                    if not has_return:
                        continue
                    has_revert = any(
                        n.contains_require_or_assert() or n.type == NodeType.THROW
                        for n in branch_nodes
                    )
                    if has_revert:
                        continue
                    # Branch must also perform an assignment (the silent clamp).
                    has_assign = False
                    for n in branch_nodes:
                        for ir in n.irs:
                            if isinstance(ir, Assignment):
                                has_assign = True
                                break
                        if has_assign:
                            break
                    if not has_assign:
                        continue

                    info: DETECTOR_INFO = [
                        function,
                        " silently clamps an out-of-range input at ",
                        node,
                        " and early-returns instead of reverting. Governance "
                        "misconfiguration is masked - revert on the bound check.\n",
                    ]
                    results.append(self.generate_result(info))
                    break  # One finding per function is enough.

        return results
