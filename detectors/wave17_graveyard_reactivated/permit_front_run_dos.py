"""
permit_front_run_dos.py - Custom Slither detector.

Pattern (LoopFi permit-frontrun-DoS, slice_aa P42):
    A function calls `token.permit(owner, spender, value, deadline, v, r, s)`
    DIRECTLY (not wrapped in try/catch). An attacker watching the mempool
    can extract (owner, spender, v, r, s) from the user's tx, replay
    `token.permit(...)` themselves with higher gas, and consume the
    signature. The original transaction then reverts inside the bare
    `permit()` call → DoS the user's deposit/zap/etc.

Detection strategy:
    1. Walk every function in non-vendored contracts.
    2. For each node, look for HighLevelCall IRs whose target function name
       is exactly `permit`.
    3. Flag the call if its containing node is NOT of NodeType.TRY (i.e.
       the permit call is not the "try ... { } catch { }" target).

@author auditooor wave9
@pattern slice_aa P42 / LoopFi permit-frontrun-DoS
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
from slither.slithir.operations import HighLevelCall
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")


def _is_permit_call(ir) -> bool:
    if not isinstance(ir, HighLevelCall):
        return False
    fn = ir.function
    if not isinstance(fn, Function):
        return False
    if (fn.name or "") != "permit":
        return False
    # Sanity: ERC-2612 permit has 7 parameters
    params = fn.parameters or []
    return len(params) == 7


class PermitFrontRunDos(AbstractDetector):
    """Detect bare token.permit() calls that are vulnerable to front-run DoS."""

    ARGUMENT = "permit-front-run-dos"
    HELP = (
        "token.permit() called outside try/catch - attacker can front-run the "
        "permit and DoS the wrapping function"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "ERC-2612 Permit Front-Run DoS"
    WIKI_DESCRIPTION = (
        "When a function calls `token.permit(owner, spender, value, deadline, "
        "v, r, s)` directly, the (v, r, s) tuple sits in the public mempool "
        "the moment the user broadcasts. An attacker can copy the signature "
        "into their own transaction, call `token.permit(...)` first with "
        "higher gas, and consume the signature. The user's original transaction "
        "then reverts inside the bare `permit()` call (signature already used), "
        "preventing the deposit/zap/repay flow that follows. Wrapping the "
        "permit call in `try/catch` makes the failure non-blocking. Reported "
        "in LoopFi (slice_aa P42)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function deposit(IERC20Permit t, uint256 v, uint256 d, uint8 pv, bytes32 pr, bytes32 ps) external {
    t.permit(msg.sender, address(this), v, d, pv, pr, ps);   // bare call
    t.transferFrom(msg.sender, address(this), v);
}
```
1. Alice signs a permit and broadcasts deposit(...).
2. Mallory front-runs with `t.permit(alice, vault, v, d, pv, pr, ps)`.
3. Alice's tx reverts at the bare permit() - deposit DoS-ed."""
    WIKI_RECOMMENDATION = (
        "Wrap the permit call in `try { token.permit(...); } catch {}` so "
        "front-running the permit only causes the catch block to swallow the "
        "revert, after which the subsequent transferFrom still succeeds because "
        "the allowance was set by the front-runner's permit call."
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

                for node in function.nodes:
                    # Skip if this node is the TRY anchor - its IRs are guarded.
                    if node.type == NodeType.TRY:
                        continue
                    for ir in node.irs:
                        if not _is_permit_call(ir):
                            continue
                        info: DETECTOR_INFO = [
                            function,
                            " calls token.permit() at ",
                            node,
                            " outside any try/catch. An attacker can "
                            "front-run the permit and DoS this function. "
                            "Wrap the call in try { ... } catch {}.\n",
                        ]
                        results.append(self.generate_result(info))

        return results
