"""
approve_without_reset_dos.py - Custom Slither detector.

Pattern (Zellic slice_aa ONI-12, HIGH - 1inch Oct23 UnoswapRouter):
A function calls `token.approve(spender, nonZero)` without first calling
`token.approve(spender, 0)` on the same token+spender pair. Non-standard
ERC20s (USDT being the canonical example) revert inside `approve` when the
existing allowance is non-zero. A previously-executed approval that hasn't
been cleared will permanently DoS every subsequent swap/pull through the
same spender - not a theoretical issue, this has bricked multiple router
integrations in production.

Detection strategy (IR-level):
    1. For each function, walk HighLevelCall IRs, grouping approve() calls
       by (destination_token, arg0_spender) identity.
    2. An approve call is considered "non-zero" if arg1 is NOT a literal
       Constant(0).
    3. An approve call is "reset" if arg1 IS a literal Constant(0).
    4. If we observe a non-zero approve for (token, spender) and NO reset
       approve on the same (token, spender) in the same function → flag.
    5. We compare argument variables by Python identity (same LocalVariable
       object) - the same trick used by approve_then_transfer_unspent.

Distinct from:
    - wave6/approve_then_transfer_unspent: flags approve()+transfer() to the
      same recipient in the same function.
    - wave9/integration_setter_no_approval_rotation: flags an integration
      address setter that forgets to revoke the old address's approval.
    This detector flags the "set non-zero without prior zero" pattern that
    breaks specifically on USDT-style tokens.

@author auditooor wave10
@pattern slice_aa ONI-12
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
from slither.slithir.operations import HighLevelCall, TypeConversion
from slither.slithir.variables import Constant
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_APPROVE_SIGS = frozenset({
    "approve(address,uint256)",
    "safeApprove(address,uint256)",
    "forceApprove(address,uint256)",
})


def _is_zero_constant(v) -> bool:
    if not isinstance(v, Constant):
        return False
    try:
        return int(v.value) == 0
    except Exception:
        return False


def _resolve_token_source(node, destination):
    """
    Walk IRs in `node` and if `destination` is the lvalue of a TypeConversion,
    return the underlying source variable. Otherwise return `destination`.
    This unwraps the `IERC20(token)` cast that creates a fresh TMP per call.
    """
    for ir in node.irs:
        if isinstance(ir, TypeConversion) and ir.lvalue is destination:
            return ir.variable
    return destination


def _collect_approve_calls(function):
    """
    Return list of (ir, token_src, spender_var, amount_var, is_zero_reset).
    token_src is the underlying variable that the interface was cast from,
    so `IERC20(token).approve(...)` and `IERC20(token).approve(..., 0)` are
    recognised as calls against the same token.
    """
    out = []
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, HighLevelCall):
                continue
            callee = getattr(ir, "function", None)
            if callee is None:
                continue
            sig = getattr(callee, "solidity_signature", None)
            if sig not in _APPROVE_SIGS:
                continue
            args = list(ir.arguments) if ir.arguments else []
            if len(args) < 2:
                continue
            spender = args[0]
            amount = args[1]
            token_src = _resolve_token_source(node, ir.destination)
            out.append((ir, token_src, spender, amount, _is_zero_constant(amount)))
    return out


class ApproveWithoutResetDos(AbstractDetector):
    """Detect non-zero token.approve(spender) calls with no prior approve(spender, 0) reset."""

    ARGUMENT = "approve-without-reset-dos"
    HELP = (
        "ERC20 approve(spender, nonZero) called without a prior approve(spender, 0); "
        "non-standard tokens like USDT revert, permanently DoSing the integration"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Approve Without Zero Reset - USDT DoS"
    WIKI_DESCRIPTION = (
        "Tether (USDT) and a handful of other non-standard ERC20s include "
        "`require(allowance == 0 || value == 0)` in their `approve()` implementation. "
        "A contract that calls `token.approve(spender, X)` without first calling "
        "`token.approve(spender, 0)` reverts the second time it is invoked for the "
        "same (token, spender) pair whenever the previous allowance is still "
        "non-zero. In router or swap integrations this permanently bricks the "
        "affected spender/token combination. The 1inch UnoswapRouter `_curfe` "
        "helper shipped with this exact bug (Zellic ONI-12)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function swap(IERC20 token, address pool, uint256 amount) external {
    token.approve(pool, amount);          // BUG: no prior approve(pool, 0)
    IPool(pool).swap(amount);
}
```
1. First call sets allowance to `amount1`, `swap` pulls part of it, leaves
   a residual allowance.
2. Second call attempts `approve(pool, amount2)` while residual > 0.
3. USDT reverts inside `approve` → every subsequent swap through `pool`
   fails for the life of the contract."""
    WIKI_RECOMMENDATION = (
        "Use OpenZeppelin's SafeERC20 `forceApprove` / `safeApprove`, or "
        "explicitly call `approve(spender, 0)` before any non-zero approve. "
        "Do not rely on the ERC20 spec - USDT violates it."
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
                approves = _collect_approve_calls(function)
                if not approves:
                    continue

                # Group by (destination_contract_id, spender_id).
                # An (token, spender) pair is safe if at least one zero-reset
                # was emitted AT OR BEFORE a non-zero approve in textual order.
                # Simpler conservative rule: flag only if there is at least
                # one non-zero approve AND zero zero-resets on the same pair.
                pair_has_nonzero = {}
                pair_has_reset = {}
                pair_first_nonzero_ir = {}

                for ir, token_src, spender, amount, is_zero in approves:
                    # Key by (token source var id, spender var id). The token
                    # source is resolved through TypeConversion so
                    # IERC20(token).approve(...) pairs match each other.
                    key = (id(token_src), id(spender))
                    if is_zero:
                        pair_has_reset[key] = True
                    else:
                        pair_has_nonzero.setdefault(key, True)
                        pair_first_nonzero_ir.setdefault(key, ir)

                for key, _ in pair_has_nonzero.items():
                    if pair_has_reset.get(key):
                        continue
                    ir = pair_first_nonzero_ir[key]
                    info: DETECTOR_INFO = [
                        function,
                        " calls approve(spender, nonZero) at ",
                        ir.node,
                        " without a preceding approve(spender, 0) reset. "
                        "Non-standard ERC20s (USDT) will revert and brick this "
                        "integration. Use SafeERC20.forceApprove or zero first.\n",
                    ]
                    results.append(self.generate_result(info))

        return results
