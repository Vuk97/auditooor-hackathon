"""
layerzero_dust_minamountld_eq.py - Custom Slither detector.

Pattern (Brix M-02, slice_ad): a LayerZero OFT adapter calls the OFT
`send` / `sendFrom` entrypoint with `minAmountLD == amountLD`. This
leaves zero room for the destination chain's shared-decimals
truncation, so any value that hits the LD floor permanently reverts -
small bridges DoS forever.

Detection strategy:
    1. Walk every HighLevelCall to a function whose name is `send` or
       `sendFrom` (or starts with `_send`) on an interface whose name
       matches `(?i)IOFT|ILayerZero|IOApp` (or whose callee Function
       has parameters named `amountLD` / `minAmountLD`).
    2. Find the index of the `amountLD` and `minAmountLD` parameters
       on the callee. Compare the SlithIR variables passed at those
       positions. If they are the same Variable object, flag.

@author auditooor wave9
@pattern slice_ad Brix M-02
"""

import re
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.core.declarations import Function
from slither.slithir.operations import HighLevelCall
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_OFT_INTERFACE_RE = re.compile(r"(IOFT|ILayerZero|IOApp|OFT|LZ)", re.IGNORECASE)


def _ir_callee_name(ir: HighLevelCall) -> str:
    if isinstance(ir.function, Function):
        sig = ir.function.solidity_signature or ""
        return sig.split("(")[0]
    return getattr(ir, "function_name", None) or ""


def _is_send_call(ir: HighLevelCall) -> bool:
    name = _ir_callee_name(ir)
    if not name:
        return False
    return name == "send" or name == "sendFrom" or name.startswith("_send")


def _callee_looks_like_oft(ir: HighLevelCall) -> bool:
    callee = ir.function
    if not isinstance(callee, Function):
        return False
    parent = getattr(callee, "contract", None)
    parent_name = (getattr(parent, "name", "") or "")
    if _OFT_INTERFACE_RE.search(parent_name):
        return True
    # Fallback: param names mention amountLD / minAmountLD.
    pnames = {(getattr(p, "name", "") or "").lower() for p in callee.parameters}
    return ("amountld" in pnames) and ("minamountld" in pnames)


def _amount_minamount_indices(callee: Function):
    """Return (idx_amountLD, idx_minAmountLD) on the callee, or (-1,-1)."""
    amt_idx = -1
    min_idx = -1
    for i, p in enumerate(callee.parameters):
        nm = (getattr(p, "name", "") or "").lower()
        if nm == "amountld":
            amt_idx = i
        elif nm == "minamountld":
            min_idx = i
    return amt_idx, min_idx


class LayerzeroDustMinAmountLdEq(AbstractDetector):
    """LayerZero OFT send call passes minAmountLD == amountLD."""

    ARGUMENT = "layerzero-dust-minamountld-eq"
    HELP = (
        "LayerZero OFT send is called with minAmountLD == amountLD - leaves "
        "no headroom for shared-decimals truncation on destination chain"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "LayerZero OFT minAmountLD Equals amountLD"
    WIKI_DESCRIPTION = (
        "A LayerZero OFT adapter calls `send` / `sendFrom` with the same "
        "value for both `amountLD` and `minAmountLD`. LayerZero OFT converts "
        "amounts to the chain-shared-decimals on the receiving end, which can "
        "truncate a few units of dust off the value. Because `minAmountLD` "
        "equals the requested amount, the destination chain's check "
        "`amountReceivedLD >= minAmountLD` always reverts, and the bridge is "
        "effectively bricked for any value below the LD floor. Confirmed in "
        "Brix M-02."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function bridge(uint32 dst, bytes32 to, uint256 amt) external payable {
    oft.send{value: msg.value}(dst, to, amt, amt); // BUG
}
```
A user bridges 1.234567890123456789 tokens. On the destination chain
LayerZero truncates the value to shared-decimals (typically 6) which
yields a slightly lower number; the receiving check sees the truncated
amount < minAmountLD and reverts. The fee is paid, the message sits
stuck - DoS forever."""
    WIKI_RECOMMENDATION = (
        "Take `minAmountLD` as a function parameter (or compute it as "
        "`amountLD * (10000 - tolerance) / 10000`) so there is room for the "
        "shared-decimals conversion at the destination."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions_declared:
                for node in function.nodes:
                    for ir in node.irs:
                        if not isinstance(ir, HighLevelCall):
                            continue
                        if not _is_send_call(ir):
                            continue
                        if not _callee_looks_like_oft(ir):
                            continue
                        callee = ir.function
                        if not isinstance(callee, Function):
                            continue
                        amt_idx, min_idx = _amount_minamount_indices(callee)
                        if amt_idx < 0 or min_idx < 0:
                            continue
                        args = getattr(ir, "arguments", None) or []
                        if amt_idx >= len(args) or min_idx >= len(args):
                            continue
                        amt_arg = args[amt_idx]
                        min_arg = args[min_idx]
                        if amt_arg is min_arg:
                            info: DETECTOR_INFO = [
                                function,
                                " calls a LayerZero OFT send with "
                                "minAmountLD == amountLD at ",
                                node,
                                " - leaves zero headroom for shared-decimals "
                                "truncation; small bridges revert forever.\n",
                            ]
                            results.append(self.generate_result(info))

        return results
