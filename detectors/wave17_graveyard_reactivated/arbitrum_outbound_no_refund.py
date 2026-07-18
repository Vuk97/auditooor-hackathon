"""
arbitrum_outbound_no_refund.py - Custom Slither detector.

Pattern (Zellic slice_af Mitosis Vault, HIGH): a bridge helper calls
`outboundTransfer(...)` on an Arbitrum gateway. That variant sends any excess
ETH / gas refund back to `msg.sender` - which, in a contract-mediated bridge
flow, is the helper contract itself, NOT the end user. Refund ETH is stranded
in the bridge contract. The correct API is `outboundTransferCustomRefund(...)`
which takes an explicit `refundTo` parameter and routes the refund to the user.

Detection strategy:
    1. Walk every function in every non-vendored contract.
    2. For each HighLevelCall IR whose target function is named
       `outboundTransfer`, flag the call site. The Arbitrum gateway interface
       has both `outboundTransfer(address,address,uint256,uint256,uint256,bytes)`
       and `outboundTransferCustomRefund(address,address,address,...)` - we
       match by exact name (not signature) so any ABI variant is caught.
    3. Skip calls to `outboundTransferCustomRefund` (different name, safe).
    4. Use HighLevelCall.function.name rather than solidity_signature because
       the same gateway has multiple overloads and we want the distinct
       function name family.

Dedup: no Slither builtin or wave1..10 detector covers Arbitrum gateway API
selection. `missing-slippage` and related bridge detectors target different
primitives.

@author auditooor wave11
@pattern slice_af Mitosis Vault
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
from slither.core.declarations import Function
from slither.slithir.operations import HighLevelCall
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")


class ArbitrumOutboundNoRefund(AbstractDetector):
    """
    Detect Arbitrum gateway `outboundTransfer` calls that should be
    `outboundTransferCustomRefund` to prevent stranded ETH refunds.
    """

    ARGUMENT = "arbitrum-outbound-no-refund"
    HELP = (
        "Bridge helper calls Arbitrum gateway `outboundTransfer` instead of "
        "`outboundTransferCustomRefund` - ETH refund stranded in contract"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Arbitrum outboundTransfer - Missing Custom Refund Address"
    WIKI_DESCRIPTION = (
        "When a bridge helper contract relays Arbitrum L1→L2 token transfers "
        "via the Arbitrum Gateway, it must use "
        "`outboundTransferCustomRefund(token, refundTo, to, ...)` and pass the "
        "end-user as `refundTo`. Using the plain `outboundTransfer(token, to, "
        "...)` variant forwards any gas-refund ETH back to `msg.sender` - the "
        "helper contract - where it remains permanently stuck unless a "
        "dedicated sweep function exists. Observed in Mitosis Vault (Zellic "
        "slice_af)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Bridge {
    IArbitrumGateway gateway;
    function bridge(address token, address to, uint256 amount) external payable {
        // BUG: plain outboundTransfer - refund goes to this contract.
        gateway.outboundTransfer{value: msg.value}(token, to, amount, maxGas, gp, "");
    }
}
```
1. User supplies 0.01 ETH to cover L2 retryable gas.
2. Arbitrum overestimates gas; real cost is 0.003 ETH.
3. Gateway attempts to refund 0.007 ETH to the "sender" = Bridge contract.
4. Bridge contract has no withdraw function → 0.007 ETH stranded per call.
5. Over many users, large ETH balance accumulates in the helper."""
    WIKI_RECOMMENDATION = (
        "Switch to `outboundTransferCustomRefund(token, userAddress, to, "
        "amount, maxGas, gasPriceBid, data)` and pass the original caller "
        "(`msg.sender`) as `refundTo` so gas refunds return to the user."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            for function in contract.functions_and_modifiers_declared:
                for node in function.nodes:
                    for ir in node.irs:
                        if not isinstance(ir, HighLevelCall):
                            continue
                        callee = ir.function
                        if not isinstance(callee, Function):
                            continue
                        name = callee.name or ""
                        if name != "outboundTransfer":
                            continue
                        info: DETECTOR_INFO = [
                            function,
                            " calls Arbitrum gateway `outboundTransfer` at ",
                            node,
                            " - use `outboundTransferCustomRefund` with an "
                            "explicit user refund address; the plain variant "
                            "sends ETH refunds back to the caller contract "
                            "where they are stranded.\n",
                        ]
                        results.append(self.generate_result(info))

        return results
