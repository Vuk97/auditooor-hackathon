"""
missing_excess_eth_refund.py - Custom Slither detector.

Pattern (TraitForge M - excess-ETH-stuck-forgingFee - slice_aa body finding):
    A payable function reads `msg.value` and compares it against a
    required price / fee state variable using `>=`. When a caller sends
    more than the required amount, the function accepts the transaction
    but never refunds the surplus - the extra ETH is permanently stuck
    in the contract. Users who accidentally overpay (front-end bug, bad
    gas estimation, rounding) lose funds silently.

Detection strategy:
    1. Walk non-vendored contracts.
    2. For each payable function, check:
         a. msg.value is read somewhere in the body.
         b. There exists a Binary compare where one side is msg.value and
            the comparison is `>=` or `>` (i.e. overpayment is accepted).
    3. Check whether the function refunds the surplus. We look for any
       low-level `address.call{value: ...}("")` / `transfer(...)` /
       `send(...)` IR whose recipient is `msg.sender` or `tx.origin`, OR
       a SolidityCall to one of those send primitives. We also accept
       `require(msg.value == price)` (strict equality) as a non-issue.
    4. If the compare is non-strict AND no refund call exists → flag.

Confidence: MEDIUM. We only fire on payable functions that accept
overpayment and never call back to msg.sender.

@author auditooor wave11
@pattern slice_aa body finding / TraitForge excess-ETH-stuck-forgingFee
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
from slither.core.declarations import SolidityVariable, SolidityVariableComposed
from slither.slithir.operations import (
    Binary,
    BinaryType,
    LowLevelCall,
    HighLevelCall,
    Transfer,
    Send,
    TypeConversion,
)
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_ACCEPT_OVER_TYPES = frozenset({
    BinaryType.GREATER_EQUAL,
    BinaryType.GREATER,
    BinaryType.LESS_EQUAL,
    BinaryType.LESS,
})


def _is_msg_value(v) -> bool:
    if isinstance(v, (SolidityVariable, SolidityVariableComposed)):
        return v.name == "msg.value"
    return False


def _function_reads_msg_value(function) -> bool:
    for node in function.nodes:
        for sv in node.solidity_variables_read:
            if sv.name == "msg.value":
                return True
    return False


def _function_accepts_overpayment(function) -> bool:
    """
    Return True if there exists a Binary comparison where one side is
    msg.value and the operator is `>=` / `>` / `<=` / `<` - i.e. the
    function ACCEPTS payments above the required amount.

    A strict `==` (BinaryType.EQUAL) comparison is NOT flagged; the caller
    must send exactly the price so no surplus is possible.
    """
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, Binary):
                continue
            if ir.type not in _ACCEPT_OVER_TYPES:
                continue
            operands = (ir.variable_left, ir.variable_right)
            if any(_is_msg_value(o) for o in operands):
                return True
    return False


def _function_strict_equals_msg_value(function) -> bool:
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, Binary):
                continue
            if ir.type != BinaryType.EQUAL:
                continue
            operands = (ir.variable_left, ir.variable_right)
            if any(_is_msg_value(o) for o in operands):
                return True
    return False


def _function_refunds_sender(function) -> bool:
    """
    Heuristic: any Transfer / Send / LowLevelCall whose destination is
    msg.sender (or msg.origin) counts as a refund path. Because most
    recipients are produced by `payable(msg.sender)` (a TypeConversion),
    we first build a map from TemporaryVariable → origin SolidityVariable
    so we can trace dest back to `msg.sender`.
    """
    # Build TypeConversion chain so we can follow TMP → source.
    conv_origin = {}
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, TypeConversion):
                src = ir.variable
                lv = ir.lvalue
                # Chain-follow through existing conversion table.
                while id(src) in conv_origin:
                    src = conv_origin[id(src)]
                conv_origin[id(lv)] = src

    def _resolve(v):
        cur = v
        seen = set()
        while id(cur) in conv_origin and id(cur) not in seen:
            seen.add(id(cur))
            cur = conv_origin[id(cur)]
        return cur

    for node in function.nodes:
        for ir in node.irs:
            dest = None
            if isinstance(ir, (Transfer, Send)):
                dest = ir.destination
            elif isinstance(ir, LowLevelCall):
                dest = ir.destination
            elif isinstance(ir, HighLevelCall):
                dest = ir.destination
            if dest is None:
                continue
            resolved = _resolve(dest)
            nm = (getattr(resolved, "name", "") or "").lower()
            if nm in ("msg.sender", "tx.origin"):
                return True
            if "sender" in nm or "refund" in nm or "payer" in nm:
                return True
    return False


class MissingExcessEthRefund(AbstractDetector):
    """Detect payable functions that keep surplus msg.value with no refund."""

    ARGUMENT = "missing-excess-eth-refund"
    HELP = (
        "Payable function accepts msg.value > price but never refunds "
        "the surplus - overpayments are silently stuck in the contract"
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Missing Excess ETH Refund"
    WIKI_DESCRIPTION = (
        "A payable function requires `msg.value >= price` (accepting any "
        "overpayment) but never returns the surplus to the caller. Front-end "
        "rounding bugs, bad gas estimation, or naive callers cause funds to "
        "be silently locked in the contract. Reported in TraitForge "
        "(excess-ETH-stuck-forgingFee)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
uint256 public price = 0.01 ether;

function mint() external payable {
    require(msg.value >= price, "underpaid"); // BUG: >= accepts surplus
    _mint(msg.sender, _nextId());
    // No refund of (msg.value - price).
}
```
A front-end estimates `price` loosely and sends `0.012 ether`. The extra
`0.002 ether` is locked in the contract, recoverable only by whoever owns
a sweep function (or nobody)."""
    WIKI_RECOMMENDATION = (
        "Either require strict equality (`require(msg.value == price)`) or "
        "refund the surplus at the end of the function "
        "(`payable(msg.sender).call{value: msg.value - price}(\"\")`). "
        "Prefer the strict-equality form on purely-onchain paths."
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
                if not function.payable:
                    continue
                if function.view or function.pure:
                    continue

                if not _function_reads_msg_value(function):
                    continue
                # Strict equality means no surplus possible - safe.
                if _function_strict_equals_msg_value(function):
                    continue
                if not _function_accepts_overpayment(function):
                    continue
                if _function_refunds_sender(function):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " is payable, compares msg.value with `>=`/`>`, and "
                    "never refunds the surplus to msg.sender - overpayments "
                    "are silently stuck in the contract.\n",
                ]
                results.append(self.generate_result(info))

        return results
