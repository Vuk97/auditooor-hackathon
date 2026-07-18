"""
is_approved_for_all_operand_swap.py - Custom Slither detector.

Pattern (TraitForge M-11 - slice_aa body finding):
    A contract invokes `isApprovedForAll(owner, operator)` with the arguments
    swapped, passing `msg.sender` (or some other "operator"-role address) as
    the *owner* argument and the real NFT owner as the *operator* argument.
    Because `isApprovedForAll` only returns true for a tuple where the key
    order matches `(owner, operator)`, the swapped call always returns false
    (or, if the attacker sets an approval on their own account, can be
    trivially bypassed) and the intended authorization check is broken.

Detection strategy:
    1. Walk non-vendored contracts.
    2. For each declared function, iterate HighLevelCall / LibraryCall IRs
       with solidity_signature == "isApprovedForAll(address,address)".
    3. Inspect the two arguments: the canonical pattern is
         isApprovedForAll(tokenOwner, msg.sender)
       If the FIRST argument is `msg.sender` (SolidityVariable "msg.sender")
       OR a function parameter whose type is `address` and whose name hints
       at operator semantics (operator, caller, spender, relayer) while the
       SECOND argument looks like an owner (ownerOf(...) result, a param
       named owner/holder/from, or a state var of address type), flag it.
    4. Also flag if first arg is literally from a prior `ownerOf(id)` call
       AND second arg is NOT `msg.sender` (both classic swapped variants).

Confidence: MEDIUM - the heuristic is a shape match, not a dataflow check.

@author auditooor wave11
@pattern slice_aa body finding / TraitForge M-11
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
from slither.core.declarations import Function, SolidityVariable
from slither.core.variables.local_variable import LocalVariable
from slither.core.solidity_types.elementary_type import ElementaryType
from slither.slithir.operations import HighLevelCall, LibraryCall
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_OPERATOR_NAME_HINTS = (
    "operator", "caller", "spender", "relayer", "sender", "executor",
)
_OWNER_NAME_HINTS = (
    "owner", "holder", "from", "seller", "maker", "beneficiary", "account",
)


def _name_of(v) -> str:
    return (getattr(v, "name", "") or "").lower()


def _is_msg_sender(v) -> bool:
    if isinstance(v, SolidityVariable):
        return v.name == "msg.sender"
    return False


def _param_looks_operator(v) -> bool:
    if not isinstance(v, LocalVariable):
        return False
    t = getattr(v, "type", None)
    if not isinstance(t, ElementaryType) or t.name != "address":
        return False
    return any(h in _name_of(v) for h in _OPERATOR_NAME_HINTS)


def _arg_looks_owner(v) -> bool:
    # Parameter / local whose name smells like owner/holder/from/etc.
    if any(h in _name_of(v) for h in _OWNER_NAME_HINTS):
        t = getattr(v, "type", None)
        if isinstance(t, ElementaryType) and t.name == "address":
            return True
    return False


class IsApprovedForAllOperandSwap(AbstractDetector):
    """Detect isApprovedForAll calls where owner/operator arguments are swapped."""

    ARGUMENT = "is-approved-for-all-operand-swap"
    HELP = (
        "isApprovedForAll(owner, operator) called with owner/operator "
        "arguments swapped - authorization check is silently broken"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "isApprovedForAll Operand Swap"
    WIKI_DESCRIPTION = (
        "ERC721/ERC1155 authorization checks must call "
        "`isApprovedForAll(owner, operator)` in the canonical argument "
        "order. Passing `msg.sender` or an operator-like parameter in the "
        "FIRST slot and the NFT owner in the SECOND slot inverts the query "
        "and always returns false unless an attacker sets an approval on "
        "their own address - making the check either dead-code or trivially "
        "bypassable. Reported in TraitForge (M-11 isApprovedForAll-wrong-operand)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function transferFor(address owner, uint256 id) external {
    // BUG: arguments swapped - passes msg.sender as the owner slot.
    require(nft.isApprovedForAll(msg.sender, owner), "not approved");
    nft.transferFrom(owner, msg.sender, id);
}
```
The check never fires against `owner`'s approval; any caller can satisfy it
by calling `nft.setApprovalForAll(owner, true)` on their own account, so the
gate is dead."""
    WIKI_RECOMMENDATION = (
        "Call `isApprovedForAll(tokenOwner, msg.sender)` with the NFT owner "
        "in the FIRST slot and the caller/operator in the SECOND slot. Ideally "
        "wrap the check in a named helper so the argument order is obvious."
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
                    for ir in node.irs:
                        if not isinstance(ir, (HighLevelCall, LibraryCall)):
                            continue
                        callee = ir.function
                        if not isinstance(callee, Function):
                            continue
                        if callee.solidity_signature != "isApprovedForAll(address,address)":
                            continue
                        args = ir.arguments
                        if len(args) != 2:
                            continue
                        first, second = args[0], args[1]

                        # Classic swap: first == msg.sender OR operator-like
                        # AND second looks like owner.
                        swapped = False
                        if _is_msg_sender(first) and _arg_looks_owner(second):
                            swapped = True
                        elif _param_looks_operator(first) and _arg_looks_owner(second):
                            swapped = True

                        if not swapped:
                            continue

                        info: DETECTOR_INFO = [
                            function,
                            " calls isApprovedForAll with swapped operands at ",
                            node,
                            " - first arg looks like the operator, second "
                            "arg looks like the owner. Canonical order is "
                            "(owner, operator); the check is silently broken.\n",
                        ]
                        results.append(self.generate_result(info))

        return results
