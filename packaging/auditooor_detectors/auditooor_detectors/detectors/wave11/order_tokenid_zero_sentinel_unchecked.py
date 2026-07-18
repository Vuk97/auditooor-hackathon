"""
order_tokenid_zero_sentinel_unchecked.py — Custom Slither detector.

Pattern (Cantina 3.1.5 — ctf-exchange-v2 Structs.sol / Trading.sol):
Many hybrid exchanges use asset id 0 as a sentinel that means "collateral
ERC-20" in an ERC-1155 transfer helper. A signed-order validator that
never rejects `order.tokenId == 0` silently accepts orders that will be
settled as collateral-for-collateral transfers, which lets a malicious
maker drain the taker's collateral without delivering any outcome token.
Polymarket v2 shipped this bug; Cantina filed it as 3.1.5 and it was
fixed in PR 60.

Detection strategy:
    1. For each non-vendored contract, look at every declared function
       whose name matches /validate.*Order|performOrderCheck|fillOrder|
       matchOrder|settleOrder/.
    2. Require that the function has at least one struct parameter whose
       struct declaration includes a field named `tokenId` / `assetId`.
    3. Walk the function IR for a Binary EQUAL / NOT_EQUAL comparing
       that field against Constant(0). If none is found, flag the
       function.

@author auditooor wave11
@pattern Cantina 3.1.5 / S2 (Quantstamp auditor suggestion)
"""

import re
import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.core.solidity_types.user_defined_type import UserDefinedType
from slither.core.declarations.structure import Structure
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.slithir.operations import Binary, BinaryType
from slither.slithir.variables import Constant
from slither.utils.output import Output


SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup")
_ORDER_FN_RE = re.compile(
    r"(validate.*order|performorder|checkorder|verifyorder)",
    re.IGNORECASE,
)
_TOKEN_ID_FIELD_RE = re.compile(r"(token|asset)id", re.IGNORECASE)


def _struct_params_with_tokenid(function):
    """Return list of (param, tokenid_field_name) for struct parameters
    whose struct declaration contains a tokenId-like field."""
    hits = []
    for p in function.parameters or []:
        t = p.type
        if not isinstance(t, UserDefinedType):
            continue
        struct = t.type
        if not isinstance(struct, Structure):
            continue
        for elem_name in struct.elems:
            if _TOKEN_ID_FIELD_RE.search(elem_name or ""):
                hits.append((p, elem_name))
                break
    return hits


def _function_checks_tokenid_against_zero(function, param, field_name) -> bool:
    """
    True if some Binary EQUAL/NOT_EQUAL in function IR compares
    a read of `param.field_name` against Constant(0).

    Heuristic: if any Binary operand appears in node.variables_read along
    with the struct param AND the comparison involves a 0 constant, we
    treat it as a tokenId zero-check. This is an over-approximation but
    matches the shape reliably.
    """
    field_lower = field_name.lower()
    for node in function.nodes:
        # Collect the source-text once; Slither IR doesn't always split
        # struct field reads into a distinct IR node we can pin.
        sm = getattr(node, "source_mapping", None)
        src = (sm.content or "") if sm is not None else ""
        src_lower = src.lower()
        for ir in node.irs:
            if not isinstance(ir, Binary):
                continue
            if ir.type not in (BinaryType.EQUAL, BinaryType.NOT_EQUAL):
                continue
            # Must involve a zero constant.
            has_zero = False
            for op in (ir.variable_left, ir.variable_right):
                if isinstance(op, Constant) and str(op.value) in ("0", "0x0"):
                    has_zero = True
                    break
            if not has_zero:
                continue
            # The node source must mention the field name AND the struct
            # parameter name (so we're actually checking that field).
            pname = (param.name or "").lower()
            if field_lower in src_lower and (
                pname in src_lower or pname == ""
            ):
                return True
    return False


class OrderTokenIdZeroSentinelUnchecked(AbstractDetector):
    """Order validator accepts `order.tokenId == 0`, which is the
    sentinel for the collateral ERC-20."""

    ARGUMENT = "order-tokenid-zero-sentinel-unchecked"
    HELP = (
        "Order validator never rejects tokenId == 0 — the sentinel for "
        "the collateral ERC-20, enabling collateral-for-collateral "
        "settlement."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Order tokenId == 0 sentinel not validated"
    WIKI_DESCRIPTION = (
        "Hybrid ERC-20 + ERC-1155 exchanges commonly use asset id 0 as a "
        "sentinel meaning 'the collateral ERC-20'. If the order validator "
        "never rejects `order.tokenId == 0`, a signed order can collapse "
        "the bidirectional collateral<->CTF exchange into a "
        "collateral-for-collateral transfer, letting a malicious maker "
        "drain the taker's collateral with no outcome token ever moving. "
        "Polymarket ctf-exchange-v2 shipped this bug; Cantina filed it as "
        "3.1.5 and Polymarket fixed it in PR 60."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
struct Order { address maker; uint256 tokenId; uint256 makerAmount; uint256 takerAmount; }

function _validateOrder(Order memory o) internal pure {
    if (o.maker == address(0)) revert InvalidMaker();
    // Missing: require(o.tokenId != 0)
}
```
Attacker signs an order with `tokenId = 0`. The exchange runs the ERC-1155
transfer helper against asset id 0, which is the collateral ERC-20, and
moves collateral to the attacker without any CTF position being involved."""
    WIKI_RECOMMENDATION = (
        "In the shared order validator, add `require(order.tokenId != 0)`. "
        "Better: derive the two valid outcome token ids from the provided "
        "conditionId and require `order.tokenId` to be one of them."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue
            for function in contract.functions_and_modifiers_declared:
                if function.is_constructor:
                    continue
                if not _ORDER_FN_RE.search(function.name or ""):
                    continue
                struct_hits = _struct_params_with_tokenid(function)
                if not struct_hits:
                    continue
                for param, field_name in struct_hits:
                    if _function_checks_tokenid_against_zero(
                        function, param, field_name
                    ):
                        continue
                    info: DETECTOR_INFO = [
                        function,
                        " validates order parameter ",
                        param.name or "?",
                        " but never rejects ",
                        param.name or "?",
                        ".",
                        field_name,
                        " == 0 — the ERC-20 collateral sentinel is "
                        "accepted as a valid asset id.\n",
                    ]
                    results.append(self.generate_result(info))
        return results
