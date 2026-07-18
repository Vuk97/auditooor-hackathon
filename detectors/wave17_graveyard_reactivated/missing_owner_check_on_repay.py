"""
missing_owner_check_on_repay.py - Custom Slither detector.

Pattern (BendDAO isolateRepay slice_aa): A repay/close/pay function takes an
`onBehalfOf` / `borrower` address parameter and writes to a stored loan
position, but never verifies that `onBehalfOf` matches the recorded borrower
or NFT owner. An attacker can repay into someone else's position to corrupt
its accounting (or, in NFT-backed lending, redirect collateral release).

Detection strategy:
    1. Iterate every non-vendored contract.
    2. Find external/public functions whose lowercased name contains
       "repay", "close" or "pay" (typical naming for loan settlement).
    3. The function must accept an `address onBehalfOf` / `address borrower`
       parameter AND read/write at least one struct-typed mapping (the loan
       store).
    4. The function must NOT contain ANY of:
         a) a HighLevelCall to `ownerOf(...)`,
         b) an InternalCall to a helper whose name matches `_checkOwner`
            / `_onlyOwnerOf` / `_validateOwner`,
         c) a Binary EQUAL whose operands include the param and a struct
            member (loan.borrower / loans[id].borrower-style read).
    5. If criterion 3 is met and 4 is absent → flag.

@author auditooor wave9
@pattern slice_aa BendDAO isolateRepay
"""

import sys as _sys
import re
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.slithir.operations import (
    Binary, BinaryType, HighLevelCall, InternalCall,
)
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_FUNC_NAME_RE = re.compile(r"(repay|close|pay)", re.IGNORECASE)
_CHECK_HELPER_RE = re.compile(
    r"(checkowner|onlyownerof|validateowner|assertowner|requireowner)",
    re.IGNORECASE,
)
_BORROWER_PARAM_NAMES = ("onbehalfof", "borrower", "user", "account", "debtor", "owner")


def _find_borrower_param(function):
    for p in function.parameters:
        nm = (p.name or "").lower()
        if nm not in _BORROWER_PARAM_NAMES:
            continue
        type_str = str(getattr(p, "type", "")).lower()
        if "address" in type_str:
            return p
    return None


def _calls_owner_check(function) -> bool:
    """Return True if the function calls a known owner-check helper or ownerOf."""
    for node in function.nodes:
        for ir in node.irs:
            if isinstance(ir, HighLevelCall):
                callee = getattr(ir, "function", None)
                nm = getattr(callee, "name", "") or ""
                if nm == "ownerOf":
                    return True
            elif isinstance(ir, InternalCall):
                callee = getattr(ir, "function", None)
                nm = getattr(callee, "name", "") or ""
                if _CHECK_HELPER_RE.search(nm):
                    return True
    return False


def _has_borrower_equality_check(function, borrower_param) -> bool:
    """
    Look for a require/if comparing borrower_param to anything (typically a
    struct field like loans[id].borrower).
    """
    for node in function.nodes:
        if not (node.contains_require_or_assert() or node.contains_if()):
            continue
        if borrower_param not in node.local_variables_read:
            continue
        for ir in node.irs:
            if isinstance(ir, Binary) and ir.type == BinaryType.EQUAL:
                return True
    return False


class MissingOwnerCheckOnRepay(AbstractDetector):
    """Flag repay/close/pay functions that take onBehalfOf without verifying ownership."""

    ARGUMENT = "missing-owner-check-on-repay"
    HELP = (
        "repay/close/pay function takes onBehalfOf address but never verifies "
        "the loan borrower or NFT ownerOf - anyone can corrupt third-party loan state"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Repay Path Missing Borrower Ownership Check"
    WIKI_DESCRIPTION = (
        "A loan repay/close function accepts an `onBehalfOf` address parameter "
        "and writes to the stored position without first verifying that "
        "`onBehalfOf` is the actual borrower (or, for NFT-backed lending, the "
        "current `ownerOf(tokenId)`). An attacker can repay into another user's "
        "loan slot to corrupt amortisation state, or - in BendDAO-style NFT "
        "lending - redirect collateral release. Reported in BendDAO isolateRepay."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
struct Loan { address borrower; uint256 amount; }
mapping(uint256 => Loan) public loans;

function repay(uint256 id, uint256 amt, address onBehalfOf) external {
    loans[id].amount -= amt;          // BUG: no borrower == onBehalfOf check
}
```
1. Victim has loan id 7 with `amount = 100`.
2. Attacker calls `repay(7, 1, attacker)` 100 times - loan amount drops to 0.
3. `loans[7].borrower` (still victim) can now claim collateral release without
   ever paying back the principal."""
    WIKI_RECOMMENDATION = (
        "Verify the caller is acting on a position they own: `require("
        "loans[id].borrower == onBehalfOf)` or `require(IERC721(asset).ownerOf"
        "(tokenId) == msg.sender)` before mutating loan state."
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
                if function.visibility not in ("public", "external"):
                    continue
                if not _FUNC_NAME_RE.search(function.name or ""):
                    continue

                borrower_param = _find_borrower_param(function)
                if borrower_param is None:
                    continue

                # Function must mutate at least one state var (proxy for
                # "writes loan position"). Otherwise it's a view/getter.
                if not function.state_variables_written:
                    continue

                if _calls_owner_check(function):
                    continue
                if _has_borrower_equality_check(function, borrower_param):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " writes loan state with caller-supplied ",
                    borrower_param,
                    " but never verifies it equals the stored borrower / NFT "
                    "ownerOf. Anyone can corrupt a third-party loan position.\n",
                ]
                results.append(self.generate_result(info))

        return results
