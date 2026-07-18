"""
nft_approval_without_owner_check.py - Custom Slither detector.

Pattern: A marketplace / listing function verifies `getApproved(tokenId) ==
creator` but does NOT also check `ownerOf(tokenId) == creator`. An attacker
holding an approval for a victim's NFT can create a listing against the
victim's token, stealing the sale proceeds.

Source: Zellic slice_aa line 146 (HIGH).

Detection:
    1. Walk contract functions.
    2. Track HighLevelCalls to `getApproved(uint256)` and `ownerOf(uint256)`.
    3. If the function calls `getApproved` but not `ownerOf` → flag.

Confidence: MEDIUM. Simple presence check; any function mixing both calls is
assumed to have the intended verification. If a protocol stores owner in a
local struct (no ownerOf call) we may emit a false positive - acceptable for
this class.
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


SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")

_GET_APPROVED_SIG = "getApproved(uint256)"
_OWNER_OF_SIG = "ownerOf(uint256)"


def _highlevel_sigs(function) -> set:
    """Collect set of solidity_signatures of HighLevelCall targets in function."""
    sigs = set()
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, HighLevelCall):
                continue
            callee = getattr(ir, "function", None)
            if not isinstance(callee, Function):
                continue
            s = getattr(callee, "solidity_signature", None)
            if s:
                sigs.add(s)
    return sigs


def _first_getapproved_node(function):
    for node in function.nodes:
        for ir in node.irs:
            if not isinstance(ir, HighLevelCall):
                continue
            callee = getattr(ir, "function", None)
            if not isinstance(callee, Function):
                continue
            if getattr(callee, "solidity_signature", None) == _GET_APPROVED_SIG:
                return node
    return None


class NftApprovalWithoutOwnerCheck(AbstractDetector):
    """Detect functions that verify NFT approval without also verifying ownership."""

    ARGUMENT = "nft-approval-without-owner-check"
    HELP = (
        "Function verifies ERC721 getApproved() but does not also check "
        "ownerOf() - attacker with approval can act on victim's NFT"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "NFT Approval Check Without Owner Verification"
    WIKI_DESCRIPTION = (
        "NFT marketplaces that authorize actions by comparing "
        "`getApproved(tokenId)` to a caller/seller must ALSO verify that "
        "`ownerOf(tokenId)` equals the expected owner. ERC-721 approvals "
        "travel independently of ownership: a user who once held an NFT and "
        "set an approval for address `X` may later transfer the NFT to "
        "someone else while leaving the approval intact. An attacker holding "
        "a stale approval can list (or otherwise act on) a token they no "
        "longer own. Source: Zellic slice_aa line 146 (HIGH)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
function createListing(address creator, uint256 tokenId, uint256 price) external {
    require(nft.getApproved(tokenId) == creator, "not approved");
    // BUG: no ownerOf check
    listings[tokenId] = Listing(creator, price);
}
```
1. Alice lists token 42 on an old marketplace, setting Bob as approved.
2. Alice transfers token 42 to Carol via safeTransferFrom.
   ERC-721 clears per-token approvals on transfer only when the marketplace
   uses the canonical transfer helpers; stale approvals can remain via
   setApprovalForAll.
3. Bob calls `createListing(bob, 42, cheapPrice)` on this contract.
4. Because only the approval is checked, the listing is created -
   Carol's NFT is now sold out from under her at Bob's price."""
    WIKI_RECOMMENDATION = (
        "Always pair `getApproved(tokenId)` with `require(nft.ownerOf(tokenId) "
        "== expectedOwner)`. Better: call `nft.isApprovedForAll(owner, caller) "
        "|| nft.getApproved(tokenId) == caller` AFTER establishing ownership."
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
                sigs = _highlevel_sigs(function)
                if _GET_APPROVED_SIG not in sigs:
                    continue
                if _OWNER_OF_SIG in sigs:
                    continue

                ga_node = _first_getapproved_node(function)
                info: DETECTOR_INFO = [
                    function,
                    " calls getApproved() at ",
                    ga_node,
                    " but never calls ownerOf() in the same function - "
                    "an attacker with a stale approval can act on an NFT "
                    "they no longer own. Add ownerOf(tokenId) == expected "
                    "check before trusting approvals.\n",
                ]
                results.append(self.generate_result(info))

        return results
