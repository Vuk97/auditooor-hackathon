"""
claim_rewards_ownership_missing.py - Custom Slither detector.

Pattern: A `claimReward(uint256 tokenId)` / `claim(uint256 id)` /
`harvest(uint256 tokenId)` function transfers rewards to the caller (msg.sender)
based on a tokenId parameter but does NOT verify that msg.sender actually owns
the NFT (i.e., `require(nft.ownerOf(tokenId) == msg.sender)` is absent). An
attacker can claim rewards for NFT token IDs they do not own.

Source: external/glider-query-db/queries/claiming-nft-rewards-lack-ownership-validation.py

Detection strategy:
  1. Find any public/external function whose name starts with `claim`, `harvest`,
     or `getReward` declared in a contract.
  2. Confirm the function has at least one parameter whose name contains
     `tokenid`, `tokenId`, `id`, or `nftid` (case-insensitive).
  3. Check the function calls a transfer-like HighLevelCall:
     `transfer(address,uint256)`, `safeTransfer(address,uint256)`,
     `safeTransferFrom(address,address,uint256)` - evidence that rewards are
     being moved.
  4. Check that NO require/assert node in the function reads `msg.sender` -
     the proxy for an ownership validation.
  5. Flag if (3) is true and (4) is true (transfer exists, no ownership guard).

Approximation notes:
  - The ownership check `require(nft.ownerOf(tokenId) == msg.sender)` produces
    a require node containing a HighLevelCall + Binary == + msg.sender in the
    same node. We use the simpler "msg.sender in require/assert node.solidity_variables_read"
    check (canonical pattern from tx_origin.py), which correctly detects this.
  - Confirmed in IR probe: clean fixture has `msg.sender` in
    `node.solidity_variables_read` for the ownerOf require node.
    Vulnerable fixture has NO such node.
  - Functions that use `transferFrom(from, to, ...)` with from == msg.sender
    as an implicit ownership check are NOT caught - acceptable for triage.
  - FP risk: claim functions that use a non-require pattern (e.g., `if (!isOwner)
    revert OwnableError()`) will be flagged. Confidence MEDIUM.

Impact: HIGH - attacker steals rewards for any token ID without owning the NFT.
Confidence: MEDIUM.

@author auditooor
@pattern wave6 claim-rewards-ownership-missing
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
from slither.slithir.operations import HighLevelCall
from slither.utils.output import Output

# Skip keywords for test / mock / scaffold contracts.
_SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")

# Function name prefixes that indicate a reward-claiming entry-point.
_CLAIM_PREFIXES = ("claim", "harvest", "getreward", "collect")

# Parameter name substrings that indicate a tokenId argument.
_TOKEN_ID_HINTS = ("tokenid", "tokenId", "nftid", "nftId", "_id", "id")

# Transfer call signatures that indicate rewards are being moved.
_TRANSFER_SIGS = frozenset({
    "transfer(address,uint256)",
    "safeTransfer(address,uint256)",
    "safeTransferFrom(address,address,uint256)",
    # Also catch ERC-1155 safeTransferFrom
    "safeTransferFrom(address,address,uint256,uint256,bytes)",
    # Some protocols use sendValue or similar; catch plain call too via name
})

# Transfer function name fragments (fallback when sig doesn't resolve)
_TRANSFER_NAMES = frozenset({
    "transfer",
    "safeTransfer",
    "safeTransferFrom",
    "transferFrom",
})


def _is_claim_function(func) -> bool:
    """Return True if function name starts with a claim/harvest/getReward hint."""
    low = func.name.lower()
    return any(low.startswith(p) for p in _CLAIM_PREFIXES)


def _has_token_id_param(func) -> bool:
    """Return True if any parameter name looks like a tokenId / id argument."""
    for p in func.parameters:
        pname = p.name.lower()
        # Check exact matches for common names and substrings for compound names
        if pname in ("id", "_id", "tokenid", "_tokenid", "nftid", "_nftid"):
            return True
        if "tokenid" in pname or "nftid" in pname:
            return True
    return False


def _has_transfer_call(func) -> "str | None":
    """
    Return the transfer call signature if the function makes a transfer-like
    HighLevelCall, else None.

    Walks all nodes and their IRs. Returns the first matching sig found.
    """
    for node in func.nodes:
        for ir in node.irs:
            if not isinstance(ir, HighLevelCall):
                continue
            fn = getattr(ir, "function", None)
            if fn is None:
                continue
            sig = getattr(fn, "solidity_signature", None)
            if sig in _TRANSFER_SIGS:
                return sig
            fname = getattr(fn, "name", "")
            if fname in _TRANSFER_NAMES:
                return fname
    return None


def _has_ownership_guard(func) -> bool:
    """
    Return True if any require/assert node in the function reads msg.sender.

    This is the canonical proxy for `require(nft.ownerOf(tokenId) == msg.sender)`.
    From IR probe: the ownerOf+eq+require pattern produces a node with
    contains_require_or_assert() == True AND 'msg.sender' in solidity_variables_read.
    """
    for node in func.nodes:
        if not node.contains_require_or_assert():
            continue
        sv_read = getattr(node, "solidity_variables_read", [])
        if any(v.name == "msg.sender" for v in sv_read):
            return True
    return False


class ClaimRewardsOwnershipMissing(AbstractDetector):
    """
    Detect claim/harvest/getReward functions that accept a tokenId but do not
    verify msg.sender owns the corresponding NFT before transferring rewards.
    """

    ARGUMENT = "claim-rewards-ownership-missing"
    HELP = (
        "claimReward(tokenId) / harvest(tokenId) transfers rewards without "
        "require(nft.ownerOf(tokenId) == msg.sender) - attacker claims for any NFT"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Claim Rewards Without NFT Ownership Verification"
    WIKI_DESCRIPTION = (
        "A `claimReward(uint256 tokenId)` (or `harvest`, `getReward`) function "
        "transfers rewards to msg.sender based on a caller-supplied `tokenId` "
        "without verifying that msg.sender owns the NFT. Any caller can drain "
        "rewards accrued for any token ID without holding the corresponding NFT. "
        "This pattern was observed in multiple staking protocols and flagged in "
        "TenArmor alert (Apr 2025)."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract StakingRewards {
    mapping(uint256 => uint256) public rewards;
    IERC20 public rewardToken;

    function claimReward(uint256 tokenId) external {
        uint256 amt = rewards[tokenId];
        rewards[tokenId] = 0;
        rewardToken.transfer(msg.sender, amt);
        // ^ No ownerOf check - attacker passes any tokenId
    }
}
```
1. Protocol accrues `rewards[42] = 1000e18` for NFT token ID 42.
2. Attacker calls `claimReward(42)` without owning token ID 42.
3. `rewardToken.transfer(attacker, 1000e18)` executes unconditionally.
4. Attacker drains all accrued rewards for every token ID in the contract."""
    WIKI_RECOMMENDATION = (
        "Add an ownership check at the top of the claim function: "
        "`require(nft.ownerOf(tokenId) == msg.sender, 'not owner')`. "
        "Alternatively use ERC721's `safeTransferFrom` for reward disbursement "
        "which will revert if the caller is not the token owner."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            # Skip test / mock / vendored contracts
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue
            if is_vendored_or_test_contract(contract):
                continue

            for function in contract.functions_and_modifiers_declared:
                # Only public/external functions
                if function.visibility not in ("public", "external"):
                    continue

                # Must be a claim/harvest/getReward function
                if not _is_claim_function(function):
                    continue

                # Must accept a tokenId-like parameter
                if not _has_token_id_param(function):
                    continue

                # Must contain a transfer call (rewards are moved)
                transfer_sig = _has_transfer_call(function)
                if transfer_sig is None:
                    continue

                # Flag if no ownership guard (require + msg.sender) is present
                if not _has_ownership_guard(function):
                    info: DETECTOR_INFO = [
                        function,
                        " in contract ",
                        contract,
                        " accepts a tokenId parameter and calls a transfer ("
                        + str(transfer_sig)
                        + ") but contains no require(ownerOf(tokenId) == msg.sender) "
                        "guard. Callers can claim rewards for NFTs they do not own. "
                        "Add require(nft.ownerOf(tokenId) == msg.sender, 'not owner').\n",
                    ]
                    results.append(self.generate_result(info))

        return results
