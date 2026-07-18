"""
checkpoint_cleared_on_transfer_erc721.py - Custom Slither detector.

Pattern (Blackhole M-14, slice_ac): An ERC-721 voting-escrow / veNFT contract
overrides `_update` / `_beforeTokenTransfer` to clear voting checkpoints or
reward-index state for the SENDER on transfer, but never migrates the value
to the RECEIVER. The new owner holds the NFT but its associated voting power
or reward index is permanently reset to zero.

Detection strategy:
    1. For each non-vendored contract that LOOKS like an ERC-721 (`ownerOf`
       declared anywhere in the chain, plus a locally-declared `_update`
       or `_beforeTokenTransfer` hook).
    2. Check the contract has a state variable whose name matches a
       checkpoint pattern (`checkpoint`, `userPoint`, `rewardIndex`,
       `lastClaim`, `votingPower`).
    3. Walk the override body for `Assignment` IRs that write
       `Constant(0)` into a `ReferenceVariable` whose origin is one of
       those checkpoint state variables. Flag the function.

@author auditooor wave9
@pattern slice_ac Blackhole M-14
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
from slither.core.variables.state_variable import StateVariable
from slither.slithir.operations import Assignment, Member
from slither.slithir.variables import Constant, ReferenceVariable
from slither.utils.output import Output


_SKIP_KEYWORDS = ("test", "mock", "fixture", "helper", "script", "setup", "deploy")

_CHECKPOINT_RE = re.compile(
    r"checkpoint|userpoint|rewardindex|reward_index|lastclaim|last_claim|votingpower|voting_power",
    re.IGNORECASE,
)

_HOOK_NAMES = frozenset({
    "_update",
    "_beforeTokenTransfer",
    "_afterTokenTransfer",
})


def _looks_like_erc721(contract) -> bool:
    """Heuristic ERC-721 detection: must have ownerOf and a locally-declared
    transfer hook."""
    has_owner_of = any((f.name or "") == "ownerOf" for f in contract.functions)
    if not has_owner_of:
        return False
    has_local_hook = any(
        (f.name or "") in _HOOK_NAMES for f in contract.functions_and_modifiers_declared
    )
    return has_local_hook


def _checkpoint_state_vars(contract):
    out = []
    for sv in contract.state_variables:
        if _CHECKPOINT_RE.search(sv.name or ""):
            out.append(sv)
    return out


class CheckpointClearedOnTransferErc721(AbstractDetector):
    """Detect ERC-721 transfer hooks that zero out checkpoint state for the
    sender without migrating it to the receiver."""

    ARGUMENT = "checkpoint-cleared-on-transfer-erc721"
    HELP = (
        "veNFT/ERC-721 transfer hook clears voting checkpoint to zero on "
        "transfer without migrating it - receiver loses voting power"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "veNFT Checkpoint Cleared On Transfer"
    WIKI_DESCRIPTION = (
        "Voting-escrow NFTs and reward-bearing ERC-721s typically attach "
        "voting power, reward indices, or user points to either the tokenId "
        "or the current owner. When the transfer hook resets that state to "
        "zero on transfer but does not migrate the value to the new owner, "
        "the receiver holds the NFT but has zero voting power and earns no "
        "rewards. Worse, total voting supply is silently reduced, skewing "
        "every governance proposal that depends on it."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
struct Checkpoint { uint256 votes; uint256 blockNumber; }
mapping(uint256 => Checkpoint) public checkpoints;

function _update(address to, uint256 tokenId, address auth) internal override returns (address from) {
    from = super._update(to, tokenId, auth);
    if (from != address(0)) {
        checkpoints[tokenId].votes = 0;       // BUG
        checkpoints[tokenId].blockNumber = 0; // BUG
    }
}
```
1. Alice locks 1000 tokens, mints veNFT #7 with 1000 votes.
2. Alice sells veNFT #7 to Bob.
3. Bob owns the NFT but `checkpoints[7].votes == 0`. He has no governance
   power and earns no rewards, even though he paid for the lock value."""
    WIKI_RECOMMENDATION = (
        "Either keep checkpoints bound to the tokenId (so they travel with "
        "ownership) or actively migrate the snapshot value from sender to "
        "receiver in the same hook. Never zero out the entry without a "
        "matching write to the recipient."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if any(k in contract.name.lower() for k in _SKIP_KEYWORDS):
                continue

            if not _looks_like_erc721(contract):
                continue

            cp_svs = _checkpoint_state_vars(contract)
            if not cp_svs:
                continue
            cp_set = set(cp_svs)

            for function in contract.functions_and_modifiers_declared:
                if (function.name or "") not in _HOOK_NAMES:
                    continue

                # Pre-build a map from ReferenceVariable id → underlying
                # StateVariable so we can resolve which state-var an
                # Assignment touches.
                ref_to_origin: dict[int, StateVariable] = {}
                cleared_to_zero = False
                touched_sv = None

                for node in function.nodes:
                    for ir in node.irs:
                        if isinstance(ir, Member):
                            lv = ir.lvalue
                            if isinstance(lv, ReferenceVariable):
                                origin = lv.points_to_origin
                                if isinstance(origin, StateVariable):
                                    ref_to_origin[id(lv)] = origin
                        elif isinstance(ir, Assignment):
                            lv = ir.lvalue
                            rv = ir.rvalue
                            if not isinstance(lv, ReferenceVariable):
                                continue
                            if not isinstance(rv, Constant):
                                continue
                            if rv.value not in (0, "0"):
                                continue
                            origin = ref_to_origin.get(id(lv))
                            if origin is None:
                                # Fallback to .points_to_origin for direct
                                # mapping writes that did not go through a
                                # Member IR (rare in nested struct case).
                                origin = lv.points_to_origin if isinstance(lv.points_to_origin, StateVariable) else None
                            if origin in cp_set:
                                cleared_to_zero = True
                                touched_sv = origin
                                break
                    if cleared_to_zero:
                        break

                if not cleared_to_zero:
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " on ",
                    contract,
                    " clears checkpoint state variable ",
                    touched_sv,
                    " to zero on transfer without migrating it to the "
                    "receiver - the new NFT owner inherits zero voting "
                    "power and earns no rewards.\n",
                ]
                results.append(self.generate_result(info))

        return results
