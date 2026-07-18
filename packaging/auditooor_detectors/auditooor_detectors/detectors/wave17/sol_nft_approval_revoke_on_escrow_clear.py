"""
sol-nft-approval-revoke-on-escrow-clear — generated from reference/patterns.dsl/sol-nft-approval-revoke-on-escrow-clear.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py sol-nft-approval-revoke-on-escrow-clear.yaml
Source: solodit-cluster-C0308-NFT
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SolNftApprovalRevokeOnEscrowClear(AbstractDetector):
    ARGUMENT = "sol-nft-approval-revoke-on-escrow-clear"
    HELP = "Escrow returns NFT without clearing stale pre-escrow approvals."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/sol-nft-approval-revoke-on-escrow-clear.yaml"
    WIKI_TITLE = "Escrow return does not revoke NFT approvals"
    WIKI_DESCRIPTION = "ERC-721's `approve` is stored on the current owner's side and cleared only on outgoing `transferFrom`. When a contract returns an NFT to the original holder, approvals set by the holder BEFORE escrow remain valid and active against the returned NFT."
    WIKI_EXPLOIT_SCENARIO = "C0308 H-02: marketplace escrow returns NFT; attacker who previously had `getApproved(tokenId) == attacker` from months prior calls `transferFrom(originalOwner, attacker, tokenId)` immediately, stealing the returned NFT."
    WIKI_RECOMMENDATION = "On return path, explicitly call `token.approve(address(0), tokenId)` under the original owner's authority — OR require the returning contract to hold the token, execute a clearing approve, then transfer."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'IERC721|ERC721|NFT'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(returnNft|releaseEscrow|unlock|withdraw|returnCollateral)'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': 'safeTransferFrom|transferFrom|_transfer\\('}, {'function.body_not_contains_regex': 'approve\\s*\\(\\s*address\\s*\\(\\s*0\\s*\\)|_approve\\s*\\(\\s*address\\s*\\(\\s*0\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

    def _detect(self):
        results = []
        for c in self.contracts:
            if is_vendored_or_test_contract(c):
                continue
            if not eval_preconditions(c, self._PRECONDITIONS):
                continue
            for f in c.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(f):
                    continue
                if not eval_function_match(f, self._MATCH):
                    continue
                info = [f, f" — sol-nft-approval-revoke-on-escrow-clear: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
