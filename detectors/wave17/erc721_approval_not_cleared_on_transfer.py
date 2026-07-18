"""
erc721-approval-not-cleared-on-transfer — generated from reference/patterns.dsl/erc721-approval-not-cleared-on-transfer.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc721-approval-not-cleared-on-transfer.yaml
Source: auditooor-R73-code4rena-2024-08-superposition-160
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc721ApprovalNotClearedOnTransfer(AbstractDetector):
    ARGUMENT = "erc721-approval-not-cleared-on-transfer"
    HELP = "ERC721 custom transfer updates owner but leaves getApproved[tokenId] stale — prior operator can reclaim NFT."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc721-approval-not-cleared-on-transfer.yaml"
    WIKI_TITLE = "ERC721 custom transfer leaves per-tokenId approval stale after ownership change"
    WIKI_DESCRIPTION = "Hand-rolled ERC721 implementations that store `getApproved[tokenId]` in a mapping must clear it every transfer, as specified in EIP-721. Forgetting this clear lets the pre-transfer operator call `transferFrom` again (the operator was still authorized for that tokenId) and steal the NFT from the new owner."
    WIKI_EXPLOIT_SCENARIO = "Alice approves Marketplace for tokenId 42. Marketplace transfers 42 to Bob after sale. Because `getApproved[42]` still equals Marketplace, Marketplace can call `transferFrom(Bob, Attacker, 42)` — or any prior approvee can — and Bob loses the NFT. Any integrator (staking, escrow) that trusted post-sale ownership is compromised."
    WIKI_RECOMMENDATION = "Inside the transfer hook (even before updating owner): `delete getApproved[tokenId];` (or `getApproved[tokenId] = address(0);`). Inherit OpenZeppelin's ERC721 base instead of rolling your own whenever possible. Add a test: after transferFrom, expect `getApproved(tokenId) == address(0)`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '(?i)_transfer|transferFrom|safeTransferFrom'}, {'function.body_contains_regex': '(?i)ownerOf\\[\\s*_tokenId\\s*\\]\\s*=|_owners\\[\\s*tokenId\\s*\\]\\s*='}, {'function.body_not_contains_regex': '(?i)(getApproved|_tokenApprovals)\\[\\s*_?tokenId\\s*\\]\\s*=\\s*address\\(0\\)'}, {'contract.has_state_var_matching': '(?i)getApproved|_tokenApprovals'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — erc721-approval-not-cleared-on-transfer: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
