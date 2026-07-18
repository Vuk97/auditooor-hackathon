"""
nft-approval-not-owner-check — generated from reference/patterns.dsl/nft-approval-not-owner-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py nft-approval-not-owner-check.yaml
Source: solodit-novel/slice_aa-nft-approval
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class NftApprovalNotOwnerCheck(AbstractDetector):
    ARGUMENT = "nft-approval-not-owner-check"
    HELP = "Function relies on `getApproved(tokenId) == msg.sender` without also checking `ownerOf(tokenId) == expectedOwner`. Stale approvals from a previous owner survive the transfer and can be re-used on the new owner's token."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/nft-approval-not-owner-check.yaml"
    WIKI_TITLE = "NFT approval trusted without concurrent ownerOf check"
    WIKI_DESCRIPTION = "ERC-721 approvals ARE cleared on transfer — but only by `_transfer`. Staking/escrow contracts that cache ownership elsewhere can read `getApproved(tokenId)` under the old owner's assumption, letting the previously-approved operator act on the new owner's token."
    WIKI_EXPLOIT_SCENARIO = "Alice approves Bob on token #5 via `approve(Bob, 5)`. Alice sells the NFT to Carol through an escrow that does not call transferFrom but moves it in a custom `_migrate` path that doesn't clear approvals. Bob calls `stake(5)` on the staking contract — it reads `getApproved(5) == Bob` and succeeds, even though Carol is the rightful holder in the escrow's view."
    WIKI_RECOMMENDATION = "Always pair `getApproved(tokenId) == msg.sender` with `ownerOf(tokenId) == expectedOwner` (or rely on transferFrom's built-in approval+owner check)."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'getApproved|isApprovedForAll|ERC721'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'getApproved\\s*\\(\\s*\\w+\\s*\\)'}, {'function.body_not_contains_regex': 'ownerOf\\s*\\(\\s*\\w+\\s*\\)\\s*==|require\\s*\\(\\s*\\w+\\.ownerOf|ownerOf\\s*\\(\\s*tokenId\\s*\\)\\s*!='}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — nft-approval-not-owner-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
