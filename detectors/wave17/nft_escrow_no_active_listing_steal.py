"""
nft-escrow-no-active-listing-steal — generated from reference/patterns.dsl/nft-escrow-no-active-listing-steal.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py nft-escrow-no-active-listing-steal.yaml
Source: solodit/C0295
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class NftEscrowNoActiveListingSteal(AbstractDetector):
    ARGUMENT = "nft-escrow-no-active-listing-steal"
    HELP = "Escrowed NFT withdraw/claim/cancel path transfers the token without verifying that a listing / active sale / auction actually exists — anyone can drain an idle NFT."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/nft-escrow-no-active-listing-steal.yaml"
    WIKI_TITLE = "NFT escrow theft: claim/withdraw path missing active-listing guard"
    WIKI_DESCRIPTION = "An NFT marketplace or escrow contract holds tokens against optional buyPrice / listing / auction state. When that state is empty (or already cancelled), a callable path still transfers the NFT out, letting any caller seize an unlisted NFT held in escrow."
    WIKI_EXPLOIT_SCENARIO = "Alice deposits her NFT into the marketplace but hasn't set a buyPrice. Bob calls cancelListing() / settle() / claim() — the function transfers the NFT to msg.sender without checking listing.active, so Bob walks away with Alice's NFT."
    WIKI_RECOMMENDATION = "Gate every NFT-moving path on explicit listing/auction status: `require(listing.active, ...)` / `require(buyPrice > 0)` / `require(msg.sender == listing.seller || auction.ended)`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(?i)(buyPrice|listing|auction|sale|escrow)'}, {'contract.has_function_body_matching': '(?i)(safeTransferFrom|transferFrom)\\s*\\('}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(claim|withdraw|cancel|buy|accept|settle|steal)[A-Za-z0-9_]*'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': '(?i)(safeTransferFrom|transferFrom)\\s*\\('}, {'function.body_not_contains_regex': '(?i)(require|revert|if)\\s*\\(.{0,200}(active|buyPrice|listing|auction|expires|end|exists|started|status)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — nft-escrow-no-active-listing-steal: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
