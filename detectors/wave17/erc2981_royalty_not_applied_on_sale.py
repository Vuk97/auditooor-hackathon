"""
erc2981-royalty-not-applied-on-sale — generated from reference/patterns.dsl/erc2981-royalty-not-applied-on-sale.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc2981-royalty-not-applied-on-sale.yaml
Source: C0157
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc2981RoyaltyNotAppliedOnSale(AbstractDetector):
    ARGUMENT = "erc2981-royalty-not-applied-on-sale"
    HELP = "NFT marketplace settlement transfers sale proceeds without calling royaltyInfo() on the NFT contract. EIP-2981 royalties are skipped."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc2981-royalty-not-applied-on-sale.yaml"
    WIKI_TITLE = "ERC-2981 royalties not applied on NFT marketplace sale"
    WIKI_DESCRIPTION = "EIP-2981 (NFT Royalty Standard) defines a single on-chain hook, `royaltyInfo(tokenId, salePrice) -> (receiver, amount)`, that marketplaces are expected to invoke during sale settlement so that the original creator receives the configured royalty share. When a marketplace's settlement function calculates `sellerProceeds = salePrice - fee` and pays the seller directly without invoking `royaltyInfo`,"
    WIKI_EXPLOIT_SCENARIO = "1) Creator mints an NFT collection that implements EIP-2981 and sets a 5% royalty to their address. 2) Marketplace lists the NFT and a buyer accepts. 3) The settlement function (`buyNow` / `fillOrder` / `_settle` / `acceptOffer`) transfers `salePrice - protocolFee` to the seller and transfers the NFT from seller to buyer via `safeTransferFrom`, with no call to `royaltyInfo`. 4) The creator receive"
    WIKI_RECOMMENDATION = "In every settlement entry point, call `IERC2981(nft).royaltyInfo(tokenId, salePrice)` before paying the seller. Handle the `(address(0), 0)` response (non-royalty collection) as a no-op. When `amount > 0`, subtract it from the seller's proceeds and forward it to the returned `receiver` using the sam"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_body_matching': 'IERC2981|IERC721|safeTransferFrom\\s*\\(\\s*seller'}, {'contract.has_state_var_matching': 'nft|tokenAddress|collection'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'buy|_settle|executeSale|finalizeSale|acceptOffer|fillOrder|settleAuction|buyNow'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': 'safeTransferFrom|transferFrom.*tokenId'}, {'function.body_not_contains_regex': 'royaltyInfo|royalties|IERC2981|_royalty|calcRoyalty'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — erc2981-royalty-not-applied-on-sale: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
