"""
nft-seaport-collateral-listing-missing-auction-sync — generated from reference/patterns.dsl/nft-seaport-collateral-listing-missing-auction-sync.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py nft-seaport-collateral-listing-missing-auction-sync.yaml
Source: auditooor-mcp/w6-8-seaport-collateral
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class NftSeaportCollateralListingMissingAuctionSync(AbstractDetector):
    ARGUMENT = "nft-seaport-collateral-listing-missing-auction-sync"
    HELP = "Seaport-style NFT collateral listing fulfills the order without synchronizing the auction/listing record first."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/nft-seaport-collateral-listing-missing-auction-sync.yaml"
    WIKI_TITLE = "Seaport collateral listing missing auction sync"
    WIKI_DESCRIPTION = "A collateral-listing function hands the NFT to a Seaport-style fulfillment path before it synchronizes the listing or auction record. The stale state means the borrower can move collateral through the marketplace flow while lien/auction bookkeeping still reads as inactive or unset."
    WIKI_EXPLOIT_SCENARIO = "Borrower lists a collateral NFT for sale. The function reads the listing price and calls Seaport `fulfillOrder(tokenId, price)` but never syncs the on-chain auction record first. The order settles and the token moves, yet the contract still believes the listing is inactive. Downstream lien or redemption checks read stale state and the borrower captures value that should have stayed locked."
    WIKI_RECOMMENDATION = "Synchronize the token's auction/listing record before any external order-fulfillment call, and require that the listing or lien state is active before transferring the NFT."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(Seaport|seaport|auctionData|listForSaleOnSeaport|collateralOwner)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '.*listForSaleOnSeaport.*'}, {'function.source_matches_regex': '(?s)listForSaleOnSeaport.*seaport\\.fulfillOrder'}, {'function.not_in_skip_list': True}, {'function.body_not_contains_regex': '(?i)(_syncAuctionData\\s*\\(|syncAuctionData\\s*\\(|populateAuctionData\\s*\\()'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — nft-seaport-collateral-listing-missing-auction-sync: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
