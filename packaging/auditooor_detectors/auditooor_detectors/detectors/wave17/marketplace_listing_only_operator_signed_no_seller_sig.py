"""
marketplace-listing-only-operator-signed-no-seller-sig — generated from reference/patterns.dsl/marketplace-listing-only-operator-signed-no-seller-sig.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py marketplace-listing-only-operator-signed-no-seller-sig.yaml
Source: lisa-mine-r99-case-03068-cantina-freeverse-cryptopayments-2022
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MarketplaceListingOnlyOperatorSignedNoSellerSig(AbstractDetector):
    ARGUMENT = "marketplace-listing-only-operator-signed-no-seller-sig"
    HELP = "Marketplace bid / buy-now / listing entry point verifies an operator signature over the listing struct, but never verifies a corresponding seller signature. Anyone with the operator's permission to create listings can put up an asset the seller never agreed to sell — buyers' funds get locked at the "
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/marketplace-listing-only-operator-signed-no-seller-sig.yaml"
    WIKI_TITLE = "Listing entry point verifies only operator signature, not seller's"
    WIKI_DESCRIPTION = "Pattern fires on marketplace `bid` / `buyNow` / `listAsset` entry points whose body validates an operator-signed listing struct (`recover(...)` against an operator key, or a `verifyOperator`-style helper) without ALSO recovering / verifying a seller signature against the same struct. Even if the seller is required to actually transfer the asset at the end of the listing, the absence of a seller si"
    WIKI_EXPLOIT_SCENARIO = "An operator-key compromise (or simply a malicious operator) signs `BidInput` structs for high-value NFTs the operator does not own and cannot transfer. Buyers see the listings, place bids, funds are escrowed. The seller never signs the transfer at settlement, the listings expire, funds are refunded — but the operator has now executed a textbook fake-listing campaign that wastes buyer gas, briefly "
    WIKI_RECOMMENDATION = "Require BOTH signatures at listing creation: (a) an operator signature attesting the marketplace's record of the listing parameters, and (b) a seller signature attesting that the seller intends to sell at the listed terms. The seller signature must cover the same EIP-712 struct (or a tightly-bound s"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'BidInput|BuyNowInput|ListingInput|SellInput|orderListing'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(bid|relayedBid|buyNow|relayedBuyNow|placeBid|listAsset|createListing|processBid|processListing)$'}, {'function.body_contains_regex': 'verifySignature|recover\\s*\\(|ECDSA\\.recover|verifyOperator|operatorSig'}, {'function.body_not_contains_regex': 'sellerSig|sellerSignature|tokenOwnerSig|assetOwnerSig|verifySeller|sellerAddress\\s*==\\s*ecrecover|recoverSeller'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — marketplace-listing-only-operator-signed-no-seller-sig: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
