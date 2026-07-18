"""
listing-delisted-flag-not-checked-on-bid — generated from reference/patterns.dsl/listing-delisted-flag-not-checked-on-bid.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py listing-delisted-flag-not-checked-on-bid.yaml
Source: auditooor-R75-code4rena-2024-10-coded-estate-23
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ListingDelistedFlagNotCheckedOnBid(AbstractDetector):
    ARGUMENT = "listing-delisted-flag-not-checked-on-bid"
    HELP = "bid/purchase path checks auto-approve and denom but not the seller's `islisted` flag — seller cannot effectively unlist while bids are possible."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/listing-delisted-flag-not-checked-on-bid.yaml"
    WIKI_TITLE = "Bid handler ignores islisted flag, allowing purchase of delisted assets"
    WIKI_DESCRIPTION = "A marketplace exposes `setListForSell(islisted, price, autoApprove)` to the seller. The companion `setBidToBuy` does not check `sell.islisted`. When the seller later toggles `islisted = false` to pause sales, buyers can still call `setBidToBuy` and (with auto_approve = true) immediately complete the purchase. The seller's intent to delist is silently overridden."
    WIKI_EXPLOIT_SCENARIO = "Seller lists at 100, auto_approve = true. Market moves — asset is now worth 500. Seller sets islisted = false to prevent sale at stale price. Attacker calls setBidToBuy with 100, gets approval and purchases the token for 5x discount."
    WIKI_RECOMMENDATION = "At the top of the bid/purchase function, require `sell.islisted == true`. Add the same check on every state transition that depends on listing status (transfer_nft, auto-approve path)."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)setBid|placeBid|buyNow|setBidToBuy|purchase\\w*|bid\\b'}, {'function.body_contains_regex': '(?i)sell\\.auto_approve|auto_approve|autoApprove'}, {'function.body_not_contains_regex': '(?i)sell\\.islisted|require\\s*\\([^)]*islisted|if\\s*\\(\\s*!?\\s*listing\\.active'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — listing-delisted-flag-not-checked-on-bid: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
