"""
match-orders-buyer-constraint-checked-vs-seller-constraint — generated from reference/patterns.dsl/match-orders-buyer-constraint-checked-vs-seller-constraint.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py match-orders-buyer-constraint-checked-vs-seller-constraint.yaml
Source: lisa-mine-r99-case-08759-spearbit-infinity-exchange-2022
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MatchOrdersBuyerConstraintCheckedVsSellerConstraint(AbstractDetector):
    ARGUMENT = "match-orders-buyer-constraint-checked-vs-seller-constraint"
    HELP = "NFT marketplace `areNumItemsValid` validates the buyer's `numItems` constraint against the seller's `numItems` constraint instead of comparing the buyer's constraint against the actually-matched (constructed) item count. Sellers can lose more NFTs than the maximum they specified because the validato"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/match-orders-buyer-constraint-checked-vs-seller-constraint.yaml"
    WIKI_TITLE = "Match validator compares buyer's constraint to seller's constraint, not to constructed item count"
    WIKI_DESCRIPTION = "Pattern fires on `areNumItemsValid`-style validation helpers whose body contains a comparison of `buy.constraints[0]` (or `buy.numItems.min`) against `sell.constraints[0]` (or `sell.numItems.max`). The semantically correct check is: did the matching engine actually construct an item count that lies inside both `[buy.min, buy.max]` AND `[sell.min, sell.max]`? Comparing the two constraint windows di"
    WIKI_EXPLOIT_SCENARIO = "Infinity Exchange: a seller lists `min=1, max=2` of an NFT collection at floor price; a buyer offers `min=1, max=10`. Their constraint windows overlap. The matcher constructs 5 NFTs from the seller's collection (5 is inside `[1, 10]` for the buyer). `areNumItemsValid` confirms `[1,2]` overlaps `[1,10]` and returns true. The match settles, transferring 5 NFTs out of the seller — 3 more than they co"
    WIKI_RECOMMENDATION = "Pass the actually-matched item count `numConstructedItems` into the validator and require: `numConstructedItems >= buy.constraints[0] && numConstructedItems <= buy.constraints[1] && numConstructedItems >= sell.constraints[0] && numConstructedItems <= sell.constraints[1]`. This bounds the match to th"

    _PRECONDITIONS = [{'contract.has_function_matching': 'areNumItemsValid|matchOrders|fillOrder|matchOffers|validateOrderMatch'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '^(areNumItemsValid|_areNumItemsValid|validateNumItems)$'}, {'function.body_contains_regex': '\\bbuy(\\.|_)?(constraints|numItems|min|max)[^=]*[><=]\\s*sell(\\.|_)?(constraints|numItems|min|max)'}, {'function.body_not_contains_regex': 'numConstructedItems|constructedItems|matchedItems|actualItems'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — match-orders-buyer-constraint-checked-vs-seller-constraint: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
