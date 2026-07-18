"""
dutch-auction-parameter-manipulation — generated from reference/patterns.dsl/dutch-auction-parameter-manipulation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py dutch-auction-parameter-manipulation.yaml
Source: solodit-cluster-C0283
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DutchAuctionParameterManipulation(AbstractDetector):
    ARGUMENT = "dutch-auction-parameter-manipulation"
    HELP = "Admin-gated auction parameter setter has no sanity bounds and no active-auction guard — admin can change decrement/multiplier/start price mid-auction to extract value from bidders."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/dutch-auction-parameter-manipulation.yaml"
    WIKI_TITLE = "Dutch auction parameter manipulation: setter lacks bounds and in-flight guard"
    WIKI_DESCRIPTION = "Dutch-auction contracts expose privileged setters for decrement, multiplier, start price, or duration. When these setters (a) accept arbitrary values with no min/max cap and (b) apply immediately even while an auction is in progress, a compromised or rent-seeking admin can retune the curve mid-auction to either stall liquidation (infinite price) or extract surplus from bidders (collapse price)."
    WIKI_EXPLOIT_SCENARIO = "A liquidation auction is underway. The admin calls `setAuctionDecrement(0)` which takes effect immediately: the price never drops, so no bidder ever clears the auction and the protocol's collateral is stranded. Symmetrically, `setPriceMultiplier(type(uint256).max)` applied mid-auction to a future auction inflates the starting price so bids land at exploitative premiums. Either lever converts an ad"
    WIKI_RECOMMENDATION = "For every auction-parameter setter (1) enforce explicit `require(value >= MIN && value <= MAX)` bounds derived from protocol invariants, (2) revert when `currentAuction.active` / `auctionStarted` is true — new parameters must only apply to the next auction, and (3) emit a timelock-able event so bidd"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(DutchAuction|Auction|Liquidation|Auctioneer|currentAuction|auctionStarted|startAuction|priceMultiplier|decrement|StartPrice|EndPrice|AuctionDuration)'}, {'contract.has_state_var_matching': 'auction|startPrice|decrement|multiplier|currentAuction'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(set|update|configure)(Auction|Decrement|Multiplier|StartPrice|EndPrice|AuctionDuration|AuctionStep|AuctionParameters|PriceMultiplier|AuctionConfig)\\w*$'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyRole', 'onlyRoles', 'onlyGovernance', 'onlyGovernor', 'authorized'], 'negate': False}}, {'function.body_not_contains_regex': 'require\\s*\\([^;]*(<=|>=|<|>)|assert\\s*\\([^;]*(<=|>=|<|>)'}, {'function.body_not_contains_regex': 'isActive|auctionStarted|notActive|inactive|ongoing|!started'}, {'function.not_source_matches_regex': '(super\\.set|Governor\\.|Timelock\\.|onlyInitializing|view\\s+returns|pure\\s+returns|pendingConfig|nextAuctionConfig|scheduleConfig|TwoStepGovern)'}]

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
                info = [f, f" — dutch-auction-parameter-manipulation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
