"""
auction-conclusion-strict-less-than-allows-cancel-at-boundary — generated from reference/patterns.dsl/auction-conclusion-strict-less-than-allows-cancel-at-boundary.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py auction-conclusion-strict-less-than-allows-cancel-at-boundary.yaml
Source: lisa-mine-r99-case-00337-sherlock-axis-finance-2024-03
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AuctionConclusionStrictLessThanAllowsCancelAtBoundary(AbstractDetector):
    ARGUMENT = "auction-conclusion-strict-less-than-allows-cancel-at-boundary"
    HELP = "Auction/lot 'conclusion' guard uses strict `<` against block.timestamp instead of `<=`, so when block.timestamp == conclusion the lot is treated as still live AND already concluded simultaneously. Auction creators can cancel at the conclusion timestamp, locking bidders' quote tokens."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/auction-conclusion-strict-less-than-allows-cancel-at-boundary.yaml"
    WIKI_TITLE = "Auction conclusion guard uses strict less-than against block.timestamp"
    WIKI_DESCRIPTION = "Pattern fires on internal `_revertIfLotConcluded`-style guards that compare a stored conclusion timestamp to `block.timestamp` with strict `<`. When the two are equal (an attacker can wait one block), the conclusion-check fails (lot 'not yet concluded') AND the active-check fails (conclusion is no longer strictly greater than now). The auction creator can then cancel at the boundary even though bi"
    WIKI_EXPLOIT_SCENARIO = "An auction is created with conclusion=86401. A bidder places a bid mid-auction. At block.timestamp == 86401 the auction creator front-runs settlement and calls cancelAuction — _revertIfLotConcluded passes (86401 < 86401 is false), _revertIfLotActive passes (86401 > 86401 is false), and the auction transitions to Claimed. The bidder's quote tokens are now locked: refundBid reverts because capacity "
    WIKI_RECOMMENDATION = "Use `<=` not `<` when comparing the stored conclusion/end-time against block.timestamp in the 'concluded' guard, so the boundary timestamp is treated as concluded and consistent with the 'active' guard's strict `>` upper bound. Equivalently, ensure the active and concluded windows partition `block.t"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '_revertIfLot|_revertIfAuction|isLive|isActive|isConcluded|_revertIf.*Concluded|_revertIf.*Active'}]
    _MATCH = [{'function.kind': 'internal'}, {'function.name_matches': '_revertIf.*Concluded|_revertIfLotConcluded|_revertIfAuctionConcluded'}, {'function.body_contains_regex': '\\.(conclusion|endTime|deadline|expiry|expirationTime)\\s*<\\s*(uint\\d+\\s*\\(\\s*)?block\\.timestamp'}, {'function.body_not_contains_regex': '\\.(conclusion|endTime|deadline|expiry|expirationTime)\\s*<=\\s*(uint\\d+\\s*\\(\\s*)?block\\.timestamp'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — auction-conclusion-strict-less-than-allows-cancel-at-boundary: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
