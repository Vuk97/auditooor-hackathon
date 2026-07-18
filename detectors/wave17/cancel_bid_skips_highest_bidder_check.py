"""
cancel-bid-skips-highest-bidder-check — generated from reference/patterns.dsl/cancel-bid-skips-highest-bidder-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py cancel-bid-skips-highest-bidder-check.yaml
Source: solodit/sherlock/radicalxchange-H1-31913
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CancelBidSkipsHighestBidderCheck(AbstractDetector):
    ARGUMENT = "cancel-bid-skips-highest-bidder-check"
    HELP = "Batch-cancel / cancel-all sibling of a single-cancel function drops the per-item invariant check (e.g., highest-bidder guard, active-leader guard). Attacker routes through the batch path to clear state that the singular path would have rejected."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/cancel-bid-skips-highest-bidder-check.yaml"
    WIKI_TITLE = "Batch-cancel skips per-item invariant check that single-cancel enforces"
    WIKI_DESCRIPTION = "The contract exposes two parallel clean-up paths for the same resource (a single-item `cancelBid(id)` and a batch `cancelAllBids()`). The single version enforces a critical invariant — typically 'you may not withdraw while you are the current leader / top bidder / last-liquidator' — but the batch version was written later as a loop and forgets to re-check the invariant on each iteration. Because b"
    WIKI_EXPLOIT_SCENARIO = "User Bob is the highest bidder at 10 ETH. `_cancelBid` reverts: Bob is the top bidder. Bob calls `cancelAllBidsAndWithdrawCollateral()`, which hits `_cancelAllBids`. The loop zeros `bid.collateralAmount` and `bid.bidAmount` for Bob in every round, including the current one, then `_withdrawCollateral` sends 10 ETH back to Bob. `highestBids[tokenId].bidder` is never updated, so Bob is still recorded"
    WIKI_RECOMMENDATION = "Factor the invariant into a single `_assertCanCancel(id, user)` helper and call it from every path that clears the resource — including batch loops. Add an invariant test that constructs both single and batch paths and asserts identical authorization behavior."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(highestBid|topBidder|auction|Auction|bid\\s*\\(|Bid\\s+|bidder|leader|winner|listing|Listing|order|Order|stake|Stake|position|Position|loan|Loan)'}, {'contract.has_func_matching': '_?cancel(Bid|Order|Stake|Position|Loan|Listing)[^s]*'}, {'contract.has_func_matching': '_?cancel(All|Many|Batch|Bulk)(Bids|Orders|Stakes|Positions|Loans|Listings)'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '^_?(cancel|clear|close|revoke|withdraw)(All|Many|Batch|Bulk)(Bids|Orders|Stakes|Positions|Loans|Listings|s)?$'}, {'function.body_contains_regex': 'for\\s*\\(|while\\s*\\('}, {'function.body_contains_regex': '(collateralAmount|bidAmount|stake|amount|shares|balance)\\s*=\\s*0'}, {'function.body_not_contains_regex': 'highestBid|topBidder|leader|winner|require\\s*\\([^)]*!=\\s*(highest|top|leader|winner)'}, {'function.body_not_contains_regex': 'ended\\s*==?\\s*true|isActive\\s*==?\\s*false|finalized'}, {'function.not_source_matches_regex': '(super\\._?cancel|_assertCanCancel|onlyBeforeFinalize|require\\s*\\([^)]*finalized\\s*==\\s*false|IERC(721|1155)Receiver)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — cancel-bid-skips-highest-bidder-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
