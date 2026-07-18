"""
auction-bid-subtract-by-borrowamount-over-bidamount — generated from reference/patterns.dsl/auction-bid-subtract-by-borrowamount-over-bidamount.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py auction-bid-subtract-by-borrowamount-over-bidamount.yaml
Source: auditooor-R75-c4-lending-benddao-48
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AuctionBidSubtractByBorrowamountOverBidamount(AbstractDetector):
    ARGUMENT = "auction-bid-subtract-by-borrowamount-over-bidamount"
    HELP = "Settlement decrements `totalBidAmount` by `totalBorrowAmount`. Since borrow grows via interest after bid, borrowAmount > bidAmount and the subtraction under-flows or leaves stale accounting."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/auction-bid-subtract-by-borrowamount-over-bidamount.yaml"
    WIKI_TITLE = "Auction settle decrements bid balance by debt-with-interest, under-flows"
    WIKI_DESCRIPTION = "In NFT auction liquidation, bidders pre-fund the bid into a pooled bucket (`totalBidAmount`). At settlement, funds move into the asset's available liquidity to repay the borrower's debt. The code does `totalBidAmount -= totalBorrowAmount`. Problem: between bid time and settlement time, interest on `totalBorrowAmount` keeps accruing but `totalBidAmount` does not. With a 25h auction + high borrow ra"
    WIKI_EXPLOIT_SCENARIO = "Alice bids 5 ETH on Loan#1 (debt 4.9 ETH, interest 0.1 ETH) → totalBidAmount = 5, totalBorrowAmount = 5.0. Auction closes after 25h; totalBorrowAmount has now grown to 5.02 ETH. Settlement: `totalBidAmount -= totalBorrowAmount` → 5 - 5.02 underflows → revert. No further auctions on WETH can settle. Every unhealthy BAYC position now stuck, protocol accrues worse bad debt."
    WIKI_RECOMMENDATION = "Decrement `totalBidAmount` by the original bid amount (`loanData.bidAmount`), not by the current borrow-with-interest. Repay the interest delta from reserve/treasury or from the borrower's residual collateral. Add an invariant check `totalBidAmount >= sum(loanData.bidAmount)` post-settlement."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(totalBidAmount|totalBidAmout|assetData\\.\\w*Bid)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(?i)(executeLiquidate|executeIsolate|_?finalizeAuction|_?transferOutBid|_?settleAuction)'}, {'function.body_contains_regex': '(?i)(totalBid(Amount|Amout))\\s*-=\\s*(totalBorrow|borrowAmount|\\w*BorrowAmount)'}, {'function.body_not_contains_regex': '(?i)(totalBid(Amount|Amout))\\s*-=\\s*(totalBidAmount|_?bidAmount|loanData\\.bidAmount)|bidAmount\\s*-=\\s*borrowAmount'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — auction-bid-subtract-by-borrowamount-over-bidamount: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
