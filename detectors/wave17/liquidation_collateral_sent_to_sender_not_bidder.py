"""
liquidation-collateral-sent-to-sender-not-bidder — generated from reference/patterns.dsl/liquidation-collateral-sent-to-sender-not-bidder.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py liquidation-collateral-sent-to-sender-not-bidder.yaml
Source: auditooor-R75-c4-lending-benddao-20
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LiquidationCollateralSentToSenderNotBidder(AbstractDetector):
    ARGUMENT = "liquidation-collateral-sent-to-sender-not-bidder"
    HELP = "Finalize-liquidation path transfers seized NFT/collateral to `msg.sender` instead of the recorded auction winner / bid escrow. Anyone can steal the NFT after the auction closes."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/liquidation-collateral-sent-to-sender-not-bidder.yaml"
    WIKI_TITLE = "Seized auction collateral delivered to caller, not winning bidder"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. NFT-collateralized lending uses an English-auction style liquidation: bidder deposits assets when bidding (`isolateAuction`), those assets sit in escrow on the loan, and after the auction window any keeper can finalize (`executeIsolateLiquidate`). Finalize should transfer the NFT to the winning bidder stored on the loan. Bug: code writes `IERC721(nft).transferFrom(poolManager, msg.sender, tokenId)`."
    WIKI_EXPLOIT_SCENARIO = "Alice bids 5 ETH on BAYC#1234's auction, 5 ETH goes into escrow. After 25h (auction end + grace), Eve observes `tsLiquidator2.isolateLiquidate(BAYC, [1234], WETH, [0], false)`. The 5 ETH from Alice's bid pays off the loan; Eve receives BAYC#1234. Alice loses 5 ETH and gets nothing."
    WIKI_RECOMMENDATION = "In the finalize/settle path, transfer the NFT to `loanData.lastBidder` (the recorded highest bidder): `IERC721(nft).safeTransferFrom(address(this), loanData.lastBidder, tokenId);`. Similarly for any seized ERC-20 rewards. Do not promote from this fixture smoke alone."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(auction|executeLiquidate|isolateLiquidate|lastBidder|lastBid)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(?i)(executeLiquidate|executeIsolateLiquidate|_?finalizeAuction|_?settleAuction|_?closeAuction)'}, {'function.body_contains_regex': '(?i)(IERC721|ERC721|NFT).*(safeTransferFrom|transferFrom).*msg\\.sender'}, {'function.body_not_contains_regex': '(?i)(loanData\\.lastBidder|lastBidder|highestBidder|loan\\.bidder|auction\\.winner|tokenData\\.bidder|bidders\\[)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — liquidation-collateral-sent-to-sender-not-bidder: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
