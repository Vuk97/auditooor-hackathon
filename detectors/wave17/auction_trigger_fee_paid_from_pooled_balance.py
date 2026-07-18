"""
auction-trigger-fee-paid-from-pooled-balance — generated from reference/patterns.dsl/auction-trigger-fee-paid-from-pooled-balance.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py auction-trigger-fee-paid-from-pooled-balance.yaml
Source: auditooor-R75-code4rena-2024-04-gondi-50
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AuctionTriggerFeePaidFromPooledBalance(AbstractDetector):
    ARGUMENT = "auction-trigger-fee-paid-from-pooled-balance"
    HELP = "settleX transfers a trigger/originator fee using `asset.safeTransfer` (contract balance) instead of `safeTransferFrom(msg.sender, ...)` — so the fee is skimmed from other auctions' pooled principal."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/auction-trigger-fee-paid-from-pooled-balance.yaml"
    WIKI_TITLE = "Auction settlement pays trigger fee from pooled balance, stealing from other auctions"
    WIKI_DESCRIPTION = "A multi-auction settlement contract receives principal deposits from different auctions. On settle, the trigger fee (bps of total owed) is paid to the auction originator with `safeTransfer` from the contract's own balance. The caller never sent the fee in. When two auctions are open simultaneously, the first to settle underpays by stealing the second auction's principal."
    WIKI_EXPLOIT_SCENARIO = "Auction A has 100 ETH principal, triggerFee = 2%. Auction B has 50 ETH principal. Main lender A settles, paying lenders 100 ETH and then `safeTransfer(originator, 2 ETH)`. The 2 ETH comes from Auction B's pooled principal. When Auction B tries to settle, its balance is short and `safeTransfer` reverts — Auction B's main lender cannot redeem."
    WIKI_RECOMMENDATION = "Pay fees with `asset.safeTransferFrom(msg.sender, originator, fee)` so the caller explicitly funds the fee. Equivalently, require caller to pre-deposit `totalOwed + fee` and subtract fee before paying lenders."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)settle\\w*|buyout\\w*|finalizeAuction|closeAuction'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': '(?i)safeTransfer\\s*\\(\\s*[\\w\\.]+originator'}, {'function.body_contains_regex': '(?i)triggerFee|originatorFee|settlementFee|auctionFee'}, {'function.body_not_contains_regex': '(?i)safeTransferFrom\\s*\\([^)]*originator'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — auction-trigger-fee-paid-from-pooled-balance: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
