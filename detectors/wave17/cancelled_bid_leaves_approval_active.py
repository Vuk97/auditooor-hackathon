"""
cancelled-bid-leaves-approval-active — generated from reference/patterns.dsl/cancelled-bid-leaves-approval-active.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py cancelled-bid-leaves-approval-active.yaml
Source: auditooor-R75-code4rena-2024-10-coded-estate-6
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CancelledBidLeavesApprovalActive(AbstractDetector):
    ARGUMENT = "cancelled-bid-leaves-approval-active"
    HELP = "Cancel-bid path removes the bid from storage but doesn't revoke the approval that was granted when the bid was placed — stale approval lets ex-bidder steal the token."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/cancelled-bid-leaves-approval-active.yaml"
    WIKI_TITLE = "Cancelled bid retains token approval, allowing free theft via transferFrom"
    WIKI_DESCRIPTION = "An NFT marketplace with `auto_approve: true` grants the bidder an approval upon calling `setBid`. A trade completes when the bidder or seller calls `transfer_nft`, which charges the bid amount and transfers the NFT. If the bidder cancels, their funds are refunded and the bid is removed from the `bids` vector — but the approval is not revoked. The bidder can now call `transfer_nft` directly, which "
    WIKI_EXPLOIT_SCENARIO = "Seller lists NFT at 1000 USDC with auto_approve. Attacker bids 1000 USDC (gets approval). Attacker calls `setBid` again with 0 funds, which cancels and refunds. Approval persists. Attacker calls `transfer_nft(attacker, token)`; the function finds no matching bid for attacker, amount = 0, but still transfers ownership."
    WIKI_RECOMMENDATION = "In the cancellation branch, also call `token.approvals.retain(|a| a.spender != info.sender)`. Equivalently, tie approval lifetime to bid existence: at the top of `transfer_nft`, require `bids[recipient].amount >= sell.price`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)setBid|cancelBid|withdrawBid|removeOffer'}, {'function.body_contains_regex': '(?i)bids\\.retain|offers\\.retain|delete\\s+bids\\[|bids\\.pop\\(|removeBid'}, {'function.body_not_contains_regex': '(?i)approvals\\.retain|revokeApproval|delete\\s+approvals|_approve\\([^,)]*,\\s*address\\(0\\)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — cancelled-bid-leaves-approval-active: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
