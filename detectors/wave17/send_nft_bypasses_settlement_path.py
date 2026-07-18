"""
send-nft-bypasses-settlement-path — generated from reference/patterns.dsl/send-nft-bypasses-settlement-path.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py send-nft-bypasses-settlement-path.yaml
Source: auditooor-R75-code4rena-2024-10-coded-estate-3
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SendNftBypassesSettlementPath(AbstractDetector):
    ARGUMENT = "send-nft-bypasses-settlement-path"
    HELP = "send_nft performs ownership transfer without running the payment-settlement branch that transfer_nft has — approved bidder can bypass payment."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/send-nft-bypasses-settlement-path.yaml"
    WIKI_TITLE = "send_nft transfer path bypasses trade settlement, letting approved bidder steal for free"
    WIKI_DESCRIPTION = "A CW721 contract exposes `transfer_nft` (which settles bid payment to seller) and `send_nft` (which invokes a Cw721ReceiveMsg hook on a contract). `send_nft` internally calls a bare `_transfer_nft` that changes ownership and clears approvals but skips the bid lookup / payment send. Any party with approval (legitimately granted via `setBidToBuy` with auto_approve) can call `send_nft` to transfer th"
    WIKI_EXPLOIT_SCENARIO = "Seller lists at 1000 USDC with auto_approve. Attacker places bid (gets approval). Attacker deploys a malicious contract implementing Cw721ReceiveMsg. Attacker calls `send_nft(attacker_contract, token_id)`. Ownership transfers free; bid is still recorded but seller never receives payment."
    WIKI_RECOMMENDATION = "Either (a) add settlement logic mirroring transfer_nft to send_nft, or (b) disallow approved (non-owner) callers from send_nft. If settlement logic depends on bids, run it before the `_transfer_nft` call."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)send_nft|safeTransferFrom|transferAndCall'}, {'function.body_contains_regex': '(?i)_?transfer_nft\\(|_transferOwnership|token\\.owner\\s*='}, {'function.body_not_contains_regex': '(?i)bids|sell\\.price|safeTransferETH|paySeller|settle\\w*|bankMsg::Send'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — send-nft-bypasses-settlement-path: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
