"""
cancel-order-callback-reentrancy-desync — generated from reference/patterns.dsl/cancel-order-callback-reentrancy-desync.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py cancel-order-callback-reentrancy-desync.yaml
Source: auditooor-R77-polymarket-CTFExchange-cancelOrder
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CancelOrderCallbackReentrancyDesync(AbstractDetector):
    ARGUMENT = "cancel-order-callback-reentrancy-desync"
    HELP = "Order cancellation path lacks reentrancy protection while the exchange performs ERC-1155 safeTransferFrom with onReceived callbacks. Malicious 1271 maker can cancel sibling orders mid-batch, causing whole-batch revert while CLOB off-chain state advances."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/cancel-order-callback-reentrancy-desync.yaml"
    WIKI_TITLE = "cancelOrder lacks nonReentrant — 1271 maker can cancel sibling orders mid-batch via onERC1155Received"
    WIKI_DESCRIPTION = "Batch matchOrders loops fill orders while transferring conditional ERC-1155 tokens. `safeTransferFrom` calls `onERC1155Received` on the recipient. A POLY_1271 maker whose `onERC1155Received` handler invokes `cancelOrder(sibling)` mutates the exchange's storage mid-batch. The next iteration's signature check fails (cancelled nonce), reverting the whole batch. On-chain state rolls back; off-chain CL"
    WIKI_EXPLOIT_SCENARIO = "Attacker deploys 1271 maker with malicious onERC1155Received. Posts orders A, B. Operator matches both in one tx. During fill of A, ERC-1155 transfer triggers attacker's callback → cancelOrder(B). Batch's next iteration reverts on B's stale signature. CLOB in its off-chain state advanced A, attempts B, sees revert, leaves internal book inconsistent with chain state."
    WIKI_RECOMMENDATION = "Add nonReentrant modifier to cancelOrder + cancelOrders. Alternatively, add a sentinel flag set during matchOrders that blocks cancelOrder calls while a match is in progress."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)cancelOrder|matchOrders|onERC1155Received'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^cancel(Order|Orders)$'}, {'function.body_not_contains_regex': '(?i)nonReentrant|ReentrancyGuard|_locked|_status\\s*=\\s*1|noReentry'}, {'contract.has_function_matching': '(?i)matchOrders|_matchOrder|fillOrder'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — cancel-order-callback-reentrancy-desync: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
