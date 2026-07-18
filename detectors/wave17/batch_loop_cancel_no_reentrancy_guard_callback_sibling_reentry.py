"""
batch-loop-cancel-no-reentrancy-guard-callback-sibling-reentry — generated from reference/patterns.dsl/batch-loop-cancel-no-reentrancy-guard-callback-sibling-reentry.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py batch-loop-cancel-no-reentrancy-guard-callback-sibling-reentry.yaml
Source: auditooor-R37d-polymarket-CTFExchange-cancelOrders-sibling-reentry
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BatchLoopCancelNoReentrancyGuardCallbackSiblingReentry(AbstractDetector):
    ARGUMENT = "batch-loop-cancel-no-reentrancy-guard-callback-sibling-reentry"
    HELP = "Batch cancel/match loop iterates user-signed orders and performs ERC-1155/721 transfer or 1271 sig-check inside the loop body, with no global reentrancy guard. A malicious maker that implements onERC1155Received (or POLY_1271 isValidSignature) can re-enter the SAME function mid-iteration and cancel "
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/batch-loop-cancel-no-reentrancy-guard-callback-sibling-reentry.yaml"
    WIKI_TITLE = "Batch cancelOrders/match loop lacks nonReentrant — sibling-reentry via ERC-1155 receiver / POLY_1271 callback causes mid-batch ghost-fill"
    WIKI_DESCRIPTION = "Distinct from single-function callback-reentrancy detectors: this is the SIBLING-LOOP shape. Function f1 iterates over an array of user-supplied orderIDs; each iteration triggers an ERC-1155 safeTransferFrom (or 1271 signature verification) that callbacks into the maker. The maker re-enters f1 (or a companion cancel/match function on the same contract) and mutates per-input state for a DIFFERENT e"
    WIKI_EXPLOIT_SCENARIO = "v1 CTFExchange.cancelOrders([A,B]). Iteration 1 returns CTF tokens to maker via safeTransferFrom. Maker is a contract whose onERC1155Received calls cancelOrder(B). B's nonce/state flips. Iteration 2 sees B already cancelled (or signature stale) and reverts the whole batch. CLOB off-chain state had already marked A and B as cancelled — on-chain reverts to neither cancelled, producing book desync th"
    WIKI_RECOMMENDATION = "Add nonReentrant modifier to cancelOrder, cancelOrders, and matchOrders — gating both directions. Alternatively, set a transient batch sentinel before the loop and require it unset on entry."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Exchange|Clob|Book|Matcher|OrderBook|Auction)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(cancelOrders?|batchCancel|multiCancel|executeBatch|batchMatch)$'}, {'function.body_contains_regex': 'for\\s*\\([^{]*\\)\\s*\\{(?:[^{}]|\\{[^{}]*\\})*?(?:IERC1155|ERC1155|\\.safeTransferFrom|onERC1155Received|onERC721Received|POLY_1271|isValidSignature)'}, {'function.body_not_contains_regex': '(?i)(nonReentrant|_lockReentrancy|REENTRANCY_GUARD_LOCKED|ReentrancyGuard)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — batch-loop-cancel-no-reentrancy-guard-callback-sibling-reentry: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
