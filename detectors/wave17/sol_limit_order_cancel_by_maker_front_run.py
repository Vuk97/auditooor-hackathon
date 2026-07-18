"""
sol-limit-order-cancel-by-maker-front-run — generated from reference/patterns.dsl/sol-limit-order-cancel-by-maker-front-run.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py sol-limit-order-cancel-by-maker-front-run.yaml
Source: solodit-cluster-C0175-LimitOrder
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SolLimitOrderCancelByMakerFrontRun(AbstractDetector):
    ARGUMENT = "sol-limit-order-cancel-by-maker-front-run"
    HELP = "Maker can cancel an order while an executor's fill is in flight — executor loses gas."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/sol-limit-order-cancel-by-maker-front-run.yaml"
    WIKI_TITLE = "Limit-order cancel has no fill-in-progress guard"
    WIKI_DESCRIPTION = "Executors watching a limit-order book burn gas on fill simulations. If the maker can cancel unconditionally even while a fill transaction is in the mempool, makers can grief executors (DOS the off-chain infrastructure) or even scam them by repeatedly cancelling right before profitable fills land."
    WIKI_EXPLOIT_SCENARIO = "LimitOrderRegistry C0175: maker sees fillOrder tx, pays higher gas to cancelOrder, tx lands first; executor's fillOrder reverts with orderNotFound, wasting their gas. Repeated attack drives executors off-book."
    WIKI_RECOMMENDATION = "Track `order.status = Filling` when a fill callback begins; revert `cancel` on `Filling` state. Alternatively, charge makers a cancellation deposit to compensate executors for failed attempts."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'LimitOrderRegistry|OrderBook|makerOrder|fillOrder|cancelOrder'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(cancelOrder|cancelBatch|revokeOrder|cancel)$'}, {'function.body_contains_regex': 'orders\\[|Order\\s+storage|orderId'}, {'function.body_not_contains_regex': 'filling|lockedForFill|fillInProgress|_orderStatus\\s*==\\s*[a-zA-Z]*Filling'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — sol-limit-order-cancel-by-maker-front-run: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
