"""
matching-engine-amend-order-invariant-gap — generated from reference/patterns.dsl/matching-engine-amend-order-invariant-gap.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py matching-engine-amend-order-invariant-gap.yaml
Source: auditooor/roadmap-slice28-matching-engine-recall
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MatchingEngineAmendOrderInvariantGap(AbstractDetector):
    ARGUMENT = "matching-engine-amend-order-invariant-gap"
    HELP = "Order amend/modify path mutates lifecycle state without the invariant enforced by placement/fill paths."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/matching-engine-amend-order-invariant-gap.yaml"
    WIKI_TITLE = "Order amend path skips shared matching-engine invariant"
    WIKI_DESCRIPTION = "CLOB and perps engines often enforce order invariants on the placement/fill path: price bounds, already-filled quantity preservation, and per-transaction order-count caps. If amend/modify writes the same order state without routing through the shared invariant helper, users can bypass the book's safety rules after entering through a valid path."
    WIKI_EXPLOIT_SCENARIO = "A trader places a valid order, then amends it to a price/size/order-count state that the initial placement path would have rejected, corrupting matching semantics or bypassing DoS caps."
    WIKI_RECOMMENDATION = "Factor order lifecycle invariants into shared helpers and call them from place, amend, modify, resize, and batch variants. Add comparative tests showing placement and amend reject the same invalid state."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(struct\\s+Order|mapping\\s*\\([^)]*\\)\\s+(public\\s+)?orders|orderbook|CLOB|filled|maxLimitsPerTx|assertLimitPriceInBounds)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(amend|amendOrder|modifyOrder|updateOrder|resizeOrder|editOrder|reprice)$'}, {'function.body_contains_regex': '(orders\\s*\\[[^\\]]+\\]\\.(price|size|amount|qty|filled)\\s*=|Order\\s+storage\\s+\\w+\\s*=\\s*orders\\s*\\[)'}, {'function.body_contains_regex': '(\\.(price|size|amount|qty|filled)\\s*=|orders\\s*\\[[^\\]]+\\]\\s*=)'}, {'function.body_not_contains_regex': '(assertLimitPriceInBounds|_checkPriceBounds|_validatePrice|assertBounds|new(Size|Qty|Amount)\\s*>=\\s*\\w+\\.filled|below-filled|cannot-shrink-below-filled|maxLimitsPerTx|_checkPerTxLimit|limitsPerTx|_txCount|_bumpTx|bumpTx|perTxCount)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — matching-engine-amend-order-invariant-gap: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
