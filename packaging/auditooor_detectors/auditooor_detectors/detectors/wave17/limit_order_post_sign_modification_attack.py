"""
limit-order-post-sign-modification-attack — generated from reference/patterns.dsl/limit-order-post-sign-modification-attack.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py limit-order-post-sign-modification-attack.yaml
Source: solodit-cluster-C0072
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LimitOrderPostSignModificationAttack(AbstractDetector):
    ARGUMENT = "limit-order-post-sign-modification-attack"
    HELP = "External mutator rewrites a stored signed limit order's price/tick/deadline without cancelling-and-resigning — creator can rotate terms after an executor observed the order off-chain, filling the executor at worse terms than they saw."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/limit-order-post-sign-modification-attack.yaml"
    WIKI_TITLE = "Limit-order post-sign modification attack: mutable signed orders without hash invalidation"
    WIKI_DESCRIPTION = "When a signed limit order is stored on-chain with mutable fields (limitPrice, tickRange, deadline, amount) and a public modifyOrder/updateOrder/adjustTick/changeLimit helper writes those fields without cancelling the prior order or bumping the order's nonce, the order creator can front-run a pending fillOrder. The executor signed up to fill at terms T0 that it observed off-chain; the creator mutat"
    WIKI_EXPLOIT_SCENARIO = "1) Maker signs an Order with limitPrice = P0, tickRange = R0 and stores it on-chain at orders[id]. 2) Executor observes orders[id] off-chain at block N, computes that filling is profitable, and broadcasts fillOrder(id). 3) Before block N+1 the maker calls modifyOrder(id, newPrice, newTick) to rotate the stored order to adversarial terms P1, R1, without cancelling the old order or invalidating any "
    WIKI_RECOMMENDATION = "On every post-sign mutation path: (a) cancel the old order via `_cancel(id)` or `delete orders[id]` before writing the new fields, (b) bump an order-scoped nonce (`nonces[maker]++`) so the previously observed digest is no longer fillable, and (c) require a fresh EIP-712 signature on the mutated Orde"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'orders|orderInfo|limitOrders|orderBook'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'modifyOrder|updateOrder|changeLimit|adjustTick|_updateOrder|editOrder'}, {'function.writes_storage_matching': 'orders|limitPrice|tick|amount|deadline'}, {'function.body_not_contains_regex': '_cancel|delete\\s+orders|invalidateHash|_revoke|nonces\\[.*\\]\\+\\+|nonce\\s*=\\s*nonce\\s*\\+\\s*1'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — limit-order-post-sign-modification-attack: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
