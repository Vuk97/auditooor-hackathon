"""
amend-skips-max-limits-per-tx — generated from reference/patterns.dsl/amend-skips-max-limits-per-tx.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py amend-skips-max-limits-per-tx.yaml
Source: solodit-novel/slice_ac-CLOB
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AmendSkipsMaxLimitsPerTx(AbstractDetector):
    ARGUMENT = "amend-skips-max-limits-per-tx"
    HELP = "`amend()` bypasses the per-tx order-count limit enforced by `placeOrder()`. Attacker rapidly amends orders to spam the book past the safety cap."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/amend-skips-max-limits-per-tx.yaml"
    WIKI_TITLE = "Amend bypasses per-tx order limit"
    WIKI_DESCRIPTION = "CLOBs cap orders-per-tx to bound gas / prevent state-bloat DoS. When `amend()` mutates state equivalently to a fresh place but skips the limit counter, attackers can drive state past the cap."
    WIKI_EXPLOIT_SCENARIO = "Contract caps place at 10 orders/tx. Attacker places 10 legitimate orders then calls `amend` 10,000 times on each in the same tx, breaking DEX state invariants and inducing an iteration DoS."
    WIKI_RECOMMENDATION = "Increment the per-tx counter in `amend()` as well, or factor the limit check into a shared internal."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'maxLimitsPerTx|maxOrdersPerTx|_limitsThisTx|orderCount'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(amend|amendOrder|modifyOrder|updateOrder)'}, {'function.body_contains_regex': 'orders\\s*\\[|_amend|\\.price\\s*='}, {'function.body_not_contains_regex': '(maxLimitsPerTx|maxOrdersPerTx|_limitsThisTx|_txOrderCount|perTxCount)\\s*(\\+\\+|\\+=)|require\\s*\\(\\s*_\\w*PerTx'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — amend-skips-max-limits-per-tx: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
