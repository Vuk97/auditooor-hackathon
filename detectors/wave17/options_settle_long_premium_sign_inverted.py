"""
options-settle-long-premium-sign-inverted — generated from reference/patterns.dsl/options-settle-long-premium-sign-inverted.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py options-settle-long-premium-sign-inverted.yaml
Source: auditooor-R75-c4-2024-04-panoptic-H497
"""

# NOT_SUBMIT_READY: fixture-smoke/source-shape proof only for this row.

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OptionsSettleLongPremiumSignInverted(AbstractDetector):
    ARGUMENT = "options-settle-long-premium-sign-inverted"
    HELP = "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: `settleLongPremium` passes a positive realised long-premium delta directly into collateral `exercise(...)` instead of negating the debit owed by the long holder."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/options-settle-long-premium-sign-inverted.yaml"
    WIKI_TITLE = "Long-premium settlement credits buyer instead of debiting them (sign inversion)"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. In perpetual options, long option holders owe streaming premium to short sellers. This row only flags the direct source shape where a settlement function computes `realizedPremia` / `premiumToPay` / `owedPremium` / `longPremium` and passes that positive value directly as the collateral `exercise(...)` delta, without a visible negation at the call site."
    WIKI_EXPLOIT_SCENARIO = "Motivating Panoptic-shaped scenario: a long holder owes premium, settlement computes a positive `realizedPremia`, and `s_collateralToken0.exercise(longOwner, ..., realizedPremia)` credits the long holder instead of debiting them. This row does not claim corpus-backed exploit evidence beyond the owned fixture/source-shape smoke."
    WIKI_RECOMMENDATION = "Negate the long-holder debit before passing it to the collateral tracker, e.g. `exercise(owner, ..., -realizedPremia)` or the protocol's signed-slot equivalent. Do not promote from this fixture smoke alone; add protocol-specific evidence proving the sign convention and settlement accounting."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(settleLongPremium|_settleLongPremium|settlePremium|premiumOwed)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(settleLongPremium|_settleLongPremium|payLongPremium|chargeLongPremium|accrueLongPremium)'}, {'function.body_contains_regex': '(realizedPremia|premiumToPay|owedPremium|longPremium)'}, {'function.body_contains_regex': '\\.\\s*exercise\\s*\\([^;]*(realizedPremia|premiumToPay|owedPremium|longPremium)\\s*\\)'}, {'function.body_not_contains_regex': '\\.\\s*exercise\\s*\\([^;]*-\\s*(?:int(?:128|256)\\s*\\(\\s*)?(realizedPremia|premiumToPay|owedPremium|longPremium)'}, {'function.body_not_contains_regex': '((realizedPremia|premiumToPay|owedPremium|longPremium)\\s*=\\s*-|\\.neg\\s*\\(\\s*\\)|to(?:Left|Right)Slot\\s*\\(\\s*-)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — options-settle-long-premium-sign-inverted: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
