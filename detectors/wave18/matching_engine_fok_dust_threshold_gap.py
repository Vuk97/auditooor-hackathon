"""
matching-engine-fok-dust-threshold-gap — generated from reference/patterns.dsl/matching-engine-fok-dust-threshold-gap.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py matching-engine-fok-dust-threshold-gap.yaml
Source: auditooor/roadmap-slice28-matching-engine-recall
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MatchingEngineFokDustThresholdGap(AbstractDetector):
    ARGUMENT = "matching-engine-fok-dust-threshold-gap"
    HELP = "FOK/fill-or-kill path rejects sub-lot dust residual rather than comparing against the market lot threshold."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/matching-engine-fok-dust-threshold-gap.yaml"
    WIKI_TITLE = "FOK path treats dust residual as material fill failure"
    WIKI_DESCRIPTION = "A matching engine with lot-size or min-fill units should accept a fill-or-kill execution when the unfilled residual is below the market's material threshold. Reverting on any nonzero residual bounces otherwise-fillable orders and misrepresents book liquidity."
    WIKI_EXPLOIT_SCENARIO = "A maker submits a FOK order that would fill except for a sub-lot dust residual. The engine reverts because residual != 0, denying the fill and enabling orderflow griefing around lot boundaries."
    WIKI_RECOMMENDATION = "Compare residual against lot-size/min-fill/tick-size thresholds and add boundary tests for exact fill, sub-lot residual, and material residual."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(FOK|FillOrKill|fillOrKill)'}, {'contract.source_matches_regex': '(LOT_SIZE|lotSize|MIN_LOT|minLot|minFill|tickSize)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(fillOrder|matchOrder|_match|fill)'}, {'function.body_contains_regex': '(residual|remaining)'}, {'function.body_contains_regex': '(residual\\s*==\\s*0|require\\s*\\(\\s*residual\\s*==\\s*0|residual\\s*>\\s*0|remaining\\s*!=\\s*0|filled\\s*!=\\s*order\\.(size|qty|amount))'}, {'function.body_not_contains_regex': '((residual|remaining)\\s*(<|<=|>|>=)\\s*(LOT_SIZE|lotSize|MIN_LOT|minLot|minFill|tickSize)|residual\\s*==\\s*0\\s*\\|\\|\\s*residual\\s*<|remaining\\s*==\\s*0\\s*\\|\\|\\s*remaining\\s*<)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — matching-engine-fok-dust-threshold-gap: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
