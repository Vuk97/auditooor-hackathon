"""
options-force-exercise-itm-classification-inverted — generated from reference/patterns.dsl/options-force-exercise-itm-classification-inverted.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py options-force-exercise-itm-classification-inverted.yaml
Source: auditooor-R75-c4-2024-04-panoptic-H474
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OptionsForceExerciseItmClassificationInverted(AbstractDetector):
    ARGUMENT = "options-force-exercise-itm-classification-inverted"
    HELP = "`forceExercise` eligibility checks if the current tick is outside the strike band but does NOT branch on call-vs-put — so any leg outside the range is treated as OTM. For PUTs above the range and CALLs below the range, the position is actually ITM; force-exercising robs the long of their profit."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/options-force-exercise-itm-classification-inverted.yaml"
    WIKI_TITLE = "Force-exercise OTM test doesn't distinguish call / put — ITM positions can be force-closed"
    WIKI_DESCRIPTION = "Multi-leg options (Panoptic `TokenId`, SFPM, complex straddles) encode each leg with its type (call/put), side (long/short), strike, and width. Force-exercise is allowed only on OTM longs: the exercisor compensates the long with a fee but cuts the position before it becomes ITM again. A correct ITM/OTM test must dispatch on option type: for a CALL, ITM = `currentTick > strike+rangeUp`, OTM = `curr"
    WIKI_EXPLOIT_SCENARIO = "(1) Alice holds a long put on ETH/USDC with strike tick 200000, rangeDown 500, rangeUp 500. ETH drops and currentTick = 198000 — the put is ITM, position is worth ~2000-tick worth of profit. (2) Attacker (a short holder) sees the position is 'outside the strike range in the downward direction' (i.e. `currentTick < strike - rangeDown`). Because `validateIsExercisable` returns `return` (validated) w"
    WIKI_RECOMMENDATION = "Branch on leg type: `if (self.isLong(i) == 1 && self.tokenType(i) == CALL) return self.isOTM_call(currentTick, strike, range); else if (self.isLong(i) == 1 && self.tokenType(i) == PUT) return self.isOTM_put(currentTick, strike, range);`. Define `isOTM_call(tick, strike, range) = tick < strike - rang"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(forceExercise|validateIsExercisable|exerciseLongPosition|canForceExercise)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(validateIsExercisable|_validateIsExercisable|checkExercisable|canExercise|isExercisable)'}, {'function.body_contains_regex': '(isLong|longOrShort|isCall|isPut|tokenType)'}, {'function.body_contains_regex': 'currentTick\\s*>=?\\s*(_strike|strike)\\s*\\+\\s*range(Up)?'}, {'function.body_contains_regex': 'currentTick\\s*<\\s*(_strike|strike)\\s*-\\s*range(Down)?'}, {'function.body_not_contains_regex': '(isCall\\s*(==|!=)\\s*1|isPut\\s*(==|!=)\\s*1|tokenType\\s*(==|!=))'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — options-force-exercise-itm-classification-inverted: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
