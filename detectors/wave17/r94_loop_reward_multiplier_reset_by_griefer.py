"""
r94-loop-reward-multiplier-reset-by-griefer — generated from reference/patterns.dsl/r94-loop-reward-multiplier-reset-by-griefer.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-reward-multiplier-reset-by-griefer.yaml
Source: loop-cycle-70-sol-sibling
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopRewardMultiplierResetByGriefer(AbstractDetector):
    ARGUMENT = "r94-loop-reward-multiplier-reset-by-griefer"
    HELP = "r94-loop-reward-multiplier-reset-by-griefer"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-reward-multiplier-reset-by-griefer.yaml"
    WIKI_TITLE = "r94-loop-reward-multiplier-reset-by-griefer"
    WIKI_DESCRIPTION = "r94-loop-reward-multiplier-reset-by-griefer"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-reward-multiplier-reset-by-griefer"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(handleBalanceUpdate|updateUserWeight|refreshMultiplier|recomputeBoost)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(handleBalanceUpdate|updateUserWeight|refreshMultiplier|syncUser|recomputeBoost|updateStakeWeight)'}, {'function.source_matches_regex': '(multiplier|boost|weight|stakeWeight)\\s*\\[\\s*\\w+\\s*\\]\\s*=\\s*1\\b|resetMultiplier\\s*\\('}, {'function.not_source_matches_regex': '(msg\\.sender\\s*==\\s*(user|target|account)|require\\s*\\(\\s*(user|target|account)\\s*==\\s*msg\\.sender|onlySelf|onlyUser)'}]

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
                info = [f, f" — r94-loop-reward-multiplier-reset-by-griefer: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
