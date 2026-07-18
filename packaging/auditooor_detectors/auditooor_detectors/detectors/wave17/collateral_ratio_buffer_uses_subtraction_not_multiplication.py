"""
collateral-ratio-buffer-uses-subtraction-not-multiplication — generated from reference/patterns.dsl/collateral-ratio-buffer-uses-subtraction-not-multiplication.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py collateral-ratio-buffer-uses-subtraction-not-multiplication.yaml
Source: lisa-mine-r99-case-05257-c4-salty-2024-01
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CollateralRatioBufferUsesSubtractionNotMultiplication(AbstractDetector):
    ARGUMENT = "collateral-ratio-buffer-uses-subtraction-not-multiplication"
    HELP = "Setter for `rewardPercent` / `minimumCollateralRatioPercent` computes the post-reward collateral ratio buffer via raw subtraction (`remainingRatio = collateralRatio - rewardPercent - 1`) instead of percentage multiplication (`remainingRatio = collateralRatio * (100 - rewardPercent) / 100`). The two "
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/collateral-ratio-buffer-uses-subtraction-not-multiplication.yaml"
    WIKI_TITLE = "Collateral-ratio buffer computed via subtraction of reward%, not multiplication"
    WIKI_DESCRIPTION = "Pattern fires on governance setters for `rewardPercentForCallingLiquidation` (or `minimumCollateralRatioPercent`) that compute the safety buffer as `remainingRatio = collateralRatio - rewardPercent - constant` and gate a state update on `remainingRatio >= 105`. The dimensional bug: `rewardPercent` is a percentage of collateral seized (units: % of LP), `collateralRatio` is collateral / debt (units:"
    WIKI_EXPLOIT_SCENARIO = "DAO calls `changeRewardPercentForCallingLiquidation(true)` four times to push rewardPercent from 5 to 9. Each step the check `110 - rewardPercent - 1 >= 105` passes (109, 108, 107, 106, ..., 105). Now consider a position at the minimum 110% collateral ratio: liquidator seizes 9% of collateral as reward; remaining collateral is 110 * 0.91 = 100.1% — below the 105% safety target. Liquidator does not"
    WIKI_RECOMMENDATION = "Replace subtraction with multiplication: `uint256 remainingRatio = (minimumCollateralRatioPercent * (100 - rewardPercentForCallingLiquidation)) / 100; require(remainingRatio >= 105, ...);`. Add a hardcoded fuzz test that walks the cartesian product of `(reward, ratio)` parameter ranges and asserts t"

    _PRECONDITIONS = [{'contract.has_state_var_matching': 'minimumCollateralRatioPercent|collateralRatio|liquidationRatio'}, {'contract.has_state_var_matching': 'rewardPercent|liquidatorReward|callerReward'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'changeReward|setReward|changeMinimumCollateral|setCollateralRatio|setLiquidationRatio|changeCollateralRatio'}, {'function.body_contains_regex': '\\b(remainingRatio|remainingCR|residualRatio)\\s*=\\s*[A-Za-z_][A-Za-z0-9_]*\\s*-\\s*[A-Za-z_][A-Za-z0-9_]*'}, {'function.body_not_contains_regex': '(\\*|\\bmul\\b)\\s*\\(\\s*1[eE]?[0-9]+\\s*-|\\bcollateralRatio\\s*\\*\\s*\\(|/\\s*100\\s*\\)|\\bWAD\\b|\\bRAY\\b'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — collateral-ratio-buffer-uses-subtraction-not-multiplication: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
