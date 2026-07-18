"""
withdrawable-per-share-division-before-multiplication — generated from reference/patterns.dsl/withdrawable-per-share-division-before-multiplication.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py withdrawable-per-share-division-before-multiplication.yaml
Source: auditooor-R75-code4rena-2024-04-gondi-67
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class WithdrawablePerShareDivisionBeforeMultiplication(AbstractDetector):
    ARGUMENT = "withdrawable-per-share-division-before-multiplication"
    HELP = "Share-to-asset math divides totalAssets by totalShares before multiplying by the user's shares, so per-share rounds down and the withdrawer loses precision."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/withdrawable-per-share-division-before-multiplication.yaml"
    WIKI_TITLE = "Withdrawable-per-share computes division before multiplication, locking funds proportional to rounding loss"
    WIKI_DESCRIPTION = "A withdrawal queue computes `perShare = totalAssets / totalShares` and then `available = myShares * perShare`. When totalShares and totalAssets are close in magnitude (e.g. 5e8 vs 1e9), the intermediate `perShare = 1` (instead of 1.999...), and the user gets only half of what they should. Funds are stuck in the contract indefinitely."
    WIKI_EXPLOIT_SCENARIO = "A pool with 500_000_001 shares and 1_000_000_000 asset-wei. An LP with 100_000_000 shares should receive ~199_999_999 but gets 100_000_000 — 50% loss. The leftover sits in the contract forever."
    WIKI_RECOMMENDATION = "Use `mulDiv(userShares, totalAssets, totalShares)` in a single step (OpenZeppelin Math.mulDiv or FullMath). Add a test with totalAssets ≈ 2 * totalShares and assert the payout within 1 wei of the ideal."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(?i)_?getAvailable|getWithdrawable|previewRedeem|_convertToAssets|sharesToAssets|withdrawablePerShare'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': '(?i)(totalAssets|balanceOf|received|assets|amount).{0,40}/\\s*\\w*(totalShares|totalSupply|shares)'}, {'function.body_contains_regex': '(?i)shares\\s*\\*|\\*\\s*\\w*perShare'}, {'function.body_not_contains_regex': '(?i)mulDiv|muldiv|FullMath\\.mulDiv|fixedPoint|RAY|WAD|1e18|1e27'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — withdrawable-per-share-division-before-multiplication: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
