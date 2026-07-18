"""
glider-rounding-to-zero-solvency-bypass — generated from reference/patterns.dsl/glider-rounding-to-zero-solvency-bypass.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-rounding-to-zero-solvency-bypass.yaml
Source: glider-query-db/rounding-to-zero-solvency-bypass
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderRoundingToZeroSolvencyBypass(AbstractDetector):
    ARGUMENT = "glider-rounding-to-zero-solvency-bypass"
    HELP = "Solvency or debt-accrual math rounds down to 0 for dust-sized positions. Attacker opens many dust positions, each accruing zero interest, extracting principal over time."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-rounding-to-zero-solvency-bypass.yaml"
    WIKI_TITLE = "Debt rounds to zero enabling dust-position interest bypass"
    WIKI_DESCRIPTION = "When debt interest is computed as `principal * rate / SCALE`, small principals round to 0 interest per block. Over many dust positions, attacker bypasses interest accrual while using protocol liquidity."
    WIKI_EXPLOIT_SCENARIO = "Attacker opens 10,000 loans of $0.10 each. Each has `principal * 1e15 / 1e18 = 0` interest. Total exposure = $1,000 borrowed, zero interest ever accrues. Protocol bleeds APR worth of income."
    WIKI_RECOMMENDATION = "Round interest up (`mulDivUp` / add scale-1 in numerator), or enforce a minimum-position-size floor."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'debt|loan|collateral|solvency|healthFactor'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '(debt|owed|totalDebt|loan|shortfall)\\s*[\\*/]\\s*\\w+\\s*[+-]?\\s*[0-9]*\\s*;|\\w+\\s*/\\s*(price|rate|ratio|pct)'}, {'function.body_not_contains_regex': 'ceil|mulDivUp|roundUp|Rounding\\.Up|\\+\\s*1\\s*;|\\+\\s*(price|rate|ratio)\\s*-\\s*1'}, {'function.name_matches': '^(borrow|repay|liquidate|_checkSolvency|isSolvent|healthFactor|_accrue)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-rounding-to-zero-solvency-bypass: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
