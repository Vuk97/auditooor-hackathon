"""
validate-range-uses-value-only-in-revert-no-bounds-check — generated from reference/patterns.dsl/validate-range-uses-value-only-in-revert-no-bounds-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py validate-range-uses-value-only-in-revert-no-bounds-check.yaml
Source: lisa-mine-r99-case-02120-sherlock-gmx-2023-02
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ValidateRangeUsesValueOnlyInRevertNoBoundsCheck(AbstractDetector):
    ARGUMENT = "validate-range-uses-value-only-in-revert-no-bounds-check"
    HELP = "An internal `_validateRange(key, value)` style helper that documents itself as bounds-checking the value, but the function body never actually compares `value` against any min/max — it only reads `value` to embed in a revert error message. Callers assume validation happened; in reality the function "
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/validate-range-uses-value-only-in-revert-no-bounds-check.yaml"
    WIKI_TITLE = "_validateRange documents bounds check but only uses value in revert error"
    WIKI_DESCRIPTION = "Pattern fires on `_validateRange`-style internal helpers whose declared purpose is to validate that `value` lies within a per-key allowed range, but which contain (a) no comparison operator (`<`, `>`, `<=`, `>=`) against `value`, and (b) no `require` involving `value`. The only use of `value` is as an argument to a revert error so the caller (and off-chain logs) can see what was rejected. Net effe"
    WIKI_EXPLOIT_SCENARIO = "Governance keeper sets a fee factor via `setUint(SOME_FACTOR_KEY, valueAbove100Percent)`. `_validateRange` is called, sees that `SOME_FACTOR_KEY` is not in any of its `revert`-listed buckets, returns silently, and the data-store accepts a fee factor > 100%. Trades using that factor mis-price catastrophically. Discovery is delayed because the function name suggests the value was validated; all logs"
    WIKI_RECOMMENDATION = "Either (a) implement actual per-key min/max bounds: `(uint256 minV, uint256 maxV) = _boundsForKey(baseKey); require(value >= minV && value <= maxV, ...);`, or (b) rename the function to `_rejectRestrictedKeys` so the function name matches its actual behaviour. Option (a) is the audit-correct fix; op"

    _PRECONDITIONS = [{'contract.has_function_matching': '_validateRange|_validateBounds|_validateValue|validateRange|validateBounds|validateConfigValue'}]
    _MATCH = [{'function.kind': 'internal'}, {'function.name_matches': '_validateRange|_validateBounds|_validateValue|validateRange|validateBounds|validateConfigValue'}, {'function.has_param_name_matching': 'value|amount|factor|param'}, {'function.body_contains_regex': 'revert\\s+[A-Z][A-Za-z0-9_]*\\s*\\([^)]*\\bvalue\\b[^)]*\\)'}, {'function.body_not_contains_regex': '\\bvalue\\s*(<|>|<=|>=)\\s*[A-Za-z0-9_]'}, {'function.body_not_contains_regex': '\\b(min|max|MIN|MAX|lower|upper|LOWER|UPPER|floor|ceiling)\\s*[A-Za-z0-9_]*\\s*(<|>|<=|>=)\\s*value\\b'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*value\\b'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': False}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — validate-range-uses-value-only-in-revert-no-bounds-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
