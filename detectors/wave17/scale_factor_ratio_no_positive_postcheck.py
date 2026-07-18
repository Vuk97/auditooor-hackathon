"""
scale-factor-ratio-no-positive-postcheck — generated from reference/patterns.dsl/scale-factor-ratio-no-positive-postcheck.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py scale-factor-ratio-no-positive-postcheck.yaml
Source: roadmap-slice-51-fund-loss-via-arithmetic-sibling-detector
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ScaleFactorRatioNoPositivePostcheck(AbstractDetector):
    ARGUMENT = "scale-factor-ratio-no-positive-postcheck"
    HELP = "Constructor or initializer derives a pricing/conversion scale from a division ratio and never proves the result is positive. Integer division can truncate the scale to zero, causing downstream price, redeem, liquidation, or share-conversion math to silently misvalue funds."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/scale-factor-ratio-no-positive-postcheck.yaml"
    WIKI_TITLE = "Scale factor ratio missing positive post-check"
    WIKI_DESCRIPTION = "A pricing, oracle, vault, or conversion contract derives a fixed `SCALE_FACTOR`, `PRECISION`, `RATE`, or similar value during construction or initialization from a ratio such as `numerator / denominator`. Guards often check only that denominator inputs are non-zero. They do not prove the derived scale itself is non-zero after integer division. For unlucky decimal/sample combinations, the result tr"
    WIKI_EXPLOIT_SCENARIO = "An oracle factory deploys a market oracle with `SCALE_FACTOR = quoteSample / baseSample` after validating both samples are non-zero. For a low-precision quote sample and high-precision base sample, `SCALE_FACTOR` truncates to zero. The market opens, and every health or liquidation path consuming the oracle either reverts or treats collateral as zero-valued. A liquidator can seize collateral for no"
    WIKI_RECOMMENDATION = "After deriving the scale, require it to be positive (`require(SCALE_FACTOR > 0)`) or compute it with an explicit rounding-aware `mulDiv`/fixed-point helper. Add boundary tests for decimal/sample tuples where the numerator is smaller than the denominator."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(Oracle|Pricing|Price|Rate|Scale|Factory|Conversion|Vault|Router)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '^(constructor|initialize|__\\w+_init|__init|_initialize)$'}, {'function.body_contains_regex': '\\b(SCALE_FACTOR|SCALE|PRECISION|FACTOR|RATE|EXCHANGE_RATE|CONVERSION_RATE|DENOMINATOR)\\b\\s*=\\s*[^;]*(?:\\/\\s*[a-zA-Z_][a-zA-Z0-9_]*|\\.div\\w*\\s*\\(|Div\\s*\\()'}, {'function.body_contains_regex': '(?i)(decimal|sample|vault|asset|share|price|feed|base|quote|conversion)'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*(SCALE_FACTOR|SCALE|PRECISION|FACTOR|RATE|EXCHANGE_RATE|CONVERSION_RATE|DENOMINATOR)\\s*(>|!=)\\s*0|if\\s*\\(\\s*(SCALE_FACTOR|SCALE|PRECISION|FACTOR|RATE|EXCHANGE_RATE|CONVERSION_RATE|DENOMINATOR)\\s*==\\s*0\\s*\\)\\s*revert|if\\s*\\(\\s*!\\s*(SCALE_FACTOR|SCALE|PRECISION|FACTOR|RATE|EXCHANGE_RATE|CONVERSION_RATE|DENOMINATOR)\\s*\\)\\s*revert|require\\s*\\(\\s*(?:[a-zA-Z_][a-zA-Z0-9_]*(?:Numerator|numerator|Sample|sample|Assets|assets|Shares|shares)|(?:quote|asset|base|num)[a-zA-Z0-9_]*)\\s*>=?\\s*(?:[a-zA-Z_][a-zA-Z0-9_]*(?:Denominator|denominator|Sample|sample|Assets|assets|Shares|shares)|(?:base|share|denom)[a-zA-Z0-9_]*)|ScaleFactorIsZero|ScaleZero|PrecisionZero|RateZero|mulDiv|FullMath\\.mulDiv|Math\\.mulDiv'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" — scale-factor-ratio-no-positive-postcheck: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
