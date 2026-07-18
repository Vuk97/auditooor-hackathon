"""
constructor-precision-factor-truncates-to-zero — generated from reference/patterns.dsl/constructor-precision-factor-truncates-to-zero.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py constructor-precision-factor-truncates-to-zero.yaml
Source: auditooor-R101-morpho-I2.A
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ConstructorPrecisionFactorTruncatesToZero(AbstractDetector):
    ARGUMENT = "constructor-precision-factor-truncates-to-zero"
    HELP = "Constructor / initializer computes a precision/scale factor as `10**(...) * sampleA / sampleB` (or similar exponent-driven integer chain) and never asserts the result is non-zero. With unfortunate decimal + sample combinations the integer division truncates to zero, which downstream `price()` / `rat"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/constructor-precision-factor-truncates-to-zero.yaml"
    WIKI_TITLE = "Constructor scale factor `10**(...) * a / b` integer-truncates to zero with no post-check"
    WIKI_DESCRIPTION = "An oracle or share-conversion contract derives a fixed `SCALE_FACTOR` (or `PRECISION`, `FACTOR`, etc.) at construction time via integer arithmetic over caller-supplied decimal counts and `vaultConversionSample` parameters: `10**(qDec + feed1Dec + feed2Dec - bDec - bFeedDec) * quoteSample / baseSample`. Solidity's plain `*` / `/` truncates rather than rounding, so any combination where `baseSample "
    WIKI_EXPLOIT_SCENARIO = "Oracle factory deploys `OracleV2(baseDec=18, quoteDec=6, baseFeedDec=8, quoteFeedDec=8, baseSample=1e18, quoteSample=1)`. SCALE_FACTOR = `10**(36 + 6 + 8 - 18 - 8) * 1 / 1e18 = 10**24 / 1e18 * 1 = 1e6 / 1e18 = 0` (truncated). All four constructor `require`s pass. `oracle.price()` returns 0. A market opened against this oracle treats every borrower's collateral value as zero (so health-factor check"
    WIKI_RECOMMENDATION = "At the end of the constructor (or initialize), assert the derived factor is non-zero: `require(SCALE_FACTOR > 0, ScaleFactorIsZero());`. If you need the more permissive form, switch the multiplication to `Math.mulDiv(10**exponent, quoteSample, baseSample)` which keeps the intermediate result in 256 "

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Oracle|Pricing|Rate|Scale|Factory|Oracle\\w*|Price\\w*Feed|Conversion'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '^(constructor|initialize|__\\w+_init|__init|_initialize)$'}, {'function.body_contains_regex': '\\b(SCALE_FACTOR|SCALE|PRECISION|FACTOR|DENOMINATOR|UNIT|ONE|RAY|WAD)\\b\\s*=\\s*[^;]*\\b10\\s*\\*\\*\\s*\\([^)]+\\)|\\b(SCALE_FACTOR|SCALE|PRECISION|FACTOR|DENOMINATOR)\\b\\s*=\\s*10\\s*\\*\\*\\s*\\('}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*(SCALE_FACTOR|SCALE|PRECISION|FACTOR|DENOMINATOR|UNIT|ONE|RAY|WAD)\\s*(>|!=)\\s*0|if\\s*\\(\\s*(SCALE_FACTOR|SCALE|PRECISION|FACTOR|DENOMINATOR|UNIT|ONE|RAY|WAD)\\s*==\\s*0\\s*\\)\\s*revert|require\\s*\\(\\s*\\w+\\s*>\\s*0\\s*,\\s*"(SCALE|PRECISION|FACTOR)|mulDiv|FullMath\\.mulDiv'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — constructor-precision-factor-truncates-to-zero: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
