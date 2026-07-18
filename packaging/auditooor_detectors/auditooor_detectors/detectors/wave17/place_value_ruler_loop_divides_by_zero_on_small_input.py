"""
place-value-ruler-loop-divides-by-zero-on-small-input — generated from reference/patterns.dsl/place-value-ruler-loop-divides-by-zero-on-small-input.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py place-value-ruler-loop-divides-by-zero-on-small-input.yaml
Source: lisa-mine-r99-case-02977-sherlock-knox-2022-09
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PlaceValueRulerLoopDividesByZeroOnSmallInput(AbstractDetector):
    ARGUMENT = "place-value-ruler-loop-divides-by-zero-on-small-input"
    HELP = "Place-value decomposition helper enters a `while (integer < ruler) ruler = ruler / 10` loop without first asserting that `integer > 0` (or that `x` is above the minimum value where `(x * ONE) >> 64 > 0`). For sufficiently small `x`, `integer` is 0; the loop never finds a ruler that is small enough; "
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/place-value-ruler-loop-divides-by-zero-on-small-input.yaml"
    WIKI_TITLE = "Place-value loop divides by zero when input shrinks below threshold"
    WIKI_DESCRIPTION = "Pattern fires on `_getPositivePlaceValues` style helpers used by ABDKMath / 64x64 fixed-point libraries to find the magnitude of the input. The loop `while (integer < ruler) ruler = ruler / 10;` is supposed to find the largest `10^k <= integer`, but when `integer == 0` the loop runs all the way down to `ruler == 0`. The next access (`values[1].ruler = ruler / 10`) panics with division-by-zero. Inp"
    WIKI_EXPLOIT_SCENARIO = "Knox sets a strike-price oracle update for a small underlying like a fractionalised NFT (price ≈ 0.000001 ETH). The oracle calls `OptionMath.ceil64x64(x)`; `_getPositivePlaceValues` runs and reverts. The strike-price update reverts; the option vault cannot mark its position. Subsequent settlement reads stale data; depending on direction, sellers or buyers are short-changed at expiry."
    WIKI_RECOMMENDATION = "Guard the loop entry: `if (integer == 0) return (0, emptyValues);`. Equivalently, require `integer > 0` at function entry. Add a fuzz test that exercises `_getPositivePlaceValues` over the full int128 range and asserts no panic. For libraries shared across protocols, audit every caller for the small"

    _PRECONDITIONS = [{'contract.has_function_matching': '_getPositivePlaceValues|_getPlaceValues|_decomposeDigits|placeValueOf'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '_getPositivePlaceValues|_getPlaceValues|_decomposeDigits|placeValueOf'}, {'function.body_contains_regex': 'while\\s*\\(\\s*[A-Za-z_][A-Za-z0-9_]*\\s*<\\s*ruler\\s*\\)\\s*\\{[^}]*ruler\\s*=\\s*ruler\\s*\\/\\s*10|while\\s*\\([^)]*<\\s*ruler\\b[^)]*\\)[^{]*\\{[^}]*ruler\\s*\\/=\\s*10'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*[A-Za-z_][A-Za-z0-9_]*\\s*>=\\s*[0-9]+\\s*\\)|require\\s*\\(\\s*ruler\\s*>=\\s*1|x\\s*>\\s*ONE|integer\\s*>=\\s*[0-9]+\\s*,|require\\s*\\(\\s*x\\s*>=\\s*\\d+|integer\\s*>\\s*0\\s*,'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — place-value-ruler-loop-divides-by-zero-on-small-input: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
