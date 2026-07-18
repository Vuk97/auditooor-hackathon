"""
perp-reallocate-depends-on-slot0-not-twap - generated from reference/patterns.dsl/perp-reallocate-depends-on-slot0-not-twap.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py perp-reallocate-depends-on-slot0-not-twap.yaml
Source: auditooor-R75-c4-2024-05-predy-H209
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PerpReallocateDependsOnSlot0NotTwap(AbstractDetector):
    ARGUMENT = "perp-reallocate-depends-on-slot0-not-twap"
    HELP = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. Flags only the owned public `reallocate()` shape that reads `slot0()` and immediately decides whether the LP range is out of band from `currentTick < tickLower || currentTick > tickUpper`."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/perp-reallocate-depends-on-slot0-not-twap.yaml"
    WIKI_TITLE = "Perp LP reallocate gates on spot `slot0()` tick instead of TWAP"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. This row proves only the owned public `reallocate()` shape where a perp-style LP reallocator reads `pool.slot0()` and immediately compares `currentTick` against `tickLower` / `tickUpper` before repositioning liquidity. No corpus-backed exploit evidence has been established beyond the owned fixture pair."
    WIKI_EXPLOIT_SCENARIO = "A perp protocol keeps concentrated LP near market and exposes `reallocate()`. An attacker flash-loans inventory, moves the Uniswap spot tick for one block, and calls `reallocate()`. Because the decision keys off `slot0()` rather than a TWAP, the protocol shifts liquidity into a manipulated range and is left mispositioned after the attacker unwinds."
    WIKI_RECOMMENDATION = "Use a TWAP-derived tick via `observe(...)` or `OracleLibrary.consult(...)` for the range decision, and keep this row NOT_SUBMIT_READY until validation expands beyond the owned fixture pair."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(Perp|Range|Realloc|slot0|tickLower|tickUpper)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^reallocate$'}, {'function.body_contains_regex': '\\.slot0\\(\\)'}, {'function.body_contains_regex': 'currentTick\\s*<\\s*tickLower\\s*\\|\\|\\s*currentTick\\s*>\\s*tickUpper'}, {'function.body_contains_regex': 'outOfRange'}, {'function.body_contains_regex': '_repositionLiquidity\\s*\\(\\s*currentTick\\s*\\)'}, {'function.body_not_contains_regex': '(?i)(observe|consult|getTimeWeightedAverageTick|OracleLibrary|twapTick)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" - perp-reallocate-depends-on-slot0-not-twap: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
