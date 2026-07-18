"""
r94-loop-perps-liquidation-state-flip — generated from reference/patterns.dsl/r94-loop-perps-liquidation-state-flip.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-perps-liquidation-state-flip.yaml
Source: loop-cycle-19-perps-liquidation-state-flip-sol-sibling
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopPerpsLiquidationStateFlip(AbstractDetector):
    ARGUMENT = "r94-loop-perps-liquidation-state-flip"
    HELP = "r94-loop-perps-liquidation-state-flip"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-perps-liquidation-state-flip.yaml"
    WIKI_TITLE = "r94-loop-perps-liquidation-state-flip"
    WIKI_DESCRIPTION = "r94-loop-perps-liquidation-state-flip"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-perps-liquidation-state-flip"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(position|liquidat|Perp|Clearing)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(?i)(liquidate|deleverage|forceClose|liquidatePosition)'}, {'function.source_matches_regex': 'position\\.size|\\.positionSize|\\.size\\s*='}, {'function.not_source_matches_regex': 'position\\.isLong|position\\.direction|position\\.side|\nrequire\\s*\\([^)]*(isLong|direction|side)|\nassertDirection|sameDirection|sameSide\n'}]

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
                info = [f, f" — r94-loop-perps-liquidation-state-flip: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
