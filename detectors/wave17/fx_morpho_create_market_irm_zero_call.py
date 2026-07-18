"""
fx-morpho-create-market-irm-zero-call — generated from reference/patterns.dsl/fx-morpho-create-market-irm-zero-call.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-morpho-create-market-irm-zero-call.yaml
Source: github:morpho-org/morpho-blue@b9fe01c
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxMorphoCreateMarketIrmZeroCall(AbstractDetector):
    ARGUMENT = "fx-morpho-create-market-irm-zero-call"
    HELP = "createMarket() calls IRM.borrowRate() unconditionally, including when irm == address(0). Protocols that support zero-IRM markets cannot be initialized because the call to address(0) reverts."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-morpho-create-market-irm-zero-call.yaml"
    WIKI_TITLE = "Market creation calls IRM even when irm is address(0) — zero-IRM markets blocked"
    WIKI_DESCRIPTION = "Protocols that allow markets with irm == address(0) to represent zero-interest or fixed-rate instruments must guard the IRM initialization call. Without `if (irm != address(0))`, createMarket() always reverts when irm is the zero address, making that market configuration permanently inaccessible."
    WIKI_EXPLOIT_SCENARIO = "Morpho Blue post-cantina (2023): operator tries to create a zero-IRM market for a fixed-rate vault. createMarket() reverts on IIrm(address(0)).borrowRate(), permanently blocking the feature."
    WIKI_RECOMMENDATION = "Wrap stateful IRM initialization calls with `if (marketParams.irm != address(0)) { ... }`. Document that address(0) represents a no-op IRM."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^createMarket$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^createMarket$'}, {'function.body_contains_regex': 'IIrm\\s*\\(|IInterestRateModel\\s*\\('}, {'function.body_not_contains_regex': 'irm\\s*!=\\s*address\\s*\\(\\s*0\\s*\\)|if\\s*\\(.*irm.*==.*0'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-morpho-create-market-irm-zero-call: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
