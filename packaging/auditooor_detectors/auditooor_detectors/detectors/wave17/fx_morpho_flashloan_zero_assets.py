"""
fx-morpho-flashloan-zero-assets — generated from reference/patterns.dsl/fx-morpho-flashloan-zero-assets.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-morpho-flashloan-zero-assets.yaml
Source: github:morpho-org/morpho-blue@70e2636
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxMorphoFlashloanZeroAssets(AbstractDetector):
    ARGUMENT = "fx-morpho-flashloan-zero-assets"
    HELP = "flashLoan() does not reject assets==0. A zero-amount flash loan still fires the callback, enabling re-entrancy or griefing patterns without any economic cost or repayment obligation."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-morpho-flashloan-zero-assets.yaml"
    WIKI_TITLE = "Flash loan zero-amount callback — missing assets != 0 guard"
    WIKI_DESCRIPTION = "A flashLoan function that accepts assets=0 invokes the external borrower callback with zero tokens lent. The callback executes in the context of the pool, potentially reading or modifying pool state at zero cost. The safeTransfer and safeTransferFrom of 0 succeed unconditionally, so the repayment check also passes trivially."
    WIKI_EXPLOIT_SCENARIO = "Morpho cantina-670 (2023): flashLoan(token, 0, payload) fires onMorphoFlashLoan with assets=0. Attacker uses the callback to interact with other pool functions while holding no debt, potentially causing accounting drift."
    WIKI_RECOMMENDATION = "Add `require(assets != 0, ZERO_ASSETS)` as the first statement in flashLoan(). Extend to any flash-mint or flash-borrow entry point that takes an amount parameter."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^flashLoan$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^flashLoan$'}, {'function.has_external_call': True}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*assets\\s*!=\\s*0|require\\s*\\(\\s*amount\\s*!=\\s*0|if\\s*\\(\\s*assets\\s*==\\s*0\\s*\\)\\s*revert'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-morpho-flashloan-zero-assets: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
