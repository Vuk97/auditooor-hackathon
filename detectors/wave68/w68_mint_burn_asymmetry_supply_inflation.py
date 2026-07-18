"""
w68-mint-burn-asymmetry-supply-inflation — generated from reference/patterns.dsl/w68-mint-burn-asymmetry-supply-inflation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py w68-mint-burn-asymmetry-supply-inflation.yaml
Source: W6-8 zero-coverage detector batch (auditooor capability lift)
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class W68MintBurnAsymmetrySupplyInflation(AbstractDetector):
    ARGUMENT = "w68-mint-burn-asymmetry-supply-inflation"
    HELP = "Mint and burn accounting asymmetry allows supply inflation because burn does not decrement totalSupply"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/w68-mint-burn-asymmetry-supply-inflation.yaml"
    WIKI_TITLE = "Mint and burn accounting asymmetry allows supply inflation"
    WIKI_DESCRIPTION = "The mint path increments totalSupply but the burn path decrements only the holder balance, leaving totalSupply permanently inflated relative to circulating tokens."
    WIKI_EXPLOIT_SCENARIO = "Mint and burn accounting asymmetry allows supply inflation because burn does not decrement totalSupply"
    WIKI_RECOMMENDATION = "Decrement totalSupply symmetrically in the burn path."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches': '.*burn.*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.body_contains_regex': '(?i)balanceOf\\s*\\[[^\\]]+\\]\\s*-='}, {'function.body_not_contains_regex': '(?i)totalSupply\\s*-='}]

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
                info = [f, f" — w68-mint-burn-asymmetry-supply-inflation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
