"""
stableswap-amp-zero-config-liveness — generated from reference/patterns.dsl/stableswap-amp-zero-config-liveness.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py stableswap-amp-zero-config-liveness.yaml
Source: revert-stableswap-hooks/recall-2026-05-02
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class StableswapAmpZeroConfigLiveness(AbstractDetector):
    ARGUMENT = "stableswap-amp-zero-config-liveness"
    HELP = "StableSwap amp constructor/config path rejects only MAX_AMP, allowing amp=0 while downstream invariant math divides by amp-derived values."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/stableswap-amp-zero-config-liveness.yaml"
    WIKI_TITLE = "StableSwap amp=0 accepted by config but breaks pool liveness"
    WIKI_DESCRIPTION = "StableSwap amplification is a math-domain parameter, not an arbitrary configuration knob. Accepting zero can make invariant/swap math divide by zero or make recovery ramps impossible after liquidity exists."
    WIKI_EXPLOIT_SCENARIO = "A public factory deploys a pool with baseAmp=0. Liquidity can be added, but swaps later reach amp-derived denominators and revert; ramp recovery from zero is blocked by multiplier checks that compare against currentAmp."
    WIKI_RECOMMENDATION = "Reject amp=0 in every factory, constructor, and initializer path before deployment or registration. Add a liveness invariant that any accepted factory config can execute a minimal swap after balanced liquidity."

    _PRECONDITIONS = []
    _MATCH = []

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
                info = [f, f" — stableswap-amp-zero-config-liveness: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
