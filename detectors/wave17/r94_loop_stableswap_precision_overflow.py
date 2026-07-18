"""
r94-loop-stableswap-precision-overflow — generated from reference/patterns.dsl/r94-loop-stableswap-precision-overflow.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-stableswap-precision-overflow.yaml
Source: loop-cycle-6-stableswap-precision-sibling
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopStableswapPrecisionOverflow(AbstractDetector):
    ARGUMENT = "r94-loop-stableswap-precision-overflow"
    HELP = "r94-loop-stableswap-precision-overflow"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-stableswap-precision-overflow.yaml"
    WIKI_TITLE = "r94-loop-stableswap-precision-overflow"
    WIKI_DESCRIPTION = "r94-loop-stableswap-precision-overflow"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-stableswap-precision-overflow"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(stableswap|curveD|curveY|getY|getD|calc_D|calc_y)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(?i)(stableswap|curveD|curveY|getY|getD|calc_?D|calc_?y|calculateStable)'}, {'function.source_matches_regex': '(reserves?|balances?|poolBalance|xp\\s*\\[)\\s*[A-Za-z0-9_\\[\\]]*\\s*\\*\\s*\n(reserves?|balances?|poolBalance|xp\\s*\\[)\n'}, {'function.not_source_matches_regex': 'FullMath\\s*\\.\\s*mulDiv|Math\\s*\\.\\s*mulDiv|mulDivDown|mulDivUp|\nwmul\\s*\\(|wdiv\\s*\\(\n'}]

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
                info = [f, f" — r94-loop-stableswap-precision-overflow: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
