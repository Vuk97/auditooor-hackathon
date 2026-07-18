"""
r94-loop-cpmm-pool-creation-allows-n-gt-2-tokens-broken-math — generated from reference/patterns.dsl/r94-loop-cpmm-pool-creation-allows-n-gt-2-tokens-broken-math.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-cpmm-pool-creation-allows-n-gt-2-tokens-broken-math.yaml
Source: solodit-54977-c4-mantra-pool-manager
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopCpmmPoolCreationAllowsNGt2TokensBrokenMath(AbstractDetector):
    ARGUMENT = "r94-loop-cpmm-pool-creation-allows-n-gt-2-tokens-broken-math"
    HELP = "r94-loop-cpmm-pool-creation-allows-n-gt-2-tokens-broken-math"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-cpmm-pool-creation-allows-n-gt-2-tokens-broken-math.yaml"
    WIKI_TITLE = "r94-loop-cpmm-pool-creation-allows-n-gt-2-tokens-broken-math"
    WIKI_DESCRIPTION = "r94-loop-cpmm-pool-creation-allows-n-gt-2-tokens-broken-math"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-cpmm-pool-creation-allows-n-gt-2-tokens-broken-math"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(PoolFactory|Factory|PoolManager|CreatePool|PoolKind|UniswapV2|ConstantProduct)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(createPool|instantiatePool|registerPool|addPool|factoryCreatePool|newPool|openPool)'}, {'function.source_matches_regex': '(PoolKind\\.CPMM|PoolType\\.CPMM|ConstantProduct|CPMM|CpmmPool|XykPool)'}, {'function.not_source_matches_regex': '(require\\s*\\(\\s*\\w*assets\\.length\\s*==\\s*2|require\\s*\\(\\s*\\w*tokens\\.length\\s*==\\s*2|require\\s*\\(\\s*\\w*nTokens\\s*==\\s*2|N_COINS\\s*==\\s*2|n_coins\\s*==\\s*2|if\\s*\\(\\s*\\w*assets\\.length\\s*!=\\s*2\\s*\\)\\s*revert)'}]

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
                info = [f, f" — r94-loop-cpmm-pool-creation-allows-n-gt-2-tokens-broken-math: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
