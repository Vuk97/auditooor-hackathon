"""
r94-loop-jit-penalty-bypass-per-position-salt — generated from reference/patterns.dsl/r94-loop-jit-penalty-bypass-per-position-salt.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-jit-penalty-bypass-per-position-salt.yaml
Source: solodit-61375-openzeppelin-uniswap-hooks-v110
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopJitPenaltyBypassPerPositionSalt(AbstractDetector):
    ARGUMENT = "r94-loop-jit-penalty-bypass-per-position-salt"
    HELP = "r94-loop-jit-penalty-bypass-per-position-salt"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-jit-penalty-bypass-per-position-salt.yaml"
    WIKI_TITLE = "r94-loop-jit-penalty-bypass-per-position-salt"
    WIKI_DESCRIPTION = "r94-loop-jit-penalty-bypass-per-position-salt"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-jit-penalty-bypass-per-position-salt"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(LiquidityPenaltyHook|JITPenalty|Hook|UniswapV4|PenaltyHook)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(beforeRemoveLiquidity|afterRemoveLiquidity|computeJitPenalty|applyPenalty|penaltyHook|recordLiquidityAdd|recordLiquidityRemove)'}, {'function.source_matches_regex': '(\\w*salt\\w*|position\\.salt|params\\.salt|modifyParams\\.salt)'}, {'function.not_source_matches_regex': '(keccak256\\s*\\([^)]*owner|keccak256\\s*\\([^)]*tickLower|positionKey\\s*\\([^)]*owner|Pool\\.positionKey|abi\\.encode\\s*\\([^)]*owner[^)]*salt|compositeKey|aggregateKeyForPosition|totalRecentLiquidityForOwner|ownerTotalJit|sumSaltsForOwner)'}]

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
                info = [f, f" — r94-loop-jit-penalty-bypass-per-position-salt: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
