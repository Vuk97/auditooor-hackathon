"""
r94-loop-hook-addliquidity-attacker-chosen-poolkey — generated from reference/patterns.dsl/r94-loop-hook-addliquidity-attacker-chosen-poolkey.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-hook-addliquidity-attacker-chosen-poolkey.yaml
Source: solodit-62647-spearbit-semantic-layer-svfhook
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopHookAddliquidityAttackerChosenPoolkey(AbstractDetector):
    ARGUMENT = "r94-loop-hook-addliquidity-attacker-chosen-poolkey"
    HELP = "r94-loop-hook-addliquidity-attacker-chosen-poolkey"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-hook-addliquidity-attacker-chosen-poolkey.yaml"
    WIKI_TITLE = "r94-loop-hook-addliquidity-attacker-chosen-poolkey"
    WIKI_DESCRIPTION = "r94-loop-hook-addliquidity-attacker-chosen-poolkey"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-hook-addliquidity-attacker-chosen-poolkey"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Hook|BaseHook|PoolKey|UniswapV4|IHook|Points)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(addLiquidity|addPoints|claimPoints|depositLiquidity|earnPoints|provideLiquidity|creditLiquidity|recordLiquidity)'}, {'function.source_matches_regex': '(PoolKey\\s+\\w+|PoolKey\\s+calldata\\s+|PoolKey\\s+memory\\s+)'}, {'function.not_source_matches_regex': '(require\\s*\\(\\s*\\w*key\\s*==\\s*\\w*canonical|require\\s*\\(\\s*\\w*key\\s*==\\s*\\w*target|require\\s*\\(\\s*\\w*key\\s*==\\s*\\w*registered|require\\s*\\(\\s*\\w*poolId\\s*==\\s*\\w*(target|canonical|expected)|isRegisteredPool|registry\\.get\\s*\\(|canonicalPoolId|expectedPoolKey)'}]

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
                info = [f, f" — r94-loop-hook-addliquidity-attacker-chosen-poolkey: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
