"""
r94-loop-usdt-nonzero-to-nonzero-approve-dos-grief — generated from reference/patterns.dsl/r94-loop-usdt-nonzero-to-nonzero-approve-dos-grief.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-usdt-nonzero-to-nonzero-approve-dos-grief.yaml
Source: solodit-20423-pashov-mugen
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopUsdtNonzeroToNonzeroApproveDosGrief(AbstractDetector):
    ARGUMENT = "r94-loop-usdt-nonzero-to-nonzero-approve-dos-grief"
    HELP = "r94-loop-usdt-nonzero-to-nonzero-approve-dos-grief"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-usdt-nonzero-to-nonzero-approve-dos-grief.yaml"
    WIKI_TITLE = "r94-loop-usdt-nonzero-to-nonzero-approve-dos-grief"
    WIKI_DESCRIPTION = "r94-loop-usdt-nonzero-to-nonzero-approve-dos-grief"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-usdt-nonzero-to-nonzero-approve-dos-grief"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Router|Integrator|Swap|Zap|Bridge|Vault|USDT)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(swap|deposit|bridge|zap|provideLiquidity|addLiquidity|executeTrade|routerCall|executeSwap|approveAndCall)'}, {'function.source_matches_regex': '(\\w*token\\w*\\.approve\\s*\\(\\s*\\w+\\s*,\\s*\\w*(amount|value)|IERC20\\s*\\(\\s*\\w+\\s*\\)\\.approve\\s*\\(\\s*\\w+\\s*,\\s*\\w*(amount|value))'}, {'function.not_source_matches_regex': '(\\.approve\\s*\\(\\s*\\w+\\s*,\\s*0\\s*\\)|safeApprove\\s*\\(|forceApprove\\s*\\(|safeDecreaseAllowance|safeIncreaseAllowance|allowance\\s*\\(\\s*\\w+\\s*,\\s*\\w+\\s*\\)\\s*==\\s*0|approveFromZeroFirst)'}]

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
                info = [f, f" — r94-loop-usdt-nonzero-to-nonzero-approve-dos-grief: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
