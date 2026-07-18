"""
r94-loop-trade-missing-program-signer-sol — generated from reference/patterns.dsl/r94-loop-trade-missing-program-signer-sol.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-trade-missing-program-signer-sol.yaml
Source: loop-cycle-34-promotion-from-staged
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopTradeMissingProgramSignerSol(AbstractDetector):
    ARGUMENT = "r94-loop-trade-missing-program-signer-sol"
    HELP = "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: external/public trade-like entrypoints that move tokens without an inline or modifier-based router/program signer gate."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-trade-missing-program-signer-sol.yaml"
    WIKI_TITLE = "Trade path moves tokens without a router or program-signer caller gate"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. This row proves only the owned Solidity shape where an external/public trade-like entrypoint reaches token transfer logic without a visible `msg.sender == expectedRouter` style check or equivalent router/program-signer modifier in the same function."
    WIKI_EXPLOIT_SCENARIO = "A trade entrypoint transfers user or pool tokens and assumes an upstream router/program signer already authenticated the call, but the function itself exposes no caller-identity gate. Any account can call the trade path directly and impersonate the trusted router."
    WIKI_RECOMMENDATION = "Bind every externally reachable trade path to a trusted router/program signer with a modifier or explicit `require(msg.sender == expectedRouter)` style check, and keep this row NOT_SUBMIT_READY until evidence expands beyond the owned fixture pair."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(trade|executeTrade|swap|dispatch|hook)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(trade|executeTrade|swap|routeSwap|hook|dispatchSwap)'}, {'function.source_matches_regex': '\\.transfer\\s*\\(|\\.transferFrom\\s*\\(|_safeTransfer|IERC20'}, {'function.not_source_matches_regex': 'require\\s*\\([^)]*msg\\.sender\\s*==\\s*(expectedRouter|trustedRouter|dtfAddress|adapter)|\nonlyRouter|onlyAdapter|onlyBundler|onlyProgram|onlyDispatcher|\n_isApprovedCaller\\s*\\(|hasRole\\s*\\(\\s*ROUTER\n'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" — r94-loop-trade-missing-program-signer-sol: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
