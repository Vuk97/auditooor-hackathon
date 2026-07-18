"""
external-call-in-loop-gas-griefing — generated from reference/patterns.dsl/external-call-in-loop-gas-griefing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py external-call-in-loop-gas-griefing.yaml
Source: solodit/external-call-in-loop-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ExternalCallInLoopGasGriefing(AbstractDetector):
    ARGUMENT = "external-call-in-loop-gas-griefing"
    HELP = "External/public function iterates a list and makes an external call per iteration without a gas cap or try-catch; a malicious recipient can consume all gas and DoS the whole batch."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/external-call-in-loop-gas-griefing.yaml"
    WIKI_TITLE = "External call in loop enables gas-griefing DoS"
    WIKI_DESCRIPTION = "The function iterates over an array (often caller-supplied or appendable by users) and performs an external call on each element. Because Solidity forwards all remaining gas to external calls by default, a single malicious recipient that consumes all available gas (e.g. an unbounded fallback or revert-bomb) will abort the entire transaction. Every other item in the batch is denied service. Typical"
    WIKI_EXPLOIT_SCENARIO = "A reward distributor iterates `recipients[]` and calls `recipients[i].transfer(amount[i])` for each element. Attacker registers as a recipient with a contract whose `receive()` consumes all remaining gas (or reverts with a return-bomb). The distributor's transaction always reverts or runs out of gas partway through the loop, permanently stalling the distribution for every legitimate recipient in t"
    WIKI_RECOMMENDATION = "Either (a) bound the per-iteration forwarded gas with `.call{gas: SAFE_GAS}(...)` for a small, bounded `SAFE_GAS`, (b) wrap the external call in `try ... catch` so a single failing recipient doesn't poison the whole batch, or (c) switch to a pull-payment pattern where each recipient claims their sha"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'for\\s*\\([^)]*\\)\\s*\\{[^}]*\\.(call|transfer|safeTransfer|call\\{[^}]*\\})'}, {'function.body_not_contains_regex': 'gas\\s*:\\s*\\w+|try\\s+.*\\s+catch|gasleft\\s*\\(\\s*\\)\\s*>|MAX_CALL_GAS'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — external-call-in-loop-gas-griefing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
