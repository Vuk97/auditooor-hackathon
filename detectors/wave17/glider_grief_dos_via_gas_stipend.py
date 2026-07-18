"""
glider-grief-dos-via-gas-stipend — generated from reference/patterns.dsl/glider-grief-dos-via-gas-stipend.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-grief-dos-via-gas-stipend.yaml
Source: glider/grief-dos-calls-utilizing
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderGriefDosViaGasStipend(AbstractDetector):
    ARGUMENT = "glider-grief-dos-via-gas-stipend"
    HELP = "External call sends a fixed low gas stipend (transfer's 2300, or literal < 10k). Contract recipients with an expensive fallback DoS distribution loops that silently assume stipend is sufficient."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-grief-dos-via-gas-stipend.yaml"
    WIKI_TITLE = "Fixed low gas stipend enables grief-DoS on external call"
    WIKI_DESCRIPTION = "`payable(x).transfer(amount)` hard-codes a 2300-gas stipend. Any contract recipient whose fallback consumes even a single SSTORE (20k gas) reverts the outer call. Same applies to `.call{gas: 3000}`. Inside a distribution loop that iterates over many recipients, a single malicious recipient bricks the whole loop."
    WIKI_EXPLOIT_SCENARIO = "Airdrop contract loops over winners and calls `payable(winner).transfer(amount)`. Attacker deploys a wallet with `fallback() { uint256 x; assembly { sstore(0, 1) } }`. When the airdrop reaches their address, the transfer reverts; no other winner receives any funds."
    WIKI_RECOMMENDATION = "Use the pull pattern: credit `pending[user] += amount` and let users call `claim()` themselves. If push is required, use `.call{value: amount}(\"\")` without a gas limit and handle the `ok == false` return by crediting the pending map."

    _PRECONDITIONS = [{'contract.source_matches_regex': '\\.call\\s*\\{|\\.transfer\\s*\\(|\\.send\\s*\\('}]
    _MATCH = [{'function.kind': 'any'}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.body_contains_regex': '\\.call\\s*\\{\\s*gas\\s*:\\s*\\d+|\\.call\\{gas:\\s*\\d+|\\.transfer\\s*\\(|\\.send\\s*\\('}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.body_contains_regex': '\\.call\\s*\\{\\s*gas\\s*:\\s*(\\d{1,4})\\s*,|\\.transfer\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-grief-dos-via-gas-stipend: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
