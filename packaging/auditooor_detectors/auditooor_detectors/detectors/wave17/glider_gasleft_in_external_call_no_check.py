"""
glider-gasleft-in-external-call-no-check — generated from reference/patterns.dsl/glider-gasleft-in-external-call-no-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-gasleft-in-external-call-no-check.yaml
Source: hexens-glider/gasleft-is-utilized-in-external-call-without-ensuring
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderGasleftInExternalCallNoCheck(AbstractDetector):
    ARGUMENT = "glider-gasleft-in-external-call-no-check"
    HELP = "External call forwards `gasleft()` (or a raw fraction thereof) as its gas parameter without a minimum-gas assertion. The EIP-150 63/64 rule means the callee sees ~63/64 of the available gas; a caller squeezing `gas * 1` can starve the subcall of gas, producing a silent OOG revert that the outer succ"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-gasleft-in-external-call-no-check.yaml"
    WIKI_TITLE = "Forwarding `gasleft()` to an external call without minimum-gas check"
    WIKI_DESCRIPTION = "Under EIP-150, an external call can only forward up to 63/64 of the remaining gas. If the caller supplies a tight outer gas budget, the subcall may run out of gas in a way that (a) reverts silently inside the subcall, (b) still returns success=false to the outer call which handles failure differently than an external revert. For safety-critical subcalls (transfers, state updates in other contracts"
    WIKI_EXPLOIT_SCENARIO = "Contract A's `forwardCall` executes `(bool ok, ) = target.call{gas: gasleft()}(data);`. Attacker calls `A.forwardCall(data)` with exactly enough gas that the subcall gets 63/64 of the tiny remainder — insufficient for the target's expected work. The subcall reverts with OOG but `ok == false` and the outer function handles the failure as 'graceful', e.g. by emitting a FailureRefunded event and retu"
    WIKI_RECOMMENDATION = "Either (1) fix a minimum gas stipend: `uint256 constant MIN_GAS = 100_000;` and `require(gasleft() >= MIN_GAS * 64 / 63);` before the call, or (2) forward a generous fixed amount (`gas: 1_000_000`) rather than `gasleft()`. Pair with a require(ok) guard that reverts on any subcall failure so partial-"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'gasleft'}]
    _MATCH = [{'function.kind': 'any'}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.body_contains_regex': '\\.call\\s*\\{\\s*gas\\s*:\\s*gasleft\\s*\\(\\s*\\)|\\{\\s*gas\\s*:\\s*gasleft\\s*\\(\\s*\\)\\s*\\*|\\.call\\s*\\{\\s*gas\\s*:\\s*gasleft\\s*\\(\\s*\\)\\s*/'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*gasleft\\s*\\(\\s*\\)\\s*(>=|>)\\s*|gasleft\\s*\\(\\s*\\)\\s*\\*\\s*64\\s*/\\s*63'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-gasleft-in-external-call-no-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
