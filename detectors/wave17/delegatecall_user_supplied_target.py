"""
delegatecall-user-supplied-target — generated from reference/patterns.dsl/delegatecall-user-supplied-target.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py delegatecall-user-supplied-target.yaml
Source: auditooor-seed
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DelegatecallUserSuppliedTarget(AbstractDetector):
    ARGUMENT = "delegatecall-user-supplied-target"
    HELP = "External/public function delegatecalls to an un-allow-listed target (SWC-112) — attacker can execute arbitrary code in the caller's storage context."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/delegatecall-user-supplied-target.yaml"
    WIKI_TITLE = "delegatecall with user-supplied target without allow-list (SWC-112)"
    WIKI_DESCRIPTION = "A function forwards an externally-provided address (msg.sender-derived, calldata, or unchecked external state) to `delegatecall`. Because delegatecall executes the callee's code in the caller's storage / msg.sender context, a malicious callee can rewrite state variables, zero the owner, drain funds, or selfdestruct the caller. The fix is to constrain the target to an explicit allow-list or a singl"
    WIKI_EXPLOIT_SCENARIO = "Attacker deploys a contract whose function overwrites slot 0 (often `owner`) and transfers funds. They pass its address to the victim's unchecked delegatecall entry-point. The victim's storage is rewritten: the attacker is now owner and can drain the contract."
    WIKI_RECOMMENDATION = "Restrict delegatecall targets to an immutable or tightly-controlled allow-list (e.g., `require(implementations[target], 'bad impl')` or `require(target == IMPLEMENTATION, 'bad impl')`). Never derive the target address from untrusted calldata, msg.sender, or mutable external state without a check."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.body_contains_regex': '\\.delegatecall\\s*\\(|delegatecallAt'}, {'function.body_not_contains_regex': 'require\\s*\\(.*(implementations|allowed|trustedTarget|\\bimpl\\b|\\bIMPLEMENTATION\\b)\\s*[\\[==]|onlyImpl|allowListed\\['}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — delegatecall-user-supplied-target: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
