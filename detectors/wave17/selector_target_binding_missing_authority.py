"""
selector-target-binding-missing-authority - generated from reference/patterns.dsl/selector-target-binding-missing-authority.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py selector-target-binding-missing-authority.yaml
Source: auditooor capability lift 2026-06-02 sibling generalizer
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SelectorTargetBindingMissingAuthority(AbstractDetector):
    ARGUMENT = "selector-target-binding-missing-authority"
    HELP = "Selector, target, module, handler, wrapper, or action binding writes a dispatch registry without owner, role, allowlist, or timelock authority."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/selector-target-binding-missing-authority.yaml"
    WIKI_TITLE = "Selector target binding missing authority"
    WIKI_DESCRIPTION = "A public registry writer lets an untrusted caller bind a selector or action key to a target implementation, handler, module, wrapper, or plugin without an authoritative owner, role, allowlist, or timelock check."
    WIKI_EXPLOIT_SCENARIO = "Selector, target, module, handler, wrapper, or action binding writes a dispatch registry without owner, role, allowlist, or timelock authority."
    WIKI_RECOMMENDATION = "Gate registry writes with the protocol authority and keep the selector key, target address, and wrapper or module relationship inside the authorized update path."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(selector|target|module|handler|facet|plugin|router|wrapper|implementation|registrar|action)'}, {'contract.has_state_var_matching': '(?i)(selector|target|module|handler|facet|plugin|router|wrapper|implementation|registrar|action)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i).*(set|add|enable|register|route|bind|install|update).*(selector|target|module|handler|facet|plugin|router|wrapper|implementation|action).*|.*(selector|target|module|handler|facet|plugin|router|wrapper|implementation|action).*(set|add|enable|register|route|bind|install|update).*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.writes_state_var_matching_regex': '(?i)(selector|target|module|handler|facet|plugin|router|wrapper|implementation|registrar|action)'}, {'function.body_contains_regex': '(?i)\\[[^\\]]*(selector|msg\\.sig|bytes4)[^\\]]*\\]\\s*=\\s*(target|module|handler|facet|plugin|router|wrapper|implementation|action)'}, {'function.not_modifiers_match': '(?i)(onlyOwner|onlyAdmin|onlyRole|onlyGovernance|onlyAuthorized|requiresAuth|auth|ownerOnly|adminOnly|governanceOnly|onlyTimelock|onlyManager|onlyOperator)'}, {'function.body_not_contains_regex': '(?i)(require\\s*\\(\\s*(msg\\.sender|_msgSender\\(\\))\\s*==|hasRole\\s*\\(|_checkRole\\s*\\(|isAllowed|isAuthorized|trusted|allowlist|whitelist|OwnableUnauthorizedAccount|AccessControlUnauthorizedAccount)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" - selector-target-binding-missing-authority: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
