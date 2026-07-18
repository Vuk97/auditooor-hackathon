"""
w68-selector-registration-bypass-no-auth - generated from reference/patterns.dsl/w68-selector-registration-bypass-no-auth.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py w68-selector-registration-bypass-no-auth.yaml
Source: W6-8 zero-coverage detector batch (auditooor capability lift)
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class W68SelectorRegistrationBypassNoAuth(AbstractDetector):
    ARGUMENT = "w68-selector-registration-bypass-no-auth"
    HELP = "Selector, module, action, or wrapper registry allows unintended target binding - registration lacks an authority / allowlist / wrapper-enforcement check, or is gated by a non-authoritative registrar"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/w68-selector-registration-bypass-no-auth.yaml"
    WIKI_TITLE = "Selector, module, action, or wrapper registry allows unintended target binding"
    WIKI_DESCRIPTION = "The selector-to-target, selector-to-module, selector-to-action, or selector-to-wrapper registry can be written by an untrusted caller or by a registrar check that is not the authoritative owner/admin/allowlist gate, letting an attacker bind a function selector to a malicious implementation, module, action handler, or wrapper."
    WIKI_EXPLOIT_SCENARIO = "Selector, module, action, or wrapper registry allows unintended target binding - registration lacks an authority / allowlist / wrapper-enforcement check, or is gated by a non-authoritative registrar"
    WIKI_RECOMMENDATION = "Gate selector, module, action, and wrapper binding behind an owner/admin/allowlist check. If a registrar indirection exists, verify that the registrar is authoritative and cannot be caller-controlled, and keep wrapper-enforcement load-bearing so untrusted callers cannot route execution to attacker-c"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches': '(?i).*(register|add|set|enable|route|bind|execute|install|update|swap).*(selector|target|module|action|wrapper|implementation|handler|facet|plugin|router|executor|hook|registrar|registration).*|.*(selector|target|module|action|wrapper|implementation|handler|facet|plugin|router|executor|hook|registrar|registration).*(register|add|set|enable|route|bind|execute|install|update|swap).*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.writes_state_var_matching_regex': '(?i)(selector|target|module|action|wrapper|implementation|handler|facet|plugin|router|executor|hook|registration|registrar)'}, {'function.body_not_contains_regex': '(?i)(onlyOwner|onlyAdmin|onlyGovernance|onlyRoles?\\(|onlyAuthorized|onlyTimelock|onlyHost|onlyGovernor|onlyKeeper|onlyManager|onlyOperator|onlyConfigurator|auth|restricted|whitelist|allowlist|approved|isAllowed|trusted|authorized|require\\s*\\(\\s*msg\\.sender\\s*==\\s*(owner|admin|governance|authority|controller|manager|operator|configurator|guardian|governor|timelock|safe|self|auth))'}]

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
                info = [f, f" - w68-selector-registration-bypass-no-auth: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
