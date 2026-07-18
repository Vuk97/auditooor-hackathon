"""
freeze-control-unguarded-state-flip - generated from reference/patterns.dsl/freeze-control-unguarded-state-flip.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py freeze-control-unguarded-state-flip.yaml
Source: auditooor-capability-lift-2026-06-02
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FreezeControlUnguardedStateFlip(AbstractDetector):
    ARGUMENT = "freeze-control-unguarded-state-flip"
    HELP = "Public freeze, pause, halt, or blocklist control path writes a protocol safety flag without an authorization gate"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/freeze-control-unguarded-state-flip.yaml"
    WIKI_TITLE = "Unguarded freeze control state flip"
    WIKI_DESCRIPTION = "Any caller can flip a protocol safety flag such as frozen, paused, halted, disabled, blacklist, or blocklist state because the setter writes the control flag without an authorization modifier or inline caller check."
    WIKI_EXPLOIT_SCENARIO = "An attacker calls an unguarded freeze or blocklist control function and sets the safety flag to a state that freezes users, bypasses intended emergency governance, or disables a transfer path."
    WIKI_RECOMMENDATION = "Gate every freeze, pause, halt, disabled, blacklist, and blocklist setter behind the protocol owner, admin, role, or governance authority and add a negative test with a non-admin caller."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(freeze|frozen|pause|paused|halt|emergency|blacklist|blocklist|blocked|disabled|lock)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i).*(freeze|pause|halt|emergency|blacklist|blocklist|block|disable|lock).*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.writes_state_var_matching_regex': '(?i)(freeze|frozen|pause|paused|halt|halted|emergency|blacklist|blocklist|blocked|disabled|locked)'}, {'function.body_contains_regex': '(?i)(freeze|frozen|pause|paused|halt|halted|emergency|blacklist|blocklist|blocked|disabled|locked)\\w*(\\[[^\\]]+\\])?\\s*='}, {'function.not_modifiers_match': '(?i)(onlyOwner|onlyAdmin|onlyRole|onlyGovernance|requiresAuth|auth|ownerOnly|adminOnly|governanceOnly)'}, {'function.body_not_contains_regex': '(?i)(require\\s*\\(\\s*(msg\\.sender|_msgSender\\(\\)|tx\\.origin)\\s*==|if\\s*\\(\\s*(msg\\.sender|_msgSender\\(\\)|tx\\.origin)\\s*!=|hasRole\\s*\\(|_checkRole\\s*\\(|OwnableUnauthorizedAccount|AccessControlUnauthorizedAccount)'}]

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
                info = [f, f" - freeze-control-unguarded-state-flip: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
