"""
r94-loop-dvn-admin-role-grant-no-timelock-delay — generated from reference/patterns.dsl/r94-loop-dvn-admin-role-grant-no-timelock-delay.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-dvn-admin-role-grant-no-timelock-delay.yaml
Source: kelp-rseth-exploit-2026-04-18-banteg-postmortem
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopDvnAdminRoleGrantNoTimelockDelay(AbstractDetector):
    ARGUMENT = "r94-loop-dvn-admin-role-grant-no-timelock-delay"
    HELP = "r94-loop-dvn-admin-role-grant-no-timelock-delay"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-dvn-admin-role-grant-no-timelock-delay.yaml"
    WIKI_TITLE = "r94-loop-dvn-admin-role-grant-no-timelock-delay"
    WIKI_DESCRIPTION = "r94-loop-dvn-admin-role-grant-no-timelock-delay"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-dvn-admin-role-grant-no-timelock-delay"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(DVN|AccessControl|Ownable|AdminRole)'}]
    _MATCH = [{'function.name_matches': '(?i)^(grantRole|addAdmin|setAdmin|addSigner|transferOwnership|delegateAdminRole)$'}, {'function.source_matches_regex': '(_grantRole\\s*\\(|roles\\s*\\[\\s*\\w*ADMIN_ROLE\\s*\\]\\s*=|admins\\.push|roleMembers\\.push|_roles\\s*\\[\\s*\\w*role\\s*\\]\\.members\\s*\\[\\s*\\w+\\s*\\]\\s*=\\s*true)'}, {'function.not_source_matches_regex': '(timelock|TimeLock|TIMELOCK|pendingAdmin|scheduledRole|queueAdminGrant|twoStepTransfer|acceptAdmin|GRANT_DELAY|require\\s*\\(\\s*block\\.timestamp\\s*>=\\s*\\w*(scheduled|pendingAdminGrantedAt|readyAt))'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r94-loop-dvn-admin-role-grant-no-timelock-delay: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
