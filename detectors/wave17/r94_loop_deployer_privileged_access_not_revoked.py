"""
r94-loop-deployer-privileged-access-not-revoked — generated from reference/patterns.dsl/r94-loop-deployer-privileged-access-not-revoked.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-deployer-privileged-access-not-revoked.yaml
Source: loop-cycle-89-sol-sibling
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopDeployerPrivilegedAccessNotRevoked(AbstractDetector):
    ARGUMENT = "r94-loop-deployer-privileged-access-not-revoked"
    HELP = "r94-loop-deployer-privileged-access-not-revoked"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-deployer-privileged-access-not-revoked.yaml"
    WIKI_TITLE = "r94-loop-deployer-privileged-access-not-revoked"
    WIKI_DESCRIPTION = "r94-loop-deployer-privileged-access-not-revoked"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-deployer-privileged-access-not-revoked"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(constructor[\\s\\S]{0,300}?(grantRole|_setupRole)[\\s\\S]{0,100}?(DEFAULT_ADMIN_ROLE|ADMIN_ROLE)[\\s\\S]{0,100}?(msg\\.sender|deployer))'}, {'contract.not_source_matches_regex': '(revokeRole|_revokeRole|renounceRole|_renounceRole|transferAdminRole)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'contract.source_matches_regex': '(constructor|initialize)'}, {'contract.not_source_matches_regex': '(revokeRole\\s*\\(\\s*DEFAULT_ADMIN_ROLE|renounceRole\\s*\\(\\s*DEFAULT_ADMIN_ROLE|transferAdminRole)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — r94-loop-deployer-privileged-access-not-revoked: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
