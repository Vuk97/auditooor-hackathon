"""
role-grant-divergence — generated from reference/patterns.dsl/role-grant-divergence.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py role-grant-divergence.yaml
Source: polymarket/OFF.A
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RoleGrantDivergence(AbstractDetector):
    ARGUMENT = "role-grant-divergence"
    HELP = "Functions gated by role modifiers whose required role may not be granted at deploy time to the expected caller. Flags the P1 pattern from the auditooor bug_patterns_observed.md catalog — first observed as Polymarket #OFF.A (High, submitted)."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/role-grant-divergence.yaml"
    WIKI_TITLE = "Deployment-state role-grant divergence"
    WIKI_DESCRIPTION = "The role-based access control pattern requires that deployment scripts grant the correct roles to the correct addresses. Audits typically pass because the test fixture grants the role; production deployments can miss the grant entirely, causing every call to revert."
    WIKI_EXPLOIT_SCENARIO = "Functions gated by role modifiers whose required role may not be granted at deploy time to the expected caller. Flags the P1 pattern from the auditooor bug_patterns_observed.md catalog — first observed as Polymarket #OFF.A (High, submitted)."
    WIKI_RECOMMENDATION = "1. Enumerate every role-gated function in production contracts.\n2. For each role, enumerate every contract address that should hold the role.\n3. Verify the deploy script grants the role to EVERY expected holder.\n4. Add a post-deploy assertion: `require(hasRole(role, expected_holder), ...)` in the"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_modifier': {'includes': ['onlyRoles', 'onlyRole', 'hasRole', 'onlyOwner', 'onlyAdmin', 'onlyOperator', 'onlyManager', 'onlyWrapper', 'onlyMinter', 'onlyBurner']}}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — role-grant-divergence: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
