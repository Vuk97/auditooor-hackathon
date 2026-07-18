"""
role-grant-divergence-dsl — generated from reference/patterns.dsl/role-grant-divergence-dsl.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py role-grant-divergence-dsl.yaml
Source: polymarket/OFF.A
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RoleGrantDivergenceDsl(AbstractDetector):
    ARGUMENT = "role-grant-divergence-dsl"
    HELP = "Role-gated wrap/unwrap/mint/burn function; verify the required role is granted on mainnet to every caller."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/role-grant-divergence-dsl.yaml"
    WIKI_TITLE = "Role-gated asset-flow function: verify live-state role grant"
    WIKI_DESCRIPTION = "A function gated by a role modifier (onlyRoles / hasRole) that performs asset movement. On mainnet, the role must be granted to every expected caller. If the deploy script misses the grant, every call permanently reverts."
    WIKI_EXPLOIT_SCENARIO = "See Polymarket #OFF.A: CollateralOfframp.unwrap() is gated by WRAPPER_ROLE but the deploy script never granted it to Offramp. All unwraps revert with Unauthorized."
    WIKI_RECOMMENDATION = "Enumerate role holders via cast call + cross-reference against expected caller list."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_modifier': {'includes': ['onlyRoles', 'onlyRole', 'hasRole', 'hasAnyRole'], 'negate': False}}, {'function.name_matches': '.*(wrap|unwrap|mint|burn|convert|redeem).*'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — role-grant-divergence-dsl: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
