"""
a-malicious-owner-or-user-with-a-role-router-role-can-drain-a-ro — generated from reference/patterns.dsl/a-malicious-owner-or-user-with-a-role-router-role-can-drain-a-ro.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-malicious-owner-or-user-with-a-role-router-role-can-drain-a-ro.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AMaliciousOwnerOrUserWithARoleRouterRoleCanDrainARo(AbstractDetector):
    ARGUMENT = "a-malicious-owner-or-user-with-a-role-router-role-can-drain-a-ro"
    HELP = "A malicious owner or user with a Role.Router role can drain a router's liquidity"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-malicious-owner-or-user-with-a-role-router-role-can-drain-a-ro.yaml"
    WIKI_TITLE = "A malicious owner or user with a Role.Router role can drain a router 's liquidity"
    WIKI_DESCRIPTION = "## Security Report\n\n## Severity: High Risk\n\n### Context\n- `RoutersFacet.sol#L263-L267`\n- `RoutersFacet.sol#L297`\n- `RoutersFacet.sol#L498`\n- `BridgeFacet.sol#L622`\n\n### Description\nA malicious owner or user with the `Role.Router` role (denominated as A in this example) can drain a router's liquidity"
    WIKI_EXPLOIT_SCENARIO = "A malicious owner or user with a Role.Router role can drain a router's liquidity"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches': '.*(removeRouter|setupRouter|removeRouterLiquidityFor|addRouter).*'}, {'function.not_leaf_helper': True}, {'function.reads_state_var_matching': '.*(addRouter|addRouterLiquidity|addRouterLiquidityFor).*'}, {'function.does_not_call_matching': '.*(accrue|update|sync|validate|check|refresh).*'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — a-malicious-owner-or-user-with-a-role-router-role-can-drain-a-ro: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
