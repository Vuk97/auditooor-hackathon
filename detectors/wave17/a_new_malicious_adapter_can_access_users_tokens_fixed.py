"""
a-new-malicious-adapter-can-access-users-tokens-fixed — generated from reference/patterns.dsl/a-new-malicious-adapter-can-access-users-tokens-fixed.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-new-malicious-adapter-can-access-users-tokens-fixed.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ANewMaliciousAdapterCanAccessUsersTokensFixed(AbstractDetector):
    ARGUMENT = "a-new-malicious-adapter-can-access-users-tokens-fixed"
    HELP = "A new malicious adapter can access users' tokens — Fixed"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-new-malicious-adapter-can-access-users-tokens-fixed.yaml"
    WIKI_TITLE = "A new malicious adapter can access users' tokens ✓ Fixed"
    WIKI_DESCRIPTION = "#### Resolution\n\n\n\nThis is fixed in [ConsenSys/[email protected]`8de01f6`](https://github.com/ConsenSys/metaswap-contracts/commit/8de01f6f217ac544632f2af4b5569688fd2938e2).\n\n\n#### Description\n\n\nThe purpose of the `MetaSwap` contract is to save users gas costs when dealing with a number of different"
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #16406: #### Resolution\n\n\n\nThis is fixed in [ConsenSys/[email protected]`8de01f6`](https://github.com/ConsenSys/metaswap-contracts/commit/8de01f6f217ac544632f2af4b5569688fd2938e2).\n\n\n#### Description\n\n\nThe pu"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches_regex': '.*(MetaSwap|approve|Spender|DELEGATECALL).*'}, {'function.not_leaf_helper': True}, {'function.reads_state_var_matching_regex': '.*(approve).*'}, {'function.does_not_call_matching_regex': '.*(accrue|update|sync|validate|check|refresh).*'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — a-new-malicious-adapter-can-access-users-tokens-fixed: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
