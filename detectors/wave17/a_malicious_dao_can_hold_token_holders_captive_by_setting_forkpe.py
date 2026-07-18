"""
a-malicious-dao-can-hold-token-holders-captive-by-setting-forkpe — generated from reference/patterns.dsl/a-malicious-dao-can-hold-token-holders-captive-by-setting-forkpe.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-malicious-dao-can-hold-token-holders-captive-by-setting-forkpe.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AMaliciousDaoCanHoldTokenHoldersCaptiveBySettingForkpe(AbstractDetector):
    ARGUMENT = "a-malicious-dao-can-hold-token-holders-captive-by-setting-forkpe"
    HELP = "A malicious DAO can hold token holders captive by setting forkPeriod to an unreasonably low value"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-malicious-dao-can-hold-token-holders-captive-by-setting-forkpe.yaml"
    WIKI_TITLE = "A malicious DAO can hold token holders captive by setting forkPeriod to an unreasonably low value"
    WIKI_DESCRIPTION = "## Security Advisory\n\n## Severity\n**Medium Risk**\n\n## Context\n**File:** NounsDAOV3Admin.sol  \n**Lines:** 516-L524\n\n## Description\nA malicious majority can reduce the number of Noun holders joining an executed fork by setting the `forkPeriod` to an unreasonably low value, e.g., 0, because there is no"
    WIKI_EXPLOIT_SCENARIO = "A malicious DAO can hold token holders captive by setting forkPeriod to an unreasonably low value"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches': '(?i).*(forkPeriod|MIN_FORK_PERIOD|forkThresholdBPS).*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.reads_state_var_matching': '(?i).*(forkPeriod|forkThresholdBPS).*'}, {'function.does_not_call_matching': '(?i).*(accrue|update|sync|validate|check|refresh).*'}]

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
                info = [f, f" — a-malicious-dao-can-hold-token-holders-captive-by-setting-forkpe: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
