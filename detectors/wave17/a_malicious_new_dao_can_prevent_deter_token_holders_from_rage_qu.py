"""
a-malicious-new-dao-can-prevent-deter-token-holders-from-rage-qu — generated from reference/patterns.dsl/a-malicious-new-dao-can-prevent-deter-token-holders-from-rage-qu.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-malicious-new-dao-can-prevent-deter-token-holders-from-rage-qu.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AMaliciousNewDaoCanPreventDeterTokenHoldersFromRageQu(AbstractDetector):
    ARGUMENT = "a-malicious-new-dao-can-prevent-deter-token-holders-from-rage-qu"
    HELP = "A malicious new DAO can prevent/deter token holders from rage quitting by including arbitrary addresses in erc20TokensToIncludeInQuit"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-malicious-new-dao-can-prevent-deter-token-holders-from-rage-qu.yaml"
    WIKI_TITLE = "A malicious new DAO can prevent/deter token holders from rage quitting by including arbitrary addresses in erc20TokensToIncludeInQuit"
    WIKI_DESCRIPTION = "## Medium Risk Vulnerability Report\n\n## Severity \n**Medium Risk**\n\n## Context \n`NounsDAOLogicV1Fork.sol#L201-L215`\n\n## Description \nAs described in the fork spec: \n\n> \"New DAOs are deployed with vanilla ragequit in place; otherwise it's possible for a new DAO majority to collude to hurt a minority,"
    WIKI_EXPLOIT_SCENARIO = "A malicious new DAO can prevent/deter token holders from rage quitting by including arbitrary addresses in erc20TokensToIncludeInQuit"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches': '.*(erc20TokensToIncludeInQuit|balanceOf|transfer).*'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.reads_state_var_matching': '.*(balanceOf|erc20TokensToIncludeInQuit|transfer).*'}, {'function.does_not_call_matching': '.*(accrue|update|sync|validate|check|refresh).*'}]

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
                info = [f, f" — a-malicious-new-dao-can-prevent-deter-token-holders-from-rage-qu: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
