"""
a-malicious-dao-can-prevent-deter-token-holders-from-executing-j — generated from reference/patterns.dsl/a-malicious-dao-can-prevent-deter-token-holders-from-executing-j.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-malicious-dao-can-prevent-deter-token-holders-from-executing-j.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AMaliciousDaoCanPreventDeterTokenHoldersFromExecutingJ(AbstractDetector):
    ARGUMENT = "a-malicious-dao-can-prevent-deter-token-holders-from-executing-j"
    HELP = "A malicious DAO can prevent/deter token holders from executing/joining a fork by including arbitrary addresses in erc20TokensToIncludeInFork"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-malicious-dao-can-prevent-deter-token-holders-from-executing-j.yaml"
    WIKI_TITLE = "A malicious DAO can prevent/deter token holders from executing/joining a fork by including arbitrary addresses in erc20TokensToIncludeInFork"
    WIKI_DESCRIPTION = "## Severity: Medium Risk\n\n## Context\nNounsDAOV3Fork.sol#L224-L228\n\n## Description\nAs motivated in the fork spec, forking is a minority protection mechanism that should always allow a group of minority token holders to exit together into a new instance of Nouns DAO. However, a malicious majority in t"
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #21336: ## Severity: Medium Risk\n\n## Context\nNounsDAOV3Fork.sol#L224-L228\n\n## Description\nAs motivated in the fork spec, forking is a minority protection mechanism that should always allow a group of minority"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches': '.*(erc20TokensToIncludeInFork|balanceOf|transfer).*'}, {'function.not_leaf_helper': True}, {'function.reads_state_var_matching': '.*(balanceOf|erc20TokensToIncludeInFork|transfer).*'}, {'function.does_not_call_matching': '.*(accrue|update|sync|validate|check|refresh).*'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — a-malicious-dao-can-prevent-deter-token-holders-from-executing-j: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
