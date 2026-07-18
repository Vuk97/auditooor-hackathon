"""
a-malicious-dao-can-mint-arbitrary-fork-dao-tokens — generated from reference/patterns.dsl/a-malicious-dao-can-mint-arbitrary-fork-dao-tokens.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-malicious-dao-can-mint-arbitrary-fork-dao-tokens.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AMaliciousDaoCanMintArbitraryForkDaoTokens(AbstractDetector):
    ARGUMENT = "a-malicious-dao-can-mint-arbitrary-fork-dao-tokens"
    HELP = "A malicious DAO can mint arbitrary fork DAO tokens"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-malicious-dao-can-mint-arbitrary-fork-dao-tokens.yaml"
    WIKI_TITLE = "A malicious DAO can mint arbitrary fork DAO tokens"
    WIKI_DESCRIPTION = "## Severity: Medium Risk\n\n## Context\n- NounsDAOV3Proposals.sol#L495\n- NounsDAOV3Fork.sol#L203-L205\n- NounsTokenFork.sol#L166-L174\n\n## Description\nThe original DAO is assumed to be honest during the fork period, which is reinforced in the protocol by preventing it from executing any malicious proposa"
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #21327: ## Severity: Medium Risk\n\n## Context\n- NounsDAOV3Proposals.sol#L495\n- NounsDAOV3Fork.sol#L203-L205\n- NounsTokenFork.sol#L166-L174\n\n## Description\nThe original DAO is assumed to be honest during the fo"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches_regex': '.*(claimDuringForkPeriod|forkEndTimestamp|forkingPeriodEndTimestamp|executeFork).*'}, {'function.reads_state_var_matching_regex': '.*(claimDuringForkPeriod|executeFork|forkEndTimestamp).*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.does_not_call_matching_regex': '.*(accrue|update|sync|validate|check|refresh).*'}]

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
                info = [f, f" — a-malicious-dao-can-mint-arbitrary-fork-dao-tokens: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
