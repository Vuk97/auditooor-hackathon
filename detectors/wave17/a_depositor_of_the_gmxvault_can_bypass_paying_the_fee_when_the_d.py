"""
a-depositor-of-the-gmxvault-can-bypass-paying-the-fee-when-the-d — generated from reference/patterns.dsl/a-depositor-of-the-gmxvault-can-bypass-paying-the-fee-when-the-d.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-depositor-of-the-gmxvault-can-bypass-paying-the-fee-when-the-d.yaml
Source: Codehawks/SteadeFi-Solodit-27641
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ADepositorOfTheGmxvaultCanBypassPayingTheFeeWhenTheD(AbstractDetector):
    ARGUMENT = "a-depositor-of-the-gmxvault-can-bypass-paying-the-fee-when-the-d"
    HELP = "A depositor of the GMXVault can bypass paying the fee when the depositor deposit into the GMXVault."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-depositor-of-the-gmxvault-can-bypass-paying-the-fee-when-the-d.yaml"
    WIKI_TITLE = "A depositor of the GMXVault can bypass paying the fee when the depositor deposit into the GMXVault."
    WIKI_DESCRIPTION = "### Relevant GitHub Links\n<a data-meta=\"codehawks-github-link\" href=\"https://github.com/Cyfrin/2023-10-SteadeFi/blob/main/contracts/strategy/gmx/GMXDeposit.sol#L119\">https://github.com/Cyfrin/2023-10-SteadeFi/blob/main/contracts/strategy/gmx/GMXDeposit.sol#L119</a>\n\n<a data-meta=\"codehawks-github-link\" href=\"https://github.com/Cyfrin/2023-10-SteadeFi/blob/main/contracts/strategy/gmx/GMXD"
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #27641: ### Relevant GitHub Links\n<a data-meta=\"codehawks-github-link\" href=\"https://github.com/Cyfrin/2023-10-SteadeFi/blob/main/contracts/strategy/gmx/GMXDeposit.sol#L119\">https://github.com/Cyfrin/2023-10-SteadeFi/blob/main/contracts/strategy/gmx/GMXDeposit.sol#L119</a>"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches': '.*(mintFee|deposit).*'}, {'function.not_leaf_helper': True}, {'function.reads_state_var_matching': '.*(deposit|mintFee).*'}, {'function.does_not_call_matching': '.*(accrue|update|sync|validate|check|refresh).*'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — a-depositor-of-the-gmxvault-can-bypass-paying-the-fee-when-the-d: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
