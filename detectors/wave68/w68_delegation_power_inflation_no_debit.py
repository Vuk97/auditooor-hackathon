"""
w68-delegation-power-inflation-no-debit — generated from reference/patterns.dsl/w68-delegation-power-inflation-no-debit.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py w68-delegation-power-inflation-no-debit.yaml
Source: W6-8 zero-coverage detector batch (auditooor capability lift)
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class W68DelegationPowerInflationNoDebit(AbstractDetector):
    ARGUMENT = "w68-delegation-power-inflation-no-debit"
    HELP = "Governance delegation power inflated by double-counting because delegate adds power without debiting the prior delegate"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/w68-delegation-power-inflation-no-debit.yaml"
    WIKI_TITLE = "Governance delegation power inflated by double-counting"
    WIKI_DESCRIPTION = "The delegate function credits the new delegatee but never debits the prior delegate, so repeated re-delegation inflates total delegation power."
    WIKI_EXPLOIT_SCENARIO = "Governance delegation power inflated by double-counting because delegate adds power without debiting the prior delegate"
    WIKI_RECOMMENDATION = "Debit the previous delegate before crediting the new delegatee."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches': '.*delegate.*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.body_contains_regex': '(?i)delegationPower\\s*\\[[^\\]]+\\]\\s*\\+='}, {'function.body_not_contains_regex': '(?i)delegationPower\\s*\\[[^\\]]+\\]\\s*-='}]

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
                info = [f, f" — w68-delegation-power-inflation-no-debit: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
