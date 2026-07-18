"""
a-linear-increase-in-the-withdrawal-wait-time-for-lido-for-reque — generated from reference/patterns.dsl/a-linear-increase-in-the-withdrawal-wait-time-for-lido-for-reque.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-linear-increase-in-the-withdrawal-wait-time-for-lido-for-reque.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ALinearIncreaseInTheWithdrawalWaitTimeForLidoForReque(AbstractDetector):
    ARGUMENT = "a-linear-increase-in-the-withdrawal-wait-time-for-lido-for-reque"
    HELP = "A linear increase in the withdrawal wait time for Lido for requests exceeding 500 ETH"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-linear-increase-in-the-withdrawal-wait-time-for-lido-for-reque.yaml"
    WIKI_TITLE = "A linear increase in the withdrawal wait time for Lido for requests exceeding 500 ETH"
    WIKI_DESCRIPTION = "The current implementation of Lido withdrawals in the `StEtherAdapter` contract exhibits a scalability issue. Withdrawal requests exceeding 500 ETH through the `StEtherAdapter` contract are forcibly trimmed to 500 ETH. Additionally, the `BaseLSTAdapter` design only processes a sing"
    WIKI_EXPLOIT_SCENARIO = "A linear increase in the withdrawal wait time for Lido for requests exceeding 500 ETH"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i).*(StEtherAdapter|BaseLSTAdapter).*'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(?i).*(StEtherAdapter|BaseLSTAdapter).*'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.reads_state_var_matching': '(?i).*(balance|amount|total|supply|reserve).*'}, {'function.does_not_call_matching': '(?i).*(accrue|update|sync|validate|check|refresh).*'}]

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
                info = [f, f" — a-linear-increase-in-the-withdrawal-wait-time-for-lido-for-reque: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
