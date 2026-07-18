"""
a-broken-hook-can-block-user-funds — generated from reference/patterns.dsl/a-broken-hook-can-block-user-funds.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-broken-hook-can-block-user-funds.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ABrokenHookCanBlockUserFunds(AbstractDetector):
    ARGUMENT = "a-broken-hook-can-block-user-funds"
    HELP = "A broken hook can block user funds"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-broken-hook-can-block-user-funds.yaml"
    WIKI_TITLE = "A broken hook can block user funds"
    WIKI_DESCRIPTION = "For closing position, a user should call the `burn` function which uses hooks to external contract https://github.com/cryptoalgebra/Algebra/blob/6c22b64977e0b0266aec89470480df74977eb606/src/core/contracts/AlgebraPool.sol#L137. If a hook were broken, then users would not be able to"
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #27789: For closing position, a user should call the `burn` function which uses hooks to external contract https://github.com/cryptoalgebra/Algebra/blob/6c22b64977e0b0266aec89470480df74977eb"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.has_state_var_matching': '(?i).*(pendingBurn|burnable|burnLiquidity|burnShares).*'}]
    _MATCH = [{'function.name_matches': '(?i).*(burn).*'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.is_mutating': True}, {'function.reads_state_var_matching': '(?i).*(pendingBurn|burnable|burnLiquidity|burnShares).*'}, {'function.has_high_level_call_named': '(?i).*(beforeBurn|afterBurn|onBurn|burnHook).*'}, {'function.does_not_call_matching': '(?i).*(accrue|update|sync|validate|check|refresh).*'}]

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
                info = [f, f" — a-broken-hook-can-block-user-funds: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
