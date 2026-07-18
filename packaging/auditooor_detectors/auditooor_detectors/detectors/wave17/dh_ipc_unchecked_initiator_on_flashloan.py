"""
dh-ipc-unchecked-initiator-on-flashloan — generated from reference/patterns.dsl/dh-ipc-unchecked-initiator-on-flashloan.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py dh-ipc-unchecked-initiator-on-flashloan.yaml
Source: defihacklabs/IPC-2025-01+Unilend-2025-01
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DhIpcUncheckedInitiatorOnFlashloan(AbstractDetector):
    ARGUMENT = "dh-ipc-unchecked-initiator-on-flashloan"
    HELP = "Flashloan callback reads `initiator`/`sender` but does not require it equals `address(this)`."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/dh-ipc-unchecked-initiator-on-flashloan.yaml"
    WIKI_TITLE = "Flashloan callback missing initiator == address(this) check"
    WIKI_DESCRIPTION = "Aave/Balancer/Uniswap flashloan callbacks can be invoked by anyone via the public lending pool. A receiver that doesn't verify `initiator == address(this)` will execute its user-data-driven logic for any attacker that calls the pool with this contract as receiver."
    WIKI_EXPLOIT_SCENARIO = "IPC 2025-01, Unilend 2025-01, DoughFina 2024-07: receiver's `executeOperation` proceeded to swap/repay based on decoded `params` without asserting it had initiated the loan. Attacker called Aave pool directly requesting the receiver as beneficiary with crafted params, triggering unintended repayments/swaps using the victim's collateral."
    WIKI_RECOMMENDATION = "Add `require(initiator == address(this), \"unexpected initiator\")` and also `require(msg.sender == address(pool))` at the top of every flashloan callback."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'IFlashLoanReceiver|executeOperation|onFlashLoan|receiveFlashLoan|flashCallback'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(executeOperation|onFlashLoan|receiveFlashLoan|flashCallback|uniswapV3FlashCallback|pancakeV3FlashCallback)$'}, {'function.body_contains_regex': 'initiator|sender'}, {'function.body_not_contains_regex': 'initiator\\s*==\\s*address\\s*\\(\\s*this|require\\s*\\([^)]*initiator'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — dh-ipc-unchecked-initiator-on-flashloan: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
