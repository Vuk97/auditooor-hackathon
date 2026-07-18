"""
flashloan-fee-underflow-or-missing — generated from reference/patterns.dsl/flashloan-fee-underflow-or-missing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py flashloan-fee-underflow-or-missing.yaml
Source: solodit-cluster/C0109
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FlashloanFeeUnderflowOrMissing(AbstractDetector):
    ARGUMENT = "flashloan-fee-underflow-or-missing"
    HELP = "Flashloan entry point (flashLoan / flashBorrow / executeFlashLoan / onFlashLoan / doFlashLoan) on a contract that advertises a flash-fee knob does not charge or propagate the fee — either the fee is omitted entirely (free flashloans) or the computation rounds to zero for small principals."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/flashloan-fee-underflow-or-missing.yaml"
    WIKI_TITLE = "Flashloan fee missing or rounds to zero"
    WIKI_DESCRIPTION = "The contract exposes a flash-fee state variable (flashFee / flashloanFee / feeRate / flashLoanRate) advertising non-zero economic rent on borrowed principal, yet its flashloan entry point does not multiply by that fee, does not call the fee accessor, and does not bind a local fee variable. The effect is either free flashloans (principal returned 1:1, protocol earns nothing) or — when the intended "
    WIKI_EXPLOIT_SCENARIO = "An attacker borrows `amount` via flashLoan(amount). The entry point transfers the principal to the receiver, invokes onFlashLoan(amount, 0), and pulls back exactly `amount`. The protocol-advertised `flashFee` of 0.09% was never applied, so the attacker extracts arbitrage value at no rent cost. Variant: the fee is computed but `amount * feeRate < 1e18`, so the fee truncates to zero for each small s"
    WIKI_RECOMMENDATION = "At the top of every flashloan entry point, bind `uint256 fee = _flashFee(token, amount);` (or its equivalent accessor), enforce `fee > 0` when `amount > 0` to block round-to-zero underflow, pass the fee through to the `onFlashLoan` callback, and require the post-call balance to be at least `pre + fe"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'flashFee|flashloanFee|feeRate|flashLoanRate'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'flashLoan|flashBorrow|executeFlashLoan|_flashLoan|onFlashLoan|doFlashLoan'}, {'function.body_not_contains_regex': 'fee\\s*\\*|fee\\s*=|_flashFee|flashFee\\s*\\(|feeAmount|feeToReceive|\\*\\s*flashloanRate|\\*\\s*FEE'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — flashloan-fee-underflow-or-missing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
