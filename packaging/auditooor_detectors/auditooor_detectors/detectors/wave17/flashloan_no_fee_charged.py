"""
flashloan-no-fee-charged — generated from reference/patterns.dsl/flashloan-no-fee-charged.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py flashloan-no-fee-charged.yaml
Source: solodit-cluster/flashloan-fee-omitted
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FlashloanNoFeeCharged(AbstractDetector):
    ARGUMENT = "flashloan-no-fee-charged"
    HELP = "Flashloan entry (flashLoan / flashBorrow / executeFlashLoan / flash / _flashLoan) sends principal outbound via safeTransfer / transfer / _transferToReceiver / _sendFunds but contains no fee-charging idiom (feeBps / flashFee / _calculateFee / fee = / fee * / amount + fee / premium / flashloanPremium)"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/flashloan-no-fee-charged.yaml"
    WIKI_TITLE = "Flashloan sends principal but charges no fee"
    WIKI_DESCRIPTION = "The flashloan entry point transfers the loaned principal to the borrower and pulls it back but never references a fee, premium, or fee accessor in its body. An attacker can borrow arbitrarily large principal, execute MEV / arbitrage / liquidation / price-manipulation strategies that are ordinarily uneconomic at the protocol's advertised fee rate, and repay the loan 1:1 at zero cost. Unlike the bro"
    WIKI_EXPLOIT_SCENARIO = "A vault exposes `flashLoan(uint256 amount)` that calls `IERC20(token).safeTransfer(msg.sender, amount);` then invokes a borrower callback and finally pulls back `amount` via `safeTransferFrom`. No fee is computed, accrued, or required. Attacker borrows the vault's entire liquidity, runs an arb across a decorrelated pool, and repays exactly `amount`. The vault earns nothing; the attacker keeps the "
    WIKI_RECOMMENDATION = "At the top of every flashloan entry, bind `uint256 fee = _calculateFee(amount);` (or reference the appropriate fee state variable / accessor) and require the repayment to cover `amount + fee`. Enforce `fee > 0` when `amount > 0` to block round-to-zero truncation. Propagate the fee explicitly to the "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(flashLoan|flashBorrow|executeFlashLoan|flash|_flashLoan)$'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': 'safeTransfer\\s*\\(|\\.transfer\\s*\\(|_transferToReceiver|_sendFunds'}, {'function.body_not_contains_regex': 'feeBps|flashFee|_calculateFee|fee\\s*=\\s*|fee\\s*\\*|amount\\s*\\+\\s*\\w*fee|premium|flashloanPremium'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — flashloan-no-fee-charged: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
