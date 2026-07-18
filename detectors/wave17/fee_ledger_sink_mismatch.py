"""
fee-ledger-sink-mismatch - generated from reference/patterns.dsl/fee-ledger-sink-mismatch.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fee-ledger-sink-mismatch.yaml
Source: auditooor-lane05-fee-redirect-lift-2026-06-02
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FeeLedgerSinkMismatch(AbstractDetector):
    ARGUMENT = "fee-ledger-sink-mismatch"
    HELP = "Fee logic mutates one ledger or actor while authorization/pricing still trusts another: common shapes are additive transfer fees that overrun allowance, and AMM reserve math that treats accrued protocol fees as user-owned liquidity."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fee-ledger-sink-mismatch.yaml"
    WIKI_TITLE = "Fee ledger sink mismatch across actor and accounting boundaries"
    WIKI_DESCRIPTION = "Fees are safe only when they stay inside a dedicated fee ledger and are charged to the actor who authorized the action. This shared row models two recurring Solidity shapes: additive transfer fees where `balance[from]` is debited by `amount + fee` but `allowance[from][spender]` is decremented by only `amount`, and reserve-based AMM flows where protocol fees remain inside `reserve` or `balanceOf(th"
    WIKI_EXPLOIT_SCENARIO = "Alice approves Router for 100 tokens on a fee-on-transfer token. Router calls `transferFrom` and Alice loses 101 because allowance only tracks 100. In a sibling AMM, accrued protocol fees sit inside `reserve0`; a burner exits against raw `reserve0` and captures part of the fee float as if it were LP-owned reserve. Different surfaces, same bug family: the fee was not isolated from the user ledger t"
    WIKI_RECOMMENDATION = "Keep fee deltas inside the same ledger that gates authorization and pricing. If balance is debited by `amount + fee`, allowance or signed spend cap must be debited by the same `amount + fee`. If protocol fees sit in-contract, subtract them from reserve math or move them into a dedicated accrued-fee "

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?is)(fee|tax|surcharge|accruedFee|accumulatedFee|launchpadFee|protocolFee|treasuryFee)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(transferFrom|_transferFrom|mint|burn|swap|_mint|_burn)$'}, {'function.body_contains_regex': '(?is)(?:\\b(?:uint\\d+\\s+)?\\w*(?:fee|tax|surcharge)\\w*\\s*=\\s*[^;]*\\bamount\\b[\\s\\S]{0,220}(?:_?balances?|balanceOf)\\s*\\[\\s*from\\s*\\]\\s*(?:-=|=\\s*[^;]*-)\\s*(?:\\bamount\\b\\s*\\+\\s*\\w*(?:fee|tax|surcharge)\\w*\\b|\\b(?:totalDebit|totalAmount|amountWithFee)\\b)[\\s\\S]{0,220}(?:_?allowances?|allowance)\\s*\\[\\s*from\\s*\\]\\s*\\[\\s*(?:msg\\.sender|_msgSender\\(\\))\\s*\\]\\s*(?:-=|=\\s*[^;]*-)\\s*\\bamount\\b)|(?:\\b(?:reserve0|reserve1|_reserve0|_reserve1)\\b[\\s\\S]{0,220}\\b(?:accruedFee|accumulatedFee|launchpadFee|protocolFee|treasuryFee)\\b|\\b(?:accruedFee|accumulatedFee|launchpadFee|protocolFee|treasuryFee)\\b[\\s\\S]{0,220}(?:balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)|IERC20\\s*\\(\\s*\\w+\\s*\\)\\.balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)|\\b(?:reserve0|reserve1|_reserve0|_reserve1)\\b))'}, {'function.body_not_contains_regex': '(?is)(?:_?allowances?|allowance)\\s*\\[\\s*from\\s*\\]\\s*\\[\\s*(?:msg\\.sender|_msgSender\\(\\))\\s*\\]\\s*(?:-=|=\\s*[^;]*-)\\s*(?:\\bamount\\b\\s*\\+\\s*\\w*(?:fee|tax|surcharge)\\w*\\b|\\b(?:totalDebit|totalAmount|amountWithFee)\\b)|_approve\\s*\\(\\s*from\\s*,\\s*(?:msg\\.sender|_msgSender\\(\\))\\s*,\\s*allowance\\s*\\(\\s*from\\s*,\\s*(?:msg\\.sender|_msgSender\\(\\))\\s*\\)\\s*-\\s*(?:\\bamount\\b\\s*\\+\\s*\\w*(?:fee|tax|surcharge)\\w*\\b|\\b(?:totalDebit|totalAmount|amountWithFee)\\b)\\s*\\)|(?:\\b(?:reserve0|reserve1|_reserve0|_reserve1|bal\\w*)\\s*-\\s*(?:accruedFee|accumulatedFee|launchpadFee|protocolFee|treasuryFee)\\b|\\b(?:realReserve|subFees|_subtractFee)\\b)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" - fee-ledger-sink-mismatch: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
