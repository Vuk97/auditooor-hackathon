"""
refund-full-amount-on-insufficient-liquidity — generated from reference/patterns.dsl/refund-full-amount-on-insufficient-liquidity.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py refund-full-amount-on-insufficient-liquidity.yaml
Source: solodit/H-02-insufficient-liquidity-refund
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RefundFullAmountOnInsufficientLiquidity(AbstractDetector):
    ARGUMENT = "refund-full-amount-on-insufficient-liquidity"
    HELP = "On partial-fill / insufficient-liquidity paths, the swap/buy function refunds `msg.value` (the full amount the user sent) rather than `msg.value - actuallySpent`. When part of the fill succeeded, the user gets the filled output AND the full input back — net free tokens."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/refund-full-amount-on-insufficient-liquidity.yaml"
    WIKI_TITLE = "Full-amount refund on partial-fill path — double-spend vs own reserves"
    WIKI_DESCRIPTION = "When a swap/buy/fillOrder routine cannot fully consume the user's input (insufficient pool liquidity, partial order fill), the correct refund is `msg.value - actuallySpent`. A buggy flow refunds the full `msg.value` unconditionally or only in the 'insufficient liquidity' branch, leaving the user with both the partial output AND their entire native input. The protocol eats the delta from its own re"
    WIKI_EXPLOIT_SCENARIO = "User sends 10 ETH to `swap()` expecting up to 10 ETH of token X. Pool only has enough liquidity to fill 4 ETH worth. The function sells the 4 ETH, sends user 4 ETH-worth of tokens, then hits the `else` branch — 'insufficient liquidity' — and refunds `msg.value` (10 ETH) instead of `10 - 4 = 6 ETH`. User walks away with 4 ETH of tokens and 10 ETH cash. Attacker batches calls until the pool's native"
    WIKI_RECOMMENDATION = "Track the exact input actually consumed. Refund `msg.value - spent`. Never refund a stored input parameter without subtracting what you used from it. Add invariant tests: for every settled swap, `sum(refunds) + sum(spent) == sum(inputs)`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(swap|Swap|Router|AMM|Pool|OrderBook|Exchange|Vault)'}, {'contract.has_state_var_matching': 'liquidity|reserves|available|capacity'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(swap|swapExact|swapExactIn|swapExactOut|buy|sell|trade|fulfillOrder|fillOrder|execute|_execute|redeem)$'}, {'function.not_source_matches_regex': '(spent\\s*=|used\\s*=|actualIn\\s*=|consumedAmount|amountInActual|remainingRefund)'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': '\\.call\\s*\\{\\s*value\\s*:\\s*msg\\.value\\s*\\}|safeTransfer\\s*\\([^,]*,\\s*msg\\.value|transfer\\s*\\(\\s*msg\\.sender\\s*,\\s*msg\\.value'}, {'function.body_not_contains_regex': 'msg\\.value\\s*-\\s*(spent|used|filled|actual|consumed)|refund\\s*=\\s*msg\\.value\\s*-|remaining\\s*=\\s*msg\\.value\\s*-'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — refund-full-amount-on-insufficient-liquidity: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
