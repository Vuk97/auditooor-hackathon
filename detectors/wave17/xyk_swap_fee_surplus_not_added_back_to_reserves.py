"""
xyk-swap-fee-surplus-not-added-back-to-reserves — generated from reference/patterns.dsl/xyk-swap-fee-surplus-not-added-back-to-reserves.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py xyk-swap-fee-surplus-not-added-back-to-reserves.yaml
Source: auditooor-R76-c4-rujira-bug-bounty-25
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class XykSwapFeeSurplusNotAddedBackToReserves(AbstractDetector):
    ARGUMENT = "xyk-swap-fee-surplus-not-added-back-to-reserves"
    HELP = "XYK swap decrements reserves by the full gross return but only sends min_return to user. Fee+surplus tokens are stranded in the contract — LP withdraw reads state.y and can never claim them."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/xyk-swap-fee-surplus-not-added-back-to-reserves.yaml"
    WIKI_TITLE = "XYK AMM strands fee + surplus tokens — reserve tracker decremented by gross, only min_return sent"
    WIKI_DESCRIPTION = "A constant-product AMM computes `gross = state.swap(offer)` and decrements `state.y -= gross` in one shot. The contract then pays the user `min_return` (set by the user; typically `< gross`) and the difference (`fee_amount + surplus`) is merely emitted in an event and abandoned in the contract balance. Because LP withdrawals compute the withdrawer's share from `state.y`, the stranded dust is never"
    WIKI_EXPLOIT_SCENARIO = "Pool 1M/1M, fee 1%. User swaps 100k USDC → gross = 90,909. fee = 909, surplus = 1001. Only `min_return = 89,000` is sent. state.y drops to 909,091, but the contract balance is 911,000 — 1,910 tokens stranded. After 50 such swaps, ~100k tokens are frozen. No admin rescue function exists."
    WIKI_RECOMMENDATION = "After computing fee and surplus, either (a) `state.y += fee_amount` so LPs get the fees, or (b) include a `BankMsg::Send { to: fee_address, ... }` for the fee+surplus, or (c) return surplus to the user (increase the effective `min_return` to `gross - fee`). Add a protocol-invariant test: `contract.b"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)\\.rs$|xyk|constant_product|amm|swapper'}, {'contract.has_state_var_matching': '(?i)state\\.y|state\\.x|reserves?_y|pool_state'}]
    _MATCH = [{'function.kind': 'internal_or_public'}, {'function.name_matches': '(?i)swap|validate_swap|execute_swap|do_swap'}, {'function.body_contains_regex': '(?i)state\\.swap\\s*\\(|state\\.y\\s*-=|self\\.y\\s*=\\s*self\\.y\\s*-'}, {'function.body_contains_regex': '(?i)fee_amount|fee\\s*=\\s*[\\w\\.]+\\.multiply_ratio|surplus'}, {'function.body_not_contains_regex': '(?i)state\\.y\\s*\\+?=\\s*fee|state\\.y\\.add\\(fee|BankMsg::Send.*fee_address|transfer.*fee_address'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — xyk-swap-fee-surplus-not-added-back-to-reserves: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
