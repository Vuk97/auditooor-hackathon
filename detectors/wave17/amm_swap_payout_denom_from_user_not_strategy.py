"""
amm-swap-payout-denom-from-user-not-strategy — generated from reference/patterns.dsl/amm-swap-payout-denom-from-user-not-strategy.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py amm-swap-payout-denom-from-user-not-strategy.yaml
Source: auditooor-R76-c4-rujira-bug-bounty-3
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AmmSwapPayoutDenomFromUserNotStrategy(AbstractDetector):
    ARGUMENT = "amm-swap-payout-denom-from-user-not-strategy"
    HELP = "User supplies `min_return: Coin` (amount + denom) that is paid directly via BankMsg::Send. Strategy validates only amount, not denom — attacker requests wrong denom and drains that reserve."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/amm-swap-payout-denom-from-user-not-strategy.yaml"
    WIKI_TITLE = "AMM swap payout uses caller-supplied denom directly → pick-any-token drain"
    WIKI_DESCRIPTION = "The Swap entrypoint accepts `min_return: Coin` (which combines an amount and a denom) and both passes the amount into `strategy.validate_swap()` AND forwards the entire Coin into `BankMsg::Send { amount: vec![min_return] }` as the user's payout. The strategy validates the NUMERIC amount but never enforces that `min_return.denom` corresponds to the strategy's output (counter-asset) for the offered "
    WIKI_EXPLOIT_SCENARIO = "Pool seeded with 10M RUJI and 10M USDC. Attacker offers 5M USDC, requests `min_return: coin(4_970_149_254, 'usdc')` (intentionally USDC, not RUJI). Strategy returns `expected_return ≈ 4.97M` against the numeric target — denom is never inspected. Contract sends 4.97M USDC to attacker from its USDC reserves; RUJI reserve unchanged. Attacker profit = attacker payout - attacker offer, drained entirely"
    WIKI_RECOMMENDATION = "Derive the payout denom inside the handler from the strategy's known counter-asset — e.g. `let out_denom = config.denoms.ask(side_of(offer.denom));` — and construct the `BankMsg::Send` with `(out_denom, amount)`. Ignore any denom in the user-supplied min_return; use only its amount as a lower bound."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)\\.rs$|contract\\.rs|swap|amm'}, {'contract.has_function_matching': '(?i)execute.*Swap|swap|do_swap'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)swap|execute_swap|do_swap|handle_swap'}, {'function.body_contains_regex': '(?i)min_return\\s*:\\s*Coin|min_return\\s*:\\s*Uint128,\\s*\\w+\\s*:\\s*String'}, {'function.body_contains_regex': '(?i)BankMsg::Send\\s*\\{[^}]*amount\\s*:\\s*vec!\\[\\s*min_return|amount\\s*:\\s*vec!\\[min_return'}, {'function.body_not_contains_regex': '(?i)ensure_eq!\\s*\\(\\s*min_return\\.denom\\s*,|strategy\\.counter_asset|denom_out\\s*==|derive_payout_denom|config\\.denoms\\.ask'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — amm-swap-payout-denom-from-user-not-strategy: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
