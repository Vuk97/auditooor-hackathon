"""
sol-decimal-zero-address-token-pricing-denom — generated from reference/patterns.dsl/sol-decimal-zero-address-token-pricing-denom.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py sol-decimal-zero-address-token-pricing-denom.yaml
Source: solodit-cluster-C0255-Decimals
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SolDecimalZeroAddressTokenPricingDenom(AbstractDetector):
    ARGUMENT = "sol-decimal-zero-address-token-pricing-denom"
    HELP = "Math uses `10**decimals` without capping decimals at 18 — tokens with >18 decimals break accounting."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/sol-decimal-zero-address-token-pricing-denom.yaml"
    WIKI_TITLE = "Unchecked token decimals > 18 breaks pricing denominator"
    WIKI_DESCRIPTION = "Most Solidity fixed-point pricing assumes `decimals <= 18`, making `1e18 * amount / 10**decimals` safe. Tokens like YAM-v1 (24 decimals) and historical experimental ERC20s exist with decimals > 18; when their decimals feed the denominator, `10**24` exceeds `1e18` and division yields zero, silently breaking deposit/withdraw."
    WIKI_EXPLOIT_SCENARIO = "C0255 M-19: `_handleDeposit` used `amount * 1e18 / 10**decimals`. Attacker deployed an ERC20 fork with 24 decimals, deposited 1 wei — math returned 0 shares, but state recorded the deposit. On withdrawal a different code path paid out based on amount, draining prior depositors' funds."
    WIKI_RECOMMENDATION = "Reject tokens with decimals > 18 at registration (`require(t.decimals() <= 18)`) OR normalize both sides: use `scaledAmount` computed as a ratio, not a literal exponent."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'decimals|IERC20Metadata|IERC20|decimalOffset'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': 'decimals\\s*\\(\\s*\\)|_decimals|\\.decimals\\s*\\('}, {'function.body_contains_regex': '10\\s*\\*\\*\\s*(decimals|_decimals|[a-zA-Z_]+Decimals)'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*decimals\\s*<=\\s*18\\s*\\)|require\\s*\\(\\s*[a-zA-Z_]+Decimals\\s*<=\\s*18'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — sol-decimal-zero-address-token-pricing-denom: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
