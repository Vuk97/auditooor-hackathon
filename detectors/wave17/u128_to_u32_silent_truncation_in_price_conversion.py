"""
u128-to-u32-silent-truncation-in-price-conversion — generated from reference/patterns.dsl/u128-to-u32-silent-truncation-in-price-conversion.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py u128-to-u32-silent-truncation-in-price-conversion.yaml
Source: auditooor-R76-c4-gmtrade-bug-bounty-31
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class U128ToU32SilentTruncationInPriceConversion(AbstractDetector):
    ARGUMENT = "u128-to-u32-silent-truncation-in-price-conversion"
    HELP = "Decimal::try_from_price computes scaled value as u128 but casts to u32 via `as u32` — silent truncation on any asset above ~$42k, enabling massive mispricing and LP drain."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/u128-to-u32-silent-truncation-in-price-conversion.yaml"
    WIKI_TITLE = "u128 → u32 silent truncation in Decimal::try_from_price → 70%+ undervaluation of high-price assets"
    WIKI_DESCRIPTION = "A Decimal struct stores the scaled price as `value: u32` but the conversion helper computes the pre-cast value as `u128`. The final assignment uses `value as u32`, which silently drops the high 96 bits. For BTC at $60k and precision 8, the true scaled value is 6e12 (43 bits); truncation yields ~1.7e9, representing ~$17k. Pool accounting, LP share redemption, and liquidation thresholds are all comp"
    WIKI_EXPLOIT_SCENARIO = "Pool holds 10 fBTC (fair value $600k). Oracle returns 60_000 * 1e8 = 6e12. Conversion casts to u32 → 1,705,033,728 / 1e5 = ~$17k effective price. Attacker deposits 1 fBTC; contract believes they added $17k of equity. Attacker redeems all shares; share math using truncated price gives them ~3.5 fBTC back. Stolen: 2.5 fBTC from LPs in a single deposit/withdraw cycle. Arbitrage is front-runnable via "
    WIKI_RECOMMENDATION = "Replace `value as u32` with `value.try_into().map_err(|_| DecimalError::Overflow)?`. Preferably widen the storage field to `u64` or `u128`; `u32` only supports ~$42k at 5-decimal precision and ~$17k at 8-decimal precision — both clearly insufficient for modern crypto assets. Add a range-check on eve"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)\\.rs$|price|decimal|oracle'}, {'contract.has_function_matching': '(?i)try_from_price|from_price|to_decimal|price_to_internal'}]
    _MATCH = [{'function.kind': 'public_or_internal'}, {'function.name_matches': '(?i)try_from_price|from_price|to_decimal|convert_price|price_to_|normalize_price'}, {'function.body_contains_regex': '(?i)as\\s+u32|as\\s+u16|as\\s+u64'}, {'function.body_contains_regex': '(?i)Decimal\\s*\\{|value\\s*:\\s*.*as\\s+u(32|16|8)'}, {'function.body_not_contains_regex': '(?i)\\.try_into\\(\\)|TryInto|DecimalError::Overflow|value\\.checked_.*\\bas\\b|u32::try_from'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — u128-to-u32-silent-truncation-in-price-conversion: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
