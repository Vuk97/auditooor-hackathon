"""
rate-update-lag-read-compute-write-trio — generated from reference/patterns.dsl/rate-update-lag-read-compute-write-trio.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py rate-update-lag-read-compute-write-trio.yaml
Source: defihacklabs/yETH-2025-12
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RateUpdateLagReadComputeWriteTrio(AbstractDetector):
    ARGUMENT = "rate-update-lag-read-compute-write-trio"
    HELP = "LP pool reads backing rate, computes shares, then updates the rate. Order should be: update → read → compute. Stale-snapshot shares leak arbitrage."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/rate-update-lag-read-compute-write-trio.yaml"
    WIKI_TITLE = "Multi-asset LP rate-read happens before update_rates call"
    WIKI_DESCRIPTION = "Curve/yETH style pools that maintain per-asset exchange rates must refresh rates before any share calculation. When `add_liquidity` reads the current rate snapshot, computes LP shares, and then calls `update_rates`, the shares are priced against stale rates. Any asset whose rate has moved between the last `update_rates` and the current block is mispriced for deposits/withdrawals."
    WIKI_EXPLOIT_SCENARIO = "yETH 2025-12 ($9M): `add_liquidity` read `_rates[i]`, computed shares, and then called `update_rates` at the bottom. Attacker waited for a large rate move, deposited at the stale rate, received over-valued shares, withdrew after `update_rates` re-priced. Net: attacker skimmed the rate-move delta across the pool."
    WIKI_RECOMMENDATION = "Enforce the correct order: (1) `update_rates()` or equivalent, (2) read `rate`, (3) compute shares. A single defensive pattern: make `update_rates()` the first statement in every mutable pool function. Unit test: `deposit(x)` + `withdraw` with manipulated rate must not net positive."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'update_rates|updateRate|rate_read|multiAsset|LPPool|stableSwap'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': 'add_liquidity|remove_liquidity|addLiquidity|removeLiquidity|join|exit'}, {'function.body_contains_regex': 'update_rates|updateRates|_refreshRates'}, {'function.body_contains_regex': 'rate\\[|rates\\[|_rates\\s*\\['}, {'function.body_not_contains_regex': 'update_rates\\s*\\([^;]*;[^;]*rate\\[|_updateRates\\s*\\([^;]*;[^;]*rate\\s*='}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — rate-update-lag-read-compute-write-trio: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
