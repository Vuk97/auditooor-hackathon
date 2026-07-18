"""
certora-aave-liquidity-index-monotonic — generated from reference/patterns.dsl/certora-aave-liquidity-index-monotonic.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py certora-aave-liquidity-index-monotonic.yaml
Source: certora-aave-v3-core/reserveLogic/indexMonotonic
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CertoraAaveLiquidityIndexMonotonic(AbstractDetector):
    ARGUMENT = "certora-aave-liquidity-index-monotonic"
    HELP = "Liquidity/borrow index is written without enforcing monotone increase — Aave Certora invariant `indexMonotonic` violated."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/certora-aave-liquidity-index-monotonic.yaml"
    WIKI_TITLE = "Liquidity or borrow index written without monotone-increase check"
    WIKI_DESCRIPTION = "Aave's `reserveLogic` specification encodes `liquidityIndex_t >= liquidityIndex_{t-1}` and likewise for `variableBorrowIndex`. Any path that writes the index (reserve-rescale, admin reset, special-case initialization) without asserting the new value is at least as large as the old one violates the invariant. Since interest accrual multiplies balances by `index_now / index_at_deposit`, a non-monoto"
    WIKI_EXPLOIT_SCENARIO = "An admin `rescaleReserve(asset, newIndex)` rewrites `liquidityIndex` to a lower value intending to 'normalize' the display. Every aToken holder's `balanceOf()` (computed as `scaledBalance.rayMul(liquidityIndex)`) drops instantly. If the admin is compromised or the rescale miscalculates, user funds evaporate from the UI; the scaled-balance invariant still holds but redeemable amount fell."
    WIKI_RECOMMENDATION = "All index writers must assert `newIndex >= oldIndex`. Index rescales must be done by migration — mint fresh scaled balances using the new index basis — not by mutation in place. Add a Foundry invariant tracking the last seen index and asserting non-decrease across every handler call."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(liquidityIndex|variableBorrowIndex|supplyIndex|ReserveLogic|reserveData|rayMul|rayDiv|accrueInterest|aToken|AToken)'}, {'contract.has_state_var_matching': '(?i)(liquidityIndex|variableBorrowIndex|borrowIndex|supplyIndex|cumulativeIndex)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.is_mutating': True}, {'function.writes_storage_matching': '(?i)(liquidityIndex|variableBorrowIndex|borrowIndex|supplyIndex|cumulativeIndex)'}, {'function.body_contains_regex': '(?i)(liquidityIndex|variableBorrowIndex|borrowIndex|supplyIndex|cumulativeIndex)\\s*='}, {'function.body_not_contains_regex': '(?i)(>=\\s*.*index|index\\s*<=|oldIndex|require.*index|assert.*index)'}, {'function.name_matches': '(?i)^(updateState|setIndex|initReserve|rescaleReserve|rescaleIndex|resetIndex|adjustIndex|_updateIndexes|_updateState|accrueInterest|cumulateToLiquidityIndex)\\w*$'}, {'function.not_source_matches_regex': '(?i)(view\\s+returns|pure\\s+returns|returns\\s*\\(\\s*uint256\\s+newIndex\\s*\\)|_rayMul\\s*\\(|_calculateLinearInterest|require\\s*\\([^)]*newIndex\\s*>=\\s*.*Index)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — certora-aave-liquidity-index-monotonic: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
