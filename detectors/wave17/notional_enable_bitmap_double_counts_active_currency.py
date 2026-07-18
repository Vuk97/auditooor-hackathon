"""
notional-enable-bitmap-double-counts-active-currency — generated from reference/patterns.dsl/notional-enable-bitmap-double-counts-active-currency.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py notional-enable-bitmap-double-counts-active-currency.yaml
Source: auditooor-R76-immunefi-notional-$150k
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class NotionalEnableBitmapDoubleCountsActiveCurrency(AbstractDetector):
    ARGUMENT = "notional-enable-bitmap-double-counts-active-currency"
    HELP = "enableBitmapForAccount changes the bitmap-tracked currency but does NOT remove the prior currency from the activeCurrencies list. Free-collateral calculations count the same asset twice → 2x borrowing power."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/notional-enable-bitmap-double-counts-active-currency.yaml"
    WIKI_TITLE = "Bitmap currency switch leaves prior currency in activeCurrencies — double-count"
    WIKI_DESCRIPTION = "Collateral/debt accounting uses two parallel registries: (a) an `activeCurrencies` dynamic list, (b) a bitmap-tracked `bitmapCurrencyId` slot. When the bitmap currency is changed, the previous value is left in the activeCurrencies array. The free-collateral loop iterates both registries and sums the asset twice. Attacker: enable bitmap on dummy currency → deposit target asset (added to activeCurre"
    WIKI_EXPLOIT_SCENARIO = "Notional's AccountContextHandler.enableBitmapForAccount allowed switching bitmap currency without pruning activeCurrencies. Attacker enables bitmap on cDAI, deposits USDC (activeCurrencies += USDC), re-enables bitmap on USDC — FC counts USDC twice, borrows 2×, pockets excess. $150k bounty."
    WIKI_RECOMMENDATION = "Forbid switching bitmap currency once set (Notional's actual fix). If mutability is required, atomically remove any overlap between bitmap-currency and activeCurrencies inside the same function. Add invariant test: `forall acct: bitmapCurrencyId not in activeCurrencies(acct)`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.is_lending_or_collateral_manager': True}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)enableBitmap|setBitmapCurrency|setPrimaryCurrency|switchCollateralMode'}, {'function.body_not_contains_regex': '(?i)_removeActiveCurrency|activeCurrencies\\.remove|delete\\s+activeCurrencies|setActiveCurrency\\s*\\([^)]*false\\s*\\)|clearPrevious'}, {'function.body_contains_regex': '(?i)bitmapCurrencyId\\s*=|accountContext\\.bitmap'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — notional-enable-bitmap-double-counts-active-currency: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
