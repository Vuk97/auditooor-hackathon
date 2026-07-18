"""
comet-absorb-does-not-clear-assetsIn-bitmap — generated from reference/patterns.dsl/comet-absorb-does-not-clear-assetsIn-bitmap.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py comet-absorb-does-not-clear-assetsIn-bitmap.yaml
Source: auditooor-R71-fixdiff-mined-compound-comet-a371ae1199
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CometAbsorbDoesNotClearAssetsinBitmap(AbstractDetector):
    ARGUMENT = "comet-absorb-does-not-clear-assetsIn-bitmap"
    HELP = "absorb / liquidation path zeros out each collateral's `userCollateral[user][asset].balance` but does not reset the `assetsIn` bitmap on `userBasic[user]`. Subsequent solvency checks iterate the stale bitmap, read zero balances, and still pay gas — worse, any re-credit of a collateral balance (dust r"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/comet-absorb-does-not-clear-assetsIn-bitmap.yaml"
    WIKI_TITLE = "Liquidation / absorb clears collateral balances but not assetsIn bitmap"
    WIKI_DESCRIPTION = "Comet tracks which collateral assets a user holds via a compact `uint16 assetsIn` bitmap on `userBasic[account]`, with each bit corresponding to an asset offset. The bitmap is set when `updateAssetsIn` detects a zero-to-nonzero transition and cleared on the symmetric transition. During absorption, all collateral balances are zeroed in one sweep, but if the zeroing is done directly via `userCollate"
    WIKI_EXPLOIT_SCENARIO = "Commit a371ae1199 fixed this in Comet: before the patch, `absorb` iterated each asset, computed a new base balance, but left `userBasic[account].assetsIn` at its pre-absorb value. A sequence of manipulation: (1) account is absorbed, all collateral balances become 0, but `assetsIn = 0b0010101` still; (2) a buggy deposit path on asset A (pre-re-credit through a non-updateAssetsIn code path) raises `"
    WIKI_RECOMMENDATION = "At the end of any absorb / liquidate / seize-all flow, explicitly reset the bitmap: `userBasic[account].assetsIn = 0;`. Do this AFTER zeroing balances and AFTER updating base principal so that solvency checks in the same function see the correct state. Alternative: always route balance writes throug"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'assetsIn|assetBitmap|userBasic|_absorb|absorbInternal'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '^(absorb|liquidate|liquidateBorrow|seize|forceRepay|closePosition|_absorb)$'}, {'function.body_contains_regex': 'userCollateral\\s*\\[\\s*\\w+\\s*\\]\\s*\\[\\s*\\w+\\s*\\]\\.balance\\s*=\\s*0|seizedAsset|collateralAbsorbed|totalsCollateral\\['}, {'function.body_not_contains_regex': 'assetsIn\\s*=\\s*0|userBasic\\s*\\[\\s*\\w+\\s*\\]\\.assetsIn\\s*=\\s*0|clearAssetsIn|resetAssetsIn'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — comet-absorb-does-not-clear-assetsIn-bitmap: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
