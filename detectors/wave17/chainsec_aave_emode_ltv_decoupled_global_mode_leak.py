"""
chainsec-aave-emode-ltv-decoupled-global-mode-leak — generated from reference/patterns.dsl/chainsec-aave-emode-ltv-decoupled-global-mode-leak.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py chainsec-aave-emode-ltv-decoupled-global-mode-leak.yaml
Source: auditooor-R75-chainsec-AaveV3-eModeLTVDecoupling-review
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ChainsecAaveEmodeLtvDecoupledGlobalModeLeak(AbstractDetector):
    ARGUMENT = "chainsec-aave-emode-ltv-decoupled-global-mode-leak"
    HELP = "Post-v3.5 Aave decouples eMode LTV/LT from global-mode LTV/LT. Forked code that still reads `reserveConfig.getLtv()` directly instead of going through the unified `getUserReserveLtv(user, reserve, userEMode)` picks the wrong side of the decoupling — in eMode it may apply global-mode LT (safer-liquid"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/chainsec-aave-emode-ltv-decoupled-global-mode-leak.yaml"
    WIKI_TITLE = "eMode/global LTV decoupling not honored at HF computation site — wrong LT applied"
    WIKI_DESCRIPTION = "Aave V3.5 introduced independent LTV/LT configuration per eMode category; legacy code paths that computed `reserveConfig.getLtv()` as a single value now need to select the correct value based on whether the user is in an eMode. The unified helper `getUserReserveLtv(user, reserve, userEMode)` handles this. Forks that omit the helper — reading `getLtv()`/`getLt()` directly from the ReserveConfigurat"
    WIKI_EXPLOIT_SCENARIO = "Aave V3.5 fork: USDC has globalLtv=0.77, eModeStablecoins-LtV=0.95, eModeStablecoins-LT=0.97. User Alice is in eModeStablecoins. Legacy `calculateUserAccountData` reads `reserveConfig.getLtv() = 0.77` without passing `userEMode`. Alice's borrowable capacity is understated (0.77 vs intended 0.95), so she cannot borrow up to protocol-allowed limits — a griefing / UX bug. Inverse: if the code reads `"
    WIKI_RECOMMENDATION = "Always route LTV/LT reads through a unified helper that takes the user's eMode as an input: `getUserReserveLtv(user, reserve, userEMode)` and `getUserReserveLt(user, reserve, userEMode)`. Grep every call site of `reserveConfig.getLtv()` / `getLiquidationThreshold()` and replace. Add a system-invaria"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'GenericLogic|ValidationLogic|UserConfiguration|getUserReserveLtv|getUserEMode'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': 'calculateUserAccountData|validateHealthFactor|_getLiquidationThreshold|getUserReserveLtv|getEffectiveLtv'}, {'function.body_contains_regex': 'userEMode|eModeCategory|getEModeCategoryData'}, {'function.body_contains_regex': 'getLtv\\s*\\(\\s*\\)|liquidationThreshold'}, {'function.body_not_contains_regex': 'getUserReserveLtv\\s*\\(.*userEMode|ltvzeroBitmap|effectiveLtv\\s*=\\s*eMode\\s*\\?|_getEffectiveLtv'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — chainsec-aave-emode-ltv-decoupled-global-mode-leak: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
