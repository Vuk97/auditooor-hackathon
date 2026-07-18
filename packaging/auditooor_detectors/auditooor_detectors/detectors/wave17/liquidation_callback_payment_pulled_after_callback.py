"""
liquidation-callback-payment-pulled-after-callback — generated from reference/patterns.dsl/liquidation-callback-payment-pulled-after-callback.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py liquidation-callback-payment-pulled-after-callback.yaml
Source: auditooor-R101-morpho-I2.B
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LiquidationCallbackPaymentPulledAfterCallback(AbstractDetector):
    ARGUMENT = "liquidation-callback-payment-pulled-after-callback"
    HELP = "Liquidation flow delivers seized collateral to the liquidator and fires a user-controlled callback BEFORE pulling the loan-token payment via `safeTransferFrom`. With no `nonReentrant` guard the callback re-enters `liquidate()` / `preLiquidate()` and repeats the close-factor-bounded action atomically"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/liquidation-callback-payment-pulled-after-callback.yaml"
    WIKI_TITLE = "Liquidation callback runs before loan-token settlement, no reentrancy guard — atomic close-factor bypass"
    WIKI_DESCRIPTION = "A liquidation entry point's call order is `withdrawCollateral(seized)` → `liquidatorCallback.onLiquidate(...)` → `safeTransferFrom(liquidator, this, repaidAssets)`. With no `nonReentrant` modifier on the entry point, the callback site is a re-entry pivot: the liquidator's contract holds the seized collateral, the protocol has not been paid yet, and any health-factor / preLLTV / close-factor check "
    WIKI_EXPLOIT_SCENARIO = "Attacker creates contract `L` implementing `onPreLiquidate(repaidAssets, data) { PreLiquidation.preLiquidate(borrower, ...); }`. Attacker calls `preLiquidate(borrower, seized, repaidShares, abi.encode('reenter'))`. Inside `onMorphoRepay`, the protocol withdraws `seized` collateral to L. The protocol then calls `L.onPreLiquidate(repaid, data)`. L re-enters `preLiquidate(borrower, seized2, repaid2)`"
    WIKI_RECOMMENDATION = "(a) Add `nonReentrant` to the public entry point (`preLiquidate` / `liquidate`). (b) Reorder so the loan-token `safeTransferFrom` runs BEFORE the user callback (full CEI). If the callback is required for flash-style settlement, gate the callback site itself with a per-borrower transient lock that su"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'PreLiquidation|Liquidation|Liquidator|liquidate|preLiquidate'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(_?preLiquidate|_?liquidate|_?onMorphoRepay|_?onLiquidate|_?seize|_?settleLiquidation|_?executeLiquidation)$'}, {'function.body_contains_regex': '(\\.on\\w*Liquidate\\s*\\(|\\.onSeize\\s*\\(|\\bonMorphoRepay\\s*\\(|ILiquidationCallback\\s*\\(|IPreLiquidationCallback\\s*\\(|\\.callback\\s*\\()[\\s\\S]*?safeTransferFrom\\s*\\([^)]*\\b(liquidator|msg\\.sender|caller|borrower)\\b'}, {'function.has_modifier': {'includes': ['nonReentrant'], 'negate': True}}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — liquidation-callback-payment-pulled-after-callback: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
