"""
r74-liquidation-revert-on-unrelated-pause — generated from reference/patterns.dsl/r74-liquidation-revert-on-unrelated-pause.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r74-liquidation-revert-on-unrelated-pause.yaml
Source: r74b-cross-firm-cs+tob
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R74LiquidationRevertOnUnrelatedPause(AbstractDetector):
    ARGUMENT = "r74-liquidation-revert-on-unrelated-pause"
    HELP = "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: liquidation health-factor scan iterates all of the user's assets without tolerating per-asset pauses; an unrelated asset pause halts every liquidation."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r74-liquidation-revert-on-unrelated-pause.yaml"
    WIKI_TITLE = "Liquidation reverts when an unrelated user asset is paused"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. Lending protocols compute a user's health factor by iterating every asset in the user's portfolio (reserves list, collateral list, cross-chain positions). When a single asset becomes temporarily unavailable — paused by a risk admin, oracle returns zero, proxy deprecated — the iteration reverts at that asset. Because liquidations read the use"
    WIKI_EXPLOIT_SCENARIO = "AaveV4 hub-and-spoke architecture: a long-tail asset on the hub is paused for a governance timelock due to an unrelated oracle drift. A borrower on the hub has USDC debt backed by ETH collateral and a dust amount of the paused asset they forgot to withdraw. Their health factor computation iterates all three assets, reverts at the paused one. Liquidators cannot liquidate even the unrelated USDC/ETH"
    WIKI_RECOMMENDATION = "Scan user assets with explicit failure tolerance: `try` each asset read, on revert mark the user as 'untrustable health factor' (reject NEW borrows but still allow liquidation on non-paused assets against conservatively-valued collateral). Alternatively, exclude paused assets from health computation"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(liquidate|healthFactor|userReserves|getAssetsList|collateralAssets)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(liquidate|calculateHealth|getUserHealth|_calculateUserAccountData|getUserData)'}, {'function.body_contains_regex': 'for\\s*\\([^)]*(assets?|reserves?|collaterals?)\\s*\\.length|userAssets|for\\s*\\(.*i\\s*<\\s*\\w+\\.length.*reserves'}, {'function.body_not_contains_regex': 'try\\s+\\w+|catch\\s*\\(|if\\s*\\(\\s*(paused|isPaused|assetPaused)\\s*\\)\\s*continue|skipPaused|isActive\\s*\\[|isFrozen'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r74-liquidation-revert-on-unrelated-pause: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
