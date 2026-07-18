"""
perp-position-key-collision-on-swap-output-token — generated from reference/patterns.dsl/perp-position-key-collision-on-swap-output-token.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py perp-position-key-collision-on-swap-output-token.yaml
Source: auditooor-R73-fixdiff-mined-gmx-synthetics-557c9b5d39
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PerpPositionKeyCollisionOnSwapOutputToken(AbstractDetector):
    ARGUMENT = "perp-position-key-collision-on-swap-output-token"
    HELP = "Position key derived from initialCollateralToken even though an increase order with swapPath will end up in the swap-output token. Downstream mappings (chainId, fees, auto-cancel) desync from the actual position key."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/perp-position-key-collision-on-swap-output-token.yaml"
    WIKI_TITLE = "Position key uses initialCollateralToken, not swap-output token"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: GMX-style orders carry a `swapPath` that swaps `initialCollateralToken` to an output token before the position opens. The canonical positionKey is `(account, market, collateralToken, isLong)` where `collateralToken` is the final post-swap token. Utilities that derive a key from `order.initialCollateralToken()` without traversing the swap path produce a differ"
    WIKI_EXPLOIT_SCENARIO = "Scenario A (desync): User creates an increase order with `initialCollateralToken=USDC`, `swapPath=[USDC→ETH]`, `isLong=true`. After swap, position is keyed by ETH. The multichain chainId mapping is written to key(USDC)→srcChainId=42161; on liquidation the liquidator reads key(ETH) and gets 0 (default), liquidation assumes same-chain path and unwraps WETH to the user on-chain when the user is cross"
    WIKI_RECOMMENDATION = "Any key-derivation helper that accepts `Order.Props` must resolve the final collateral token via the swap path for increase orders: `SwapUtils.getOutputToken(dataStore, order.swapPath(), order.initialCollateralToken())`. Decrease / swap orders use `initialCollateralToken` directly. Unit test: create"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Position\\.getPositionKey|positionKey|positionLastSrcChainId)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(_updatePositionLast|updatePositionKey|recordPosition|_storePositionMeta)'}, {'function.body_contains_regex': 'Position\\.getPositionKey\\s*\\([\\s\\S]*order\\.initialCollateralToken'}, {'function.body_not_contains_regex': 'SwapUtils\\.getOutputToken|_getOutputToken|getOutputCollateralToken'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — perp-position-key-collision-on-swap-output-token: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
