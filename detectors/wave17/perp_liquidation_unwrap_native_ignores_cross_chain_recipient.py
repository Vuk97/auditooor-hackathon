"""
perp-liquidation-unwrap-native-ignores-cross-chain-recipient — generated from reference/patterns.dsl/perp-liquidation-unwrap-native-ignores-cross-chain-recipient.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py perp-liquidation-unwrap-native-ignores-cross-chain-recipient.yaml
Source: auditooor-R73-fixdiff-mined-gmx-synthetics-dd82006e95
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PerpLiquidationUnwrapNativeIgnoresCrossChainRecipient(AbstractDetector):
    ARGUMENT = "perp-liquidation-unwrap-native-ignores-cross-chain-recipient"
    HELP = "Liquidation hardcodes `shouldUnwrapNativeToken = true`. For a cross-chain (multichain-balance) position, unwrapping and sending native on the local chain strands funds — the user's balance lives on a different srcChainId."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/perp-liquidation-unwrap-native-ignores-cross-chain-recipient.yaml"
    WIKI_TITLE = "Liquidation unwraps native for multichain-balance user, stranding funds"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. This row flags only the owned liquidation-order creator shape where `Order.Flags(position.isLong(), true)` or an equivalent hardcoded unwrap literal is used without any visible `srcChainId`, `positionLastSrcChainId`, or `multichainBalance` branch in the same function. GMX-synthetics commit dd82006e95 added the missing source-chain guard."
    WIKI_EXPLOIT_SCENARIO = "(1) User opens ETH-long from Arbitrum, collateral recorded as multichainBalance[user][wnt] on the hub. (2) Price crashes, position becomes liquidatable. (3) Keeper calls `createLiquidationOrder`. The liquidation order has `shouldUnwrapNativeToken = true` hardcoded. (4) Residual 0.5 ETH after liquidation fees: liquidation handler unwraps WETH and calls `sendNative(user, 0.5 ETH)` on Arbitrum. (5a) "
    WIKI_RECOMMENDATION = "In the liquidation path, branch on srcChainId: if the position was created via a multichain deposit (srcChainId != 0), set `shouldUnwrapNativeToken = false` and route residual collateral back through the multichain balance / bridging pipeline. Never hardcode `true` / `false` on unwrap flags in cross"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(liquidation|LiquidationUtils|LiquidateOrder)'}, {'contract.source_matches_regex': 'shouldUnwrapNativeToken'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(createLiquidationOrder|_createLiquidateOrder|placeLiquidationOrder|buildLiquidation)'}, {'function.body_contains_regex': 'Order\\.Flags\\s*\\([^;{}]*position\\.isLong\\s*\\(\\s*\\)\\s*,\\s*true'}, {'function.body_not_contains_regex': 'positionLastSrcChainId|srcChainId|multichainBalance'}, {'function.body_contains_regex': 'shouldUnwrapNativeToken'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — perp-liquidation-unwrap-native-ignores-cross-chain-recipient: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
