"""
perpetual-position-stuck-umbrella - generated from reference/patterns.dsl/perpetual-position-stuck-umbrella.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py perpetual-position-stuck-umbrella.yaml
Source: hackerman-v2-recall-batch3-2026-05-19
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PerpetualPositionStuckUmbrella(AbstractDetector):
    ARGUMENT = "perpetual-position-stuck-umbrella"
    HELP = "Position becomes unliquidatable or uncloseable because liquidation loops over an uncapped per-account position set, exit/redeem re-applies liquidation state, or dust thresholds leave the close path unable to settle the remainder."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/perpetual-position-stuck-umbrella.yaml"
    WIKI_TITLE = "Perpetual position stuck - unliquidatable or uncloseable position"
    WIKI_DESCRIPTION = "The same-class invariant is a perpetual, vault, trove, or option position that cannot be liquidated or closed after an adverse state transition. The source shapes are: liquidation iterates over an attacker-grown position list with no max-position cap; post-liquidation exit/redeem arithmetic subtracts already-liquidated debt, loss, margin, or collateral again; or dust/minimum-position thresholds le"
    WIKI_EXPLOIT_SCENARIO = "An adversarial account opens many dust option legs until liquidation exceeds the block gas limit, or a partial liquidation mutates debt/collateral state so the later exit path reverts, or the remaining position is below minDebt/minPosition and no close path accepts it. In all cases the account remains stuck and the protocol cannot fully liquidate or settle the position through the intended path."
    WIKI_RECOMMENDATION = "Cap positions per account at open time, provide bounded partial-liquidation batches or O(1) positionId liquidation, track post-liquidation state with a flag or nonce so exit/redeem applies the delta once, and add explicit dust/zero guards with a final close path for sub-minimum residual positions."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(liquidat|position|vault|collateral|trove|cdp|debt|borrow|margin|option|strike|expiry|exercise|settlement)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(liquidate|liquidateAccount|liquidatePosition|liquidateTrove|liquidateCDP|closePosition|exitVault|exitPosition|closeVault|settleOption|exerciseOption|redeemCollateral|repayAndClose|forceClose|batchLiquidate|withdrawMax|redeem|exit|close).*'}, {'function.body_contains_regex': '(?i)(for\\s*\\([^;]{0,160};[^;]{0,160}(positions|options|positionIdList|positionIds|accountPositions|troves)\\s*(\\[[^\\]]+\\])?\\s*\\.\\s*length|while\\s*\\([^;]{0,160}(position|option|trove)|\\.(debt|collateral|loss|margin)\\s*(?:-=|-\\s*)|payout\\s*=\\s*[^;]{0,120}\\.(collateral|margin)[^;]{0,120}-[^;]{0,120}\\.(debt|loss)|maxRedeem[^;]{0,160}\\.(debt|collateral|loss|margin)|(minDebt|minPosition|minTradeSize|minMargin|dustThreshold|MIN_(DEBT|POSITION|TRADE|MARGIN|COLLATERAL))[^;]{0,180}(liquidat|close|exit|redeem|forceClose))'}, {'function.body_contains_regex': '(?i)(position|option|trove|vault|collateral|debt|margin|liquidat|badDebt|shortfall|dust|MIN_)'}, {'function.body_not_contains_regex': '(?i)(require\\s*\\([^;]{0,240}(\\.length\\s*<=\\s*\\d|\\.length\\s*<\\s*\\d|positions\\.length\\s*==\\s*0|count\\s*<=\\s*MAX|nPositions\\s*<=\\s*MAX|positionCount\\s*<\\s*MAX|positionIdList\\[[^\\]]+\\]\\.length\\s*<\\s*MAX)|MAX_POSITIONS|MAX_OPTIONS|MAX_POSITIONS_PER_ACCOUNT|maxPositions|maxOptions|limit\\s*,\\s*offset|batchSize|partialLiquidat|positionId\\s*<|wasLiquidated|isLiquidated|liquidationNonce|liquidationCount|postLiquidationAdjust|skipLiquidated|if\\s*\\([^;]{0,160}(dust|seize|repay|remaining|payout)[^;]{0,80}(==|>|>=)\\s*0|require\\s*\\([^;]{0,160}(seize|repay|remaining|payout|amountOut)[^;]{0,80}>\\s*0)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture|demo|example)\\b'}]

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
                info = [f, f" - perpetual-position-stuck-umbrella: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
