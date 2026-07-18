"""
liquidation-remaining-margin-check-only-on-full-close — generated from reference/patterns.dsl/liquidation-remaining-margin-check-only-on-full-close.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py liquidation-remaining-margin-check-only-on-full-close.yaml
Source: auditooor-R75-code4rena-2024-05-predy-189
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LiquidationRemainingMarginCheckOnlyOnFullClose(AbstractDetector):
    ARGUMENT = "liquidation-remaining-margin-check-only-on-full-close"
    HELP = "Liquidator compensation branch runs only when the position is fully closed — attacker partial-closes to the insolvency boundary and exits with profit."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/liquidation-remaining-margin-check-only-on-full-close.yaml"
    WIKI_TITLE = "Liquidation bad-debt compensation gated on full close, enabling cherry-picked partial liquidation"
    WIKI_DESCRIPTION = "Inside `liquidate`, bad-debt compensation (`safeTransferFrom(msg.sender, this, -remainingMargin)`) only fires when `!hasPosition`. A liquidator partial-closes the position stopping at the size where `vault.margin == 0`, collects their slippage profit, and leaves the remaining (now untouchable or further-underwater) position open — protocol eats the loss that would have been the liquidator's respon"
    WIKI_EXPLOIT_SCENARIO = "Vault: 1 ETH long, entry 3000 USDC, current price 2500 USDC, margin 500 USDC. Full liquidation at 5% slippage would require liquidator to repay 75 USDC of bad debt. Instead liquidator closes 0.8 ETH → collects 2000 * 0.95 = 1900 USDC, returns 2400 USDC from entry basis, nets ~100 USDC profit, vault.margin drops to zero. Remaining 0.2 ETH stays open, now at worse LTV — protocol bears full loss."
    WIKI_RECOMMENDATION = "Extend the remainingMargin check to all liquidation paths, scaled to the closed fraction. `if (closeSize/totalSize * currentMargin < 0) collectFromLiquidator(...)`. Invariant test: for every fraction `f` of size closed, liquidator is charged their share of bad debt."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '(?i)liquidate\\w*|_liquidate|forceClose'}, {'function.body_contains_regex': '(?i)if\\s*\\(\\s*!\\s*hasPosition\\s*\\)|if\\s*\\(\\s*positionClosed\\s*\\)|if\\s*\\(\\s*\\w+\\.positionSize\\s*==\\s*0\\s*\\)'}, {'function.body_contains_regex': '(?i)remainingMargin\\s*<\\s*0|vault\\.margin\\s*<\\s*0|_netMargin\\s*<\\s*0'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': '(?i)safeTransferFrom\\s*\\(\\s*msg\\.sender\\s*,\\s*address\\(this\\)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — liquidation-remaining-margin-check-only-on-full-close: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
