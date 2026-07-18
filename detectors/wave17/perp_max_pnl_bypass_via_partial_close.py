"""
perp-max-pnl-bypass-via-partial-close — generated from reference/patterns.dsl/perp-max-pnl-bypass-via-partial-close.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py perp-max-pnl-bypass-via-partial-close.yaml
Source: auditooor-R75-c4-2022-12-tigris-H507-H111
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PerpMaxPnlBypassViaPartialClose(AbstractDetector):
    ARGUMENT = "perp-max-pnl-bypass-via-partial-close"
    HELP = "Max-PnL cap compares partial payout against FULL margin, not the partial margin. An N-way partial close can extract N× the intended cap. Also, `addToPosition` paths often omit the cap entirely — user can farm beyond cap via add-and-close loops."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/perp-max-pnl-bypass-via-partial-close.yaml"
    WIKI_TITLE = "Max-PnL cap bypassed by partial closes (cap compared against full margin, not partial share)"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. Perp DEXs limit winning PnL, e.g. 'max 500% of margin' to protect LPs against a single whale wiping out the pool. The checked-in detector distinguishes the local source shape where `_toMint` for a partial close is capped against full `_trade.margin * maxWinPercent` from a clean shape where the cap is scaled by partial margin. Tigris Dec 2022 H-507 and H-111 d"
    WIKI_EXPLOIT_SCENARIO = "(1) Alice opens a leveraged long: margin=100, leverage=500x. Hit the jackpot, uncapped payout would be 10_000 (100× return). maxWinPercent=500% → cap should be 500. (2) Alice calls `closePosition(percent=50%)`. `_toMint = 10000 * 50% = 5000`. Cap check: `5000 > 100 * 500% = 500` → `_toMint = 500`. Alice receives 500, position is 50% remaining with notional payout 5000. (3) Alice calls `closePositi"
    WIKI_RECOMMENDATION = "Apply the cap against the partial margin, not the initial margin: `if (_toMint > _trade.margin * _percent / DIVISION_CONSTANT * maxWinPercent / DIVISION_CONSTANT) _toMint = ...`. Equivalently, track lifetime payout per position and cap the cumulative: `lifetimePaid + newPayout <= initialMargin * max"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(maxWinPercent|maxPnL|payoutCap|winPercent|_closePosition|addToPosition)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(_closePosition|closePosition|partialClose|addToPosition|_addToPosition)'}, {'function.body_contains_regex': '(maxWinPercent|maxPnl|payoutCap|winLimit)'}, {'function.body_contains_regex': '_toMint\\s*>\\s*_trade\\.margin\\s*\\*\\s*maxWinPercent'}, {'function.body_not_contains_regex': '(_toMint\\s*>\\s*(_trade\\.margin\\s*\\*\\s*_percent|margin\\s*\\*\\s*closePercent)\\s*/|_partialMargin\\s*\\*\\s*maxWinPercent)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — perp-max-pnl-bypass-via-partial-close: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
