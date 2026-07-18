"""
fx-pendle-transferfrom-wrong-param — generated from reference/patterns.dsl/fx-pendle-transferfrom-wrong-param.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-pendle-transferfrom-wrong-param.yaml
Source: github:pendle-finance/pendle-core-v2-public@fa4b669
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxPendleTransferfromWrongParam(AbstractDetector):
    ARGUMENT = "fx-pendle-transferfrom-wrong-param"
    HELP = "_transferFrom called with netLpIn instead of netPtIn when pulling PT tokens for redemption. The function transfers LP tokens to the contract instead of PT tokens, leaving PT tokens unpulled and draining LP tokens from the caller."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-pendle-transferfrom-wrong-param.yaml"
    WIKI_TITLE = "ExpiredLpPtRedeemer _transferFrom uses wrong parameter — pulls LP amount instead of PT amount"
    WIKI_DESCRIPTION = "Redeem functions that accept both LP and PT inputs and then pull each separately can use the wrong variable in the transferFrom call. Passing netLpIn (LP token amount) when the intent is to pull netPtIn (PT tokens) incorrectly drains the caller's LP balance by the PT amount and leaves PT tokens in the caller's wallet, making the redemption transfer incorrect amounts of both token types."
    WIKI_EXPLOIT_SCENARIO = "Pendle (2024): ExpiredLpPtRedeemer.redeem() calls `_transferFrom(PT, msg.sender, address(this), netLpIn)` instead of `netPtIn`. Users redeeming PT tokens have their LP balance drained by netLpIn units of LP-priced transfers while the PT tokens never arrive."
    WIKI_RECOMMENDATION = "Replace `_transferFrom(PT, msg.sender, address(this), netLpIn)` with `_transferFrom(PT, msg.sender, address(this), netPtIn)`. Audit all multi-token redemption paths for similar variable-swap bugs."

    _PRECONDITIONS = [{'contract.has_function_matching': '^redeem$|^redeemPt$|^redeemLp'}, {'contract.source_matches_regex': '(ExpiredLpPtRedeemer|ActionExpired|PendleMarket|redeemLp|redeemPt|netLpIn|netPtIn|ActionRedeem)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(redeem|redeemLp|redeemPt|redeemPT|redeemExpired|redeemExpiredLpPt|redeemDueInterestAndRewards|withdrawExpired)\\w*$'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.body_contains_regex': '_transferFrom\\(.*netLpIn'}, {'function.body_not_contains_regex': '_transferFrom\\(.*netPtIn'}, {'function.not_source_matches_regex': '(?i)(view\\s+returns|pure\\s+returns|internal\\s+view|internal\\s+pure|_transferFrom\\s*\\(\\s*PT[^)]*,\\s*netPtIn|transferFrom\\s*\\(\\s*address\\s*\\(\\s*PT\\s*\\)[^)]*netPtIn)'}]

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
                info = [f, f" — fx-pendle-transferfrom-wrong-param: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
