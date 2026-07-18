"""
armor-double-unit-conversion-wei-already-in-wei — generated from reference/patterns.dsl/armor-double-unit-conversion-wei-already-in-wei.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py armor-double-unit-conversion-wei-already-in-wei.yaml
Source: auditooor-R76-immunefi-armor-$876k
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ArmorDoubleUnitConversionWeiAlreadyInWei(AbstractDetector):
    ARGUMENT = "armor-double-unit-conversion-wei-already-in-wei"
    HELP = "Payout function multiplies input amount by 1e18/WAD even though the caller already passed wei-denominated amount. Drainage via 10^18-inflation attack."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/armor-double-unit-conversion-wei-already-in-wei.yaml"
    WIKI_TITLE = "Double unit conversion — amount already in wei is multiplied by 1e18 again"
    WIKI_DESCRIPTION = "A claim/withdraw/redeem function has a line like `uint256 payment = _amount * 10 ** 18;` where `_amount` was already the smallest-unit value (wei for ETH, 1e18 for 18-decimal tokens). Upstream callers pass wei, so the multiply treats wei as whole tokens and re-converts. A $1 claim submission → 10^18 dollars in payout. The function proceeds without an availability cap, draining the contract."
    WIKI_EXPLOIT_SCENARIO = "Armor's ClaimManager line 62-64: `uint256 payment = _amount * 10 ** 18;` then transferred `payment` to claimant. Any coverage claim was inflated 10^18 times. A $1 claim could drain the treasury. $876k (vested $ARMOR) bounty."
    WIKI_RECOMMENDATION = "Standardize: internal functions ALWAYS use wei/smallest-unit amounts; any external-facing human-readable conversion happens at the UI layer, never in core logic. Before every payout, assert `payment <= maxClaim(user) && payment <= address(this).balance`. Add a static-analysis rule: flag `* 10**18` /"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)withdraw\\w*|claim\\w*|payout\\w*|redeem\\w*|settle\\w*'}, {'function.body_contains_regex': '(?i)\\w+\\s*\\*\\s*10\\s*\\*\\*\\s*18|\\w+\\s*\\*\\s*1e18|\\w+\\s*\\*\\s*WAD|(?:amount|_amount|value)\\s*\\*\\s*(?:DECIMALS|PRECISION|ONE)'}, {'function.has_param_of_type': 'uint'}, {'function.has_param_name_matching': '(?i)(^_?amount$|amountWei|weiAmount|claimAmount|payoutAmount|redeemAmount|withdrawAmount|value)'}, {'function.body_not_contains_regex': '(?i)require\\s*\\([^)]*\\s*<\\s*(?:userBalance|totalAssets|maxClaim)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — armor-double-unit-conversion-wei-already-in-wei: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
