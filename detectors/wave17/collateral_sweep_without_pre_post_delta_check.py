"""
collateral-sweep-without-pre-post-delta-check — generated from reference/patterns.dsl/collateral-sweep-without-pre-post-delta-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py collateral-sweep-without-pre-post-delta-check.yaml
Source: auditooor-R94-phase37d-polymarket-collateral-adapter
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CollateralSweepWithoutPrePostDeltaCheck(AbstractDetector):
    ARGUMENT = "collateral-sweep-without-pre-post-delta-check"
    HELP = "Adapter/Collateral wrapper redeems or converts a fixed-amount position then sweeps the FULL contract balance (`token.balanceOf(address(this))`) to the caller without computing a pre/post-call delta. Any USDC/USDC.e/collateral previously stranded on the contract is harvested by the next caller."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/collateral-sweep-without-pre-post-delta-check.yaml"
    WIKI_TITLE = "Adapter sweeps full balance instead of measuring redemption delta — stranded-asset skim"
    WIKI_DESCRIPTION = "A *Collateral/Wrapper/Offramp/Adapter* function (`redeemPositions`, `convertPositions`, `splitPosition`, `mergePositions`, `offramp`, `unwrapAll`, `claimAll`, `withdrawAll`, `sweepToCaller`, ...) accepts a fixed expected-amount parameter, performs an inner redeem/convert/unwrap, then transfers `token.balanceOf(address(this))` to `msg.sender`. There is no pre-call snapshot, so the function does NOT"
    WIKI_EXPLOIT_SCENARIO = "Polymarket Cantina #173 / #174: `CtfCollateralAdapter.redeemPositions(amount)` calls `CONDITIONAL_TOKENS.redeemPositions(...)` then runs `USDCE.transfer(msg.sender, USDCE.balanceOf(address(this)))`. Sibling `NegRiskCtfCollateralAdapter.convertPositions(amount)` does the same against `NegRiskAdapter.convertPositions`. If a user mistakenly sends USDC.e to either adapter, the next caller — even with "
    WIKI_RECOMMENDATION = "Replace the full-balance sweep with a pre/post delta:\n```\nuint256 balBefore = token.balanceOf(address(this));\n_doRedeem(amount);\nuint256 received = token.balanceOf(address(this)) - balBefore;\nrequire(received >= expected, \"shortfall\");\ntoken.transfer(msg.sender, received);\n```\nProvide a se"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(Adapter|Collateral|Offramp|Wrapper|Converter|Bridge|Vault)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(redeemPositions|convertPositions|splitPosition|mergePositions|offramp|unwrapAll|claimAll|withdrawAll|sweepToCaller)'}, {'function.body_contains_regex': '(?i)(IERC20|ERC20).*\\.transfer\\s*\\(\\s*(?:msg\\.sender|caller|to|recipient)\\s*,\\s*(?:IERC20|token|\\w+)\\.balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)'}, {'function.not_body_contains_regex': '(?i)(balanceBefore|_balanceBefore|pre_balance|snapshotBefore|snapshot_before|diff\\s*=|delta\\s*=)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — collateral-sweep-without-pre-post-delta-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
