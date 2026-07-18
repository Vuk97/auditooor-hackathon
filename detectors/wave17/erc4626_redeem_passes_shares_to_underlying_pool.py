"""
erc4626-redeem-passes-shares-to-underlying-pool — generated from reference/patterns.dsl/erc4626-redeem-passes-shares-to-underlying-pool.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc4626-redeem-passes-shares-to-underlying-pool.yaml
Source: auditooor-R73-code4rena-2024-07-loopfi-170
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc4626RedeemPassesSharesToUnderlyingPool(AbstractDetector):
    ARGUMENT = "erc4626-redeem-passes-shares-to-underlying-pool"
    HELP = "Wrapper redeem() forwards share amount to underlying pool redeem() without converting shares -> assets first."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc4626-redeem-passes-shares-to-underlying-pool.yaml"
    WIKI_TITLE = "ERC4626 wrapper passes wrapper-shares to underlying pool redeem (unit mismatch)"
    WIKI_DESCRIPTION = "An ERC4626 wrapper around another yield pool forwards the caller-supplied `shares` parameter directly to the underlying pool's redeem/withdraw without converting to assets via previewRedeem. Because the wrapper's share-to-asset ratio can diverge from 1:1, the amount withdrawn from the underlying pool is sized in the wrong unit and users receive fewer assets than they are entitled to."
    WIKI_EXPLOIT_SCENARIO = "Vault has 1 share = 2 assets. User calls redeem(shares=1). The code calls pool.redeem(1), which burns 1 underlying-share and returns 1 asset (since the underlying pool is 1:1). The user ends up with 1 asset instead of the 2 they were entitled to; the 1 missing asset remains stranded in the wrapper."
    WIKI_RECOMMENDATION = "Convert shares to assets before forwarding: `uint256 assets = previewRedeem(shares); pool.redeem(assets, …);` then burn the wrapper shares with `_withdraw(msg.sender, receiver, owner, assets, shares);`. Whenever a wrapper forwards amounts to a sub-strategy, ensure the unit matches the sub-strategy's"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(redeem|withdraw)$'}, {'function.body_contains_regex': '\\.(redeem|withdraw)\\(\\s*shares\\s*,'}, {'function.body_not_contains_regex': 'previewRedeem|convertToAssets|previewWithdraw'}, {'function.calls_function_matching': '(?i)redeem|withdraw'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — erc4626-redeem-passes-shares-to-underlying-pool: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
