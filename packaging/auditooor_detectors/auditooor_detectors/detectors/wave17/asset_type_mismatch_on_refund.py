"""
asset-type-mismatch-on-refund — generated from reference/patterns.dsl/asset-type-mismatch-on-refund.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py asset-type-mismatch-on-refund.yaml
Source: solodit-novel/slice_ab-t3rn
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AssetTypeMismatchOnRefund(AbstractDetector):
    ARGUMENT = "asset-type-mismatch-on-refund"
    HELP = "Refund/claim/redeem path checks a `claimed`-style flag but never asserts that the asset being transferred matches the asset committed at deposit time. Allows asset-substitution drains."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/asset-type-mismatch-on-refund.yaml"
    WIKI_TITLE = "Refund path lacks asset-identity assertion"
    WIKI_DESCRIPTION = "Claim / refund / redeem entrypoints verify a per-id claimed/refunded/processed flag is unset, then transfer the contract's currently-stored asset without binding that asset to the asset originally committed at deposit time. Admin re-configuration or auto-rebalance paths that flip the stored asset let users redeem a different (potentially higher-value) token than they deposited."
    WIKI_EXPLOIT_SCENARIO = "t3rn escrow: `isClaimable(orderId)` only checks the `claimed[orderId]` flag; the refund path then `IERC20(rewardAsset).transfer(user, amount)`. When admin reconfigures the market mid-flight (changing `rewardAsset` from token A to token B), a user who deposited 1 unit of A redeems 1 unit of B. The bug fires because nothing in the refund path requires that the order's stored asset still matches `rew"
    WIKI_RECOMMENDATION = "Record the asset address at deposit time inside the per-id struct (`deposits[id].asset = token`). On refund/claim/redeem, assert equality with the asset actually being transferred: `require(deposits[id].asset == currentAsset, 'asset mismatch')`. Alternatively, bind each escrow / claim contract to a "

    _PRECONDITIONS = [{'contract.has_state_var_matching': '^(claimed|refunded|processed|fulfilled|redeemed)$'}, {'contract.has_state_var_matching': '^(asset|token|rewardAsset|paymentToken|depositToken)$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(refund|claim|redeem|withdraw|exit)([A-Z_].*)?$'}, {'function.body_contains_regex': '\\b(claimed|refunded|processed|fulfilled|redeemed)\\s*\\['}, {'function.body_contains_regex': '\\.(transfer|safeTransfer|transferFrom|safeTransferFrom)\\s*\\('}, {'function.body_not_contains_regex': 'require\\s*\\([^)]*\\b(asset|token|rewardAsset|paymentToken|depositToken)\\b[^)]*==|require\\s*\\([^)]*==[^)]*\\b(asset|token|rewardAsset|paymentToken|depositToken)\\b|if\\s*\\([^)]*\\b(asset|token|rewardAsset|paymentToken|depositToken)\\b[^)]*!='}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — asset-type-mismatch-on-refund: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
