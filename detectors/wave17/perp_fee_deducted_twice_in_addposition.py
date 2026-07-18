"""
perp-fee-deducted-twice-in-addposition — generated from reference/patterns.dsl/perp-fee-deducted-twice-in-addposition.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py perp-fee-deducted-twice-in-addposition.yaml
Source: auditooor-R75-c4-2022-12-tigris-H659
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PerpFeeDeductedTwiceInAddposition(AbstractDetector):
    ARGUMENT = "perp-fee-deducted-twice-in-addposition"
    HELP = "`addToPosition` mints `tigAsset` fees to protocol destinations but then reduces the user's pulled margin by the same fee — fee is taken twice (once against backing, once from user deposit), leaving the position under-collateralised by `fee`."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/perp-fee-deducted-twice-in-addposition.yaml"
    WIKI_TITLE = "addToPosition pulls (margin - fee) from user AFTER already minting the fee from backing"
    WIKI_DESCRIPTION = "Tigris-style perp DEXs implement `addToPosition` that adds `addMargin` of collateral and scales the position by `addMargin * leverage`. The pattern used in `initiateMarketOrder` is: first mint fees (minting tigAsset to referrer/keeper/treasury, which dilutes the backing), then pull `_marginAfterFees` = `margin - fee` from the user. In `addToPosition`, the second step is sometimes coded `_handleDep"
    WIKI_EXPLOIT_SCENARIO = "(1) Alice has a tig position with margin=100, leverage=10, positionSize=1000. She calls `addToPosition(addMargin=50)`. (2) Protocol computes `fee = _handleOpenFees(50 * 10) = 5`. `_handleOpenFees` mints 5 tigAsset to the referrer and treasury; backing (USDC in StableVault) is unchanged, so every holder of tigAsset's share is diluted by 5. (3) Protocol pulls from Alice `addMargin - fee = 45` USDC. "
    WIKI_RECOMMENDATION = "Either (a) pull the full `addMargin` from the user, not `addMargin - fee`, treating the fee as already embedded in the transfer: user transfers 50, 5 goes to fee recipient, 45 goes to collateral; OR (b) keep the pull at `addMargin - fee` but reduce the position scaling to `(addMargin - fee) * levera"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(addToPosition|increasePosition|_handleOpenFees|tigAsset|stabilityPool)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(addToPosition|_addToPosition|increasePosition|addMargin|topUpPosition)'}, {'function.body_contains_regex': '_handleOpenFees|_accrueFees|mintFee|_distributeFee'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': '_handleDeposit\\s*\\([^)]*(addMargin\\s*-\\s*(fee|_fee)|margin\\s*-\\s*fee)|safeTransferFrom\\s*\\([^)]*(addMargin\\s*-\\s*(fee|_fee))'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — perp-fee-deducted-twice-in-addposition: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
