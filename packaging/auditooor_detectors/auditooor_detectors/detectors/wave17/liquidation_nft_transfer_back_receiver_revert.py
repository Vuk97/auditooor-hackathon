"""
liquidation-nft-transfer-back-receiver-revert — generated from reference/patterns.dsl/liquidation-nft-transfer-back-receiver-revert.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py liquidation-nft-transfer-back-receiver-revert.yaml
Source: auditooor-R75-c4-lending-revert-lend-499
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LiquidationNftTransferBackReceiverRevert(AbstractDetector):
    ARGUMENT = "liquidation-nft-transfer-back-receiver-revert"
    HELP = "Liquidation path ends with a safeTransfer* returning collateral directly to the borrower. Borrower's onERC721Received / ERC777 hook / fallback can revert or burn all gas, blocking liquidation forever."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/liquidation-nft-transfer-back-receiver-revert.yaml"
    WIKI_TITLE = "Liquidation bricked by borrower-controlled receiver hook"
    WIKI_DESCRIPTION = "When liquidate() returns collateral (an ERC721 NFT, ERC777 asset, or other token with receiver callbacks) to the borrower via safeTransferFrom / safeTransfer, the token standard invokes onERC721Received / tokensReceived on the borrower address. A malicious borrower deploys a contract that reverts in that hook, or consumes all gas in a tight loop. Because the transfer is on the liquidation path — n"
    WIKI_EXPLOIT_SCENARIO = "Alice's position becomes liquidatable. Before Bob can call liquidate(Alice), Alice transfers her position to a contract she controls whose onERC721Received does `while(gasleft() > 5000) counter++; revert();`. Every liquidation attempt now OOG-reverts inside _cleanupLoan's safeTransferFrom. Alice keeps the borrowed funds and the protocol accrues bad debt."
    WIKI_RECOMMENDATION = "Use a pull pattern: do not push collateral to the borrower in the liquidation path. Record the amount owed to the borrower and let them claim it in a separate transaction. If a push is required, wrap the transfer in try/catch so a reverting hook is absorbed, and cap the forwarded gas (`{gas: SAFE_GA"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)function\\s+liquidat'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(_?liquidate|_cleanupLoan|_closePosition|_seizeCollateral|executeLiquidate|_repossess)'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': '(?i)\\.(safeTransferFrom|safeTransfer)\\s*\\([^;]*,\\s*(owner|borrower|positionOwner|tokenOwner|from)[^,]*,'}, {'function.body_not_contains_regex': '(?i)(pullPattern|withdrawalQueue|pendingClaim|claimable\\[|escrow(Collateral|NFT)|\\btry\\s+\\w+\\.(safeTransferFrom|safeTransfer))'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — liquidation-nft-transfer-back-receiver-revert: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
