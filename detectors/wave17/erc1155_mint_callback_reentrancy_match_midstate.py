"""
erc1155-mint-callback-reentrancy-match-midstate — generated from reference/patterns.dsl/erc1155-mint-callback-reentrancy-match-midstate.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc1155-mint-callback-reentrancy-match-midstate.yaml
Source: auditooor-R48-polymarket-V1.C
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc1155MintCallbackReentrancyMatchMidstate(AbstractDetector):
    ARGUMENT = "erc1155-mint-callback-reentrancy-match-midstate"
    HELP = "Match/fill function mints or transfers ERC-1155 tokens (splitPosition / mergePositions / _mint / safeTransferFrom) and is NOT protected by a reentrancy guard. A malicious receiver can re-enter the same function via onERC1155Received, observe mid-match state (order not yet marked filled), and double-"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc1155-mint-callback-reentrancy-match-midstate.yaml"
    WIKI_TITLE = "ERC-1155 mint callback enables match-midstate reentrancy"
    WIKI_DESCRIPTION = "A match/fill/settle entry point in an exchange or prediction market performs an ERC-1155 mint or transfer (via `splitPosition`, `mergePositions`, direct `_mint`, or `safeTransferFrom`) to the taker / maker / position holder. ERC-1155 invokes `onERC1155Received` / `onERC1155BatchReceived` on contract recipients. If the function is NOT guarded by a reentrancy lock AND the order-fill marker is set AF"
    WIKI_EXPLOIT_SCENARIO = "Attacker registers a contract recipient M implementing `onERC1155Received` that calls back into `CTFExchange.fillOrder(...)` with the same order-hash but a different taker identity. Sequence: maker submits an order to SELL 1000 YES at $0.50. Attacker's own matching order triggers `fillOrder`. Inside, the exchange calls `splitPosition` which mints 1000 YES ERC-1155 to attacker — invoking M's `onERC"
    WIKI_RECOMMENDATION = "Add `nonReentrant` to every match/fill/settle entry point. Additionally, follow CEI: mark the order filled / increment the nonce / push to consumed-list BEFORE the mint/transfer that triggers the ERC-1155 callback. Both defences in tandem — the reentrancy lock handles the generic case; the CEI order"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'fillOrder|matchOrder|settleOrder|fillAndSettle|matchOrders|_fill|_match|_settle|executeOrder|execute'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': '(splitPosition|mergePositions|safeTransferFrom|safeBatchTransferFrom|_mint)\\s*\\('}, {'function.body_contains_regex': '(filledOrder|orderFilled|isFilled|_filled|fillStatus|ordersFilled)\\s*\\['}, {'function.has_modifier': {'includes': ['nonReentrant', 'nonreentrant', 'noReentrant'], 'negate': True}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — erc1155-mint-callback-reentrancy-match-midstate: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
