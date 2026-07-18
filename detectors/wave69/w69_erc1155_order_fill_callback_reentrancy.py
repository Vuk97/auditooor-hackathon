"""
w69-erc1155-order-fill-callback-reentrancy — generated from reference/patterns.dsl/w69-erc1155-order-fill-callback-reentrancy.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py w69-erc1155-order-fill-callback-reentrancy.yaml
Source: W69 Phase-E weak-class recall lift - production marketplace order-fill shape
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class W69Erc1155OrderFillCallbackReentrancy(AbstractDetector):
    ARGUMENT = "w69-erc1155-order-fill-callback-reentrancy"
    HELP = "ERC1155 order-fill routine calls safeTransferFrom before writing filled/order status; receiver callback can reenter cross-contract before order accounting is committed."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/w69-erc1155-order-fill-callback-reentrancy.yaml"
    WIKI_TITLE = "ERC1155 fill transfers before order accounting"
    WIKI_DESCRIPTION = "Marketplace and conditional-token exchange fill paths often transfer ERC1155 inventory to the buyer before marking the order filled. Because ERC1155 safeTransferFrom invokes receiver code, a buyer-controlled receiver can reenter the exchange while the order still appears fillable and perturb fills, fees, or cancellation state. This row intentionally keys on the order-fill shape: safeTransferFrom p"
    WIKI_EXPLOIT_SCENARIO = "ERC1155 order-fill routine calls safeTransferFrom before writing filled/order status; receiver callback can reenter cross-contract before order accounting is committed."
    WIKI_RECOMMENDATION = "Commit fill/accounting state before the ERC1155 receiver callback or guard the fill entrypoints with nonReentrant. Prefer loop-local accounting over post-callback storage reads."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(ERC1155|safeTransferFrom|onERC1155Received|OrderFilled|filledAmount|orderStatus)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(?i)^_?(fill|match|execute|buy|purchase).*(Order|Listing|Sale)?'}, {'function.body_ordered_regex': {'first': 'safeTransferFrom\\s*\\([^;]*\\)', 'second': '(filledAmount|remainingAmount|orderStatus|isFilled|filledOrders|cancelled)\\s*(?:\\[[^\\]]+\\])?\\s*(?:=|\\+=|-=)|emit\\s+OrderFilled', 'ignore_comments_and_strings': True}}, {'function.body_not_contains_regex': '(?i)\\bnonReentrant\\b|ReentrancyGuard|_reentrancyGuardEntered|_status\\s*=\\s*_ENTERED|locked\\s*=\\s*true'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — w69-erc1155-order-fill-callback-reentrancy: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
