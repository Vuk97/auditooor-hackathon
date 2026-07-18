"""
order-matched-flag-uses-owner-equal-zero — generated from reference/patterns.dsl/order-matched-flag-uses-owner-equal-zero.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py order-matched-flag-uses-owner-equal-zero.yaml
Source: solodit/sherlock/bullvbear-H2-3708
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OrderMatchedFlagUsesOwnerEqualZero(AbstractDetector):
    ARGUMENT = "order-matched-flag-uses-owner-equal-zero"
    HELP = "'Order already matched' is inferred from a mapping value being non-zero, but a user-facing `transferPosition` can write `address(0)` back to that slot, re-opening the order for matching. Attacker drains counterparties by re-matching the same order."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/order-matched-flag-uses-owner-equal-zero.yaml"
    WIKI_TITLE = "Matched-order flag aliased with owner mapping — transfer-to-zero resets it"
    WIKI_DESCRIPTION = "The order book encodes two pieces of state into one mapping slot: 'order still open' (slot == 0) and 'current position owner' (slot == owner address). A `transferPosition` / `reassign` helper lets the owner write an arbitrary address, including `address(0)`. After a match, attacker transfers to zero, the sentinel collapses back to 'open', and the original limit order can be filled again. Each re-m"
    WIKI_EXPLOIT_SCENARIO = "Bear places a limit order with orderHash H, signed to let anyone match by sending premium P. Bull matches: `matchOrder(H)` checks `bulls[H] == address(0)` (true), pulls P from bear, writes `bulls[H] = bull`. Bull calls `transferPosition(H, address(0))`. `bulls[H]` is now zero again. Bull re-matches: pulls another P from bear. Repeat until bear's allowance is exhausted."
    WIKI_RECOMMENDATION = "Track 'matched' in a separate `mapping(bytes32 => bool) matched;` that can only transition false -> true and is never touched by transfer paths. Additionally, revert in `transferPosition` when `to == address(0)` to eliminate the canonical abuse path. Treat ownership and liveness as disjoint concerns"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_param_of_type': 'address'}, {'function.body_contains_regex': '(transfer|setOwner|setRecipient|reassign|changeOwner)'}, {'function.body_contains_regex': '\\w+s?\\s*\\[\\s*(orderHash|hash|id|positionId|tokenId)\\s*\\]\\s*=\\s*(to|newOwner|recipient|address\\s*\\(\\s*0\\s*\\))'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*(to|newOwner|recipient)\\s*!=\\s*address\\s*\\(\\s*0\\s*\\)'}, {'contract.has_func_body_matching': 'require\\s*\\(\\s*\\w+\\[\\s*(orderHash|hash|id|positionId|tokenId)\\s*\\]\\s*==\\s*address\\s*\\(\\s*0\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — order-matched-flag-uses-owner-equal-zero: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
