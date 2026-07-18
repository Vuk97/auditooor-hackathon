"""
bridge-erc20-burn-uses-owner-as-source-not-caller — generated from reference/patterns.dsl/bridge-erc20-burn-uses-owner-as-source-not-caller.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-erc20-burn-uses-owner-as-source-not-caller.yaml
Source: auditooor-R75-c4-mined-2023-12-autonolas-89
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeErc20BurnUsesOwnerAsSourceNotCaller(AbstractDetector):
    ARGUMENT = "bridge-erc20-burn-uses-owner-as-source-not-caller"
    HELP = "A bridged ERC20's `burn(amount)` is gated by `onlyOwner` (the bridge mediator) but then calls `_burn(msg.sender, amount)` — burning from the bridge mediator's own balance, not from the user initiating the L2→L1 withdrawal. Result: every L2→L1 transfer attempt reverts because the bridge mediator has "
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-erc20-burn-uses-owner-as-source-not-caller.yaml"
    WIKI_TITLE = "BridgedERC20 burn() uses msg.sender (owner) instead of user, L2→L1 withdrawals revert"
    WIKI_DESCRIPTION = "BridgedERC20 is owned by the bridge mediator. When a user bridges tokens back to L1, the mediator calls `token.burn(amount)`. Implementation: `function burn(uint256 amount) { if (msg.sender != owner) revert OwnerOnly(); _burn(msg.sender, amount); }`. The `_burn` target is `msg.sender` = the mediator. The mediator holds no balance (tokens live in users' wallets on L2), so _burn reverts with ERC20In"
    WIKI_EXPLOIT_SCENARIO = "User bridges 1000 OLAS from Gnosis (L2) back to Ethereum (L1). UI calls `BridgeMediator.bridgeBack(user, 1000)`. Mediator calls `BridgedOLAS.burn(1000)` from itself. burn() checks onlyOwner (passes, mediator is owner) then `_burn(address(this), 1000)` → mediator balance is 0 → revert ERC20InsufficientBalance. Every user who tries to bridge back gets the same revert. Withdrawal channel is dead; tok"
    WIKI_RECOMMENDATION = "Refactor to `burn(address account, uint256 amount) external onlyOwner { _burn(account, amount); }`. Mediator passes the user's L2 address when burning on behalf of a withdrawal. Canonical test: deploy, mint 100 to user, mediator calls burn(user, 100), user's balance must be 0 and totalSupply must de"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'BridgedERC20|BridgedToken|L2Token'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(burn|bridgeBack|sendBack|withdraw)$'}, {'function.body_contains_regex': 'msg\\.sender\\s*!=\\s*owner|onlyOwner'}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.body_contains_regex': '_burn\\s*\\(\\s*msg\\.sender'}, {'function.body_not_contains_regex': '(_burn\\s*\\(\\s*_?account|_burn\\s*\\(\\s*_?from|_burn\\s*\\(\\s*\\w+Sender\\s*,|function\\s+burn\\s*\\(\\s*address\\s+)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — bridge-erc20-burn-uses-owner-as-source-not-caller: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
