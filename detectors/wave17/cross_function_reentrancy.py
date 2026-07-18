"""
cross-function-reentrancy — generated from reference/patterns.dsl/cross-function-reentrancy.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py cross-function-reentrancy.yaml
Source: auditooor-M14-the-dao-2016-cross-function-reentrancy
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CrossFunctionReentrancy(AbstractDetector):
    ARGUMENT = "cross-function-reentrancy"
    HELP = "Function transfers ETH/tokens to caller and only AFTER the call updates a balance-class storage slot, while a sibling function on the same contract also reads/writes that same balance. Classic cross-function reentrancy (The DAO, 2016): an attacker fallback reenters through the sibling and observes /"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/cross-function-reentrancy.yaml"
    WIKI_TITLE = "Cross-function reentrancy: balance updated after external call, sibling function reads same balance"
    WIKI_DESCRIPTION = "DAO-style cross-function reentrancy. A withdraw/claim/refund/split-class function performs an external value transfer (ETH `.call{value:}` / `.transfer` / token `safeTransfer`) BEFORE writing the user's balance-class storage slot to zero (or decrementing it). A SIBLING function on the SAME contract — typically the depositor-side accounting (`transferFrom`, `move`, `setBalance`) or another withdraw"
    WIKI_EXPLOIT_SCENARIO = "(1) Victim contract `Bank` has `function withdraw() external { uint256 bal = balances[msg.sender]; (bool ok,) = msg.sender.call{value: bal}(''); require(ok); balances[msg.sender] = 0; }` AND `function transfer(address to, uint256 amount) external { balances[msg.sender] -= amount; balances[to] += amount; }`. (2) Attacker deposits 1 ETH; `balances[attacker] = 1 ether`. (3) Attacker calls `withdraw()"
    WIKI_RECOMMENDATION = "(1) Strict Checks-Effects-Interactions: zero / decrement the balance-class storage slot BEFORE the external transfer. (2) Apply OpenZeppelin's `ReentrancyGuard` to BOTH the externally-calling leg AND every sibling that reads or writes the same balance-class state — a single guarded function does not"

    _PRECONDITIONS = [{'contract.has_function_matching': '(?i)(withdraw|claim|payout|refund|split|exit|cashOut|drain|sweep|harvest)[A-Za-z0-9_]*'}, {'contract.has_function_body_matching': '(?i)(balances?|shares?|deposits?|stakes?|credits?|principal|userBalance|accountBalance|rewardOf)\\s*\\[[^\\]]+\\]\\s*(=|-=|\\+=)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '(?i)^(withdraw|claim|payout|refund|split|exit|cashOut|drain|sweep|harvest|getReward|claimReward|requestWithdrawal|withdrawReward|withdrawRewardFor|payOut|reclaim)[A-Za-z0-9_]*$'}, {'function.has_external_call': True}, {'function.body_contains_regex': '(?i)\\.call\\s*\\{\\s*value\\s*:|\\.call\\.value\\s*\\(|\\.send\\s*\\(|\\.transfer\\s*\\(|safeTransfer(From)?\\s*\\(|sendValue\\s*\\('}, {'function.has_high_level_call_named': '(?i)^(transfer|transferFrom|safeTransfer|safeTransferFrom|send|sendValue|call)$'}, {'function.post_external_call_mutates_state': True}, {'function.reads_storage_matching': '(?i)(balance|share|deposit|stake|credit|principal|reward)'}, {'function.has_modifier': {'includes': ['nonReentrant', 'reentrancyGuard', 'lock', 'noReentrancy', 'nonreentrant'], 'negate': True}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — cross-function-reentrancy: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
