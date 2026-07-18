"""
balance-check-missing-on-action — generated from reference/patterns.dsl/balance-check-missing-on-action.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py balance-check-missing-on-action.yaml
Source: solodit-cluster-C0000
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BalanceCheckMissingOnAction(AbstractDetector):
    ARGUMENT = "balance-check-missing-on-action"
    HELP = "Action function (withdraw/transfer/debit/burn/redeem) decrements a user's balance without verifying balance >= amount — silent underflow on solc < 0.8 or uninformative revert-DoS on >= 0.8."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/balance-check-missing-on-action.yaml"
    WIKI_TITLE = "Missing balance-sufficiency check on balance-decrementing action"
    WIKI_DESCRIPTION = "A public/external function named withdraw, transfer, debit, burn, or redeem writes to a per-user balance mapping but contains no `require(balance[user] >= amount)` or equivalent `if (balance < amount) revert …` guard. On Solidity < 0.8.0 this is a direct arithmetic-underflow vulnerability that wraps the user's balance to 2^256-1 and lets the attacker drain the contract. On >= 0.8.0 the subtraction"
    WIKI_EXPLOIT_SCENARIO = "Contract stores `mapping(address => uint256) public balance` and exposes `function withdraw(uint256 amount) external { balance[msg.sender] -= amount; payable(msg.sender).transfer(amount); }`. Under solc 0.7.x, a user with zero balance calls `withdraw(1)`: the subtraction underflows to `type(uint256).max`, the transfer line drains the contract, and subsequent users cannot withdraw. Under solc 0.8.x"
    WIKI_RECOMMENDATION = "Add an explicit guard at the top of every balance-decrementing action: `require(balance[msg.sender] >= amount, \"INSUFFICIENT_BALANCE\")` or a custom error (`if (balance[msg.sender] < amount) revert InsufficientBalance(balance[msg.sender], amount);`). Prefer a named custom error so callers can decod"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'balance|balances|account|accounts'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'withdraw|transfer|debit|burn|_burn|redeem|subtract'}, {'function.writes_storage_matching': 'balance|balances|account'}, {'function.body_not_contains_regex': 'require\\s*\\(.*balance\\[.*>=|require\\s*\\(.*>=\\s*amount|if\\s*\\(.*balance.*<\\s*amount.*revert'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — balance-check-missing-on-action: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
