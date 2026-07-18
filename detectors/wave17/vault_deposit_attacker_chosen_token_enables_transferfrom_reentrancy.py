"""
vault-deposit-attacker-chosen-token-enables-transferfrom-reentrancy — generated from reference/patterns.dsl/vault-deposit-attacker-chosen-token-enables-transferfrom-reentrancy.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py vault-deposit-attacker-chosen-token-enables-transferfrom-reentrancy.yaml
Source: auditooor-R76-rekt-grim-finance-2021
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class VaultDepositAttackerChosenTokenEnablesTransferfromReentrancy(AbstractDetector):
    ARGUMENT = "vault-deposit-attacker-chosen-token-enables-transferfrom-reentrancy"
    HELP = "Vault `depositFor(token, ...)` uses an arbitrary caller-supplied token as its external-call target without a reentrancy guard. Attacker passes a malicious token whose transferFrom re-enters the same function multiple times before share accounting resolves."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/vault-deposit-attacker-chosen-token-enables-transferfrom-reentrancy.yaml"
    WIKI_TITLE = "Vault deposit accepts arbitrary token, enabling transferFrom-callback reentrancy"
    WIKI_DESCRIPTION = "When a vault's deposit function is written `depositFor(address token, uint256 amount, address to)` and uses `token.safeTransferFrom(msg.sender, address(this), amount)` as its external call, an attacker can supply a malicious contract as `token`. That contract's transferFrom can reenter `depositFor` any number of times before the share-minting code runs, each time inflating `totalDeposited` without"
    WIKI_EXPLOIT_SCENARIO = "Attacker deploys MaliciousToken. `MaliciousToken.transferFrom(from, to, amount)` calls `Vault.depositFor(MaliciousToken, amount, attacker)` N-1 more times, then returns true. Each reentry sees `balanceBefore = 0` and `balanceAfter = amount`, so `shares = amount * totalSupply / oldTotalAssets`. Because totalSupply and totalAssets are updated only after the outermost call returns, each inner mint us"
    WIKI_RECOMMENDATION = "Restrict deposits to the vault's canonical want/underlying token: `require(token == want, 'bad token');`. If a multi-token deposit adapter is needed, implement it as a separate contract with an explicit allow-list of supported assets. Always add `nonReentrant` to any function that performs an extern"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, 'Vault / strategy deposit function accepts a user-provided token address and uses it as the target of an external safeTransferFrom call before updating share balances.']
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)^depositFor|^depositToken|depositAny|depositWith|wrapDeposit'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': '(?i)safeTransferFrom|IERC20\\(\\s*(_token|token|tokenAddress)\\s*\\)\\.transferFrom'}, {'function.body_not_contains_regex': '(?i)nonReentrant|require\\s*\\(\\s*(_token|token)\\s*==\\s*(want|asset|underlying)|require\\s*\\(\\s*(_token|token)\\s*==\\s*address\\(want|allowedDepositToken'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — vault-deposit-attacker-chosen-token-enables-transferfrom-reentrancy: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
