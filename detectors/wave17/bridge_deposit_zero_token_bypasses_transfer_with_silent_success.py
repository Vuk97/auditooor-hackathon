"""
bridge-deposit-zero-token-bypasses-transfer-with-silent-success — generated from reference/patterns.dsl/bridge-deposit-zero-token-bypasses-transfer-with-silent-success.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-deposit-zero-token-bypasses-transfer-with-silent-success.yaml
Source: auditooor-R76-rekt-qubit-2022
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeDepositZeroTokenBypassesTransferWithSilentSuccess(AbstractDetector):
    ARGUMENT = "bridge-deposit-zero-token-bypasses-transfer-with-silent-success"
    HELP = "Bridge `deposit(token, amount)` does not reject `token == address(0)`. A zero-address deposit makes the `IERC20(0).safeTransferFrom` call silently succeed, so off-chain relayers credit the user with a wrapped asset on the destination chain for free."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-deposit-zero-token-bypasses-transfer-with-silent-success.yaml"
    WIKI_TITLE = "Bridge ERC20 deposit accepts token=address(0), pulling no funds but still emitting a Deposit event"
    WIKI_DESCRIPTION = "Bridges with a generic ERC20 deposit path typically call `IERC20(token).safeTransferFrom(msg.sender, address(this), amount)`. On many EVMs, calling an ERC20 function on a zero-address target does NOT revert — the low-level call to no-code address returns empty success. The bridge then emits `Deposit(token=0, amount, to)` which the relayer picks up and mints corresponding wrapped tokens on the dest"
    WIKI_EXPLOIT_SCENARIO = "Attacker calls `deposit(address(0), 1e22, attackerOnBsc)` on Ethereum. `IERC20(0).safeTransferFrom(...)` returns success silently (no revert on zero-code target under OpenZeppelin's SafeERC20 when no return data is checked for an EOA). Contract emits `Deposit(address(0), 1e22, attackerOnBsc)`. BSC-side relayer mints 10000 qXETH to attacker. Attacker uses qXETH as collateral in Qubit lending, borro"
    WIKI_RECOMMENDATION = "Reject `token == address(0)` explicitly at the start of the generic deposit function: `require(token != address(0), 'use depositETH');`. Maintain an explicit allow-list of bridgeable tokens and check `isAllowedToken(token)` before the transfer. For extra safety, verify the pulled balance delta (`bal"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, 'Bridge has a generic ERC20 deposit entrypoint that lists the deposit token in calldata and does not filter the zero-address (meant to represent native ETH).']
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)^deposit$|depositERC20|lockToken|bridgeToken|lockAndSend'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': '(?i)safeTransferFrom|transferFrom\\s*\\(|IERC20\\(\\s*tokenAddress\\s*\\)|IERC20\\(\\s*token\\s*\\)'}, {'function.body_not_contains_regex': '(?i)require\\s*\\(\\s*tokenAddress\\s*!=\\s*address\\(0\\)|require\\s*\\(\\s*token\\s*!=\\s*address\\(0\\)|token\\s*==\\s*NATIVE_TOKEN|isAllowedToken\\s*\\(\\s*token|tokenAllowlist'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — bridge-deposit-zero-token-bypasses-transfer-with-silent-success: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
