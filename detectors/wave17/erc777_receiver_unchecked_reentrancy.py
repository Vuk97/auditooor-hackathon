"""
erc777-receiver-unchecked-reentrancy — generated from reference/patterns.dsl/erc777-receiver-unchecked-reentrancy.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc777-receiver-unchecked-reentrancy.yaml
Source: solodit-cluster-cross-cluster-erc777
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc777ReceiverUncheckedReentrancy(AbstractDetector):
    ARGUMENT = "erc777-receiver-unchecked-reentrancy"
    HELP = "ERC-20 transferFrom is followed by state mutation with no nonReentrant guard — an ERC-777 implementation re-enters via tokensReceived / tokensToSend."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc777-receiver-unchecked-reentrancy.yaml"
    WIKI_TITLE = "ERC-777 receiver reentrancy: ERC-20 transferFrom path lacks nonReentrant"
    WIKI_DESCRIPTION = "ERC-777 is wire-compatible with ERC-20 but inserts a synchronous `tokensToSend` (sender) and `tokensReceived` (recipient) callback registered via ERC-1820. Any contract that handles ERC-20 via `transferFrom` — and later mutates state after that call — can be re-entered by a malicious ERC-777 token whose hook calls back into the protocol. Because the ERC-20 ABI is identical, such tokens pass most p"
    WIKI_EXPLOIT_SCENARIO = "A pool whose `deposit()` calls `token.transferFrom(msg.sender, address(this), amount)` and THEN updates `shares[msg.sender] += amount` is called with an ERC-777 token. Inside transferFrom, the token invokes `tokensToSend` on the sender; the attacker's hook re-enters `deposit()` (or `withdraw()`) to observe a half-updated state. The attacker inflates share balance or double-withdraws escrow before "
    WIKI_RECOMMENDATION = "Apply OpenZeppelin ReentrancyGuard (`nonReentrant`) on every external entrypoint that transfers tokens — or strictly reorder to Checks-Effects-Interactions so no state write follows the transfer. If the token set is restricted, ensure the allowlist excludes ERC-777 by interface detection (ERC-1820 r"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Pool|Vault|Pair|Router|Lending|Staking|Farm|MasterChef|Reward|Escrow|Custody|safeTransferFrom|transferFrom|IERC20|SafeERC20)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(deposit|withdraw|stake|unstake|swap|swapExact|addLiquidity|removeLiquidity|borrow|repay|mint|burn|claim|redeem|flashLoan|exchange|enter|exit|wrap|unwrap)\\w*$'}, {'function.has_external_call': True}, {'function.post_external_call_mutates_state': True}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': 'safeTransferFrom|\\.transferFrom\\s*\\('}, {'function.has_modifier': {'includes': ['nonReentrant', 'reentrancyGuard'], 'negate': True}}, {'function.not_source_matches_regex': '(super\\.deposit|super\\.withdraw|view\\s+returns|pure\\s+returns|_assertNotERC777|IERC1820Registry|getInterfaceImplementer|WETH9\\.deposit|require\\s*\\(\\s*token\\s*==\\s*WETH)'}]

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
                info = [f, f" — erc777-receiver-unchecked-reentrancy: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
