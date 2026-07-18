"""
erc20-transferfrom-return-value-unchecked-usdt — generated from reference/patterns.dsl/erc20-transferfrom-return-value-unchecked-usdt.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc20-transferfrom-return-value-unchecked-usdt.yaml
Source: solodit-cluster/C0250
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc20TransferfromReturnValueUncheckedUsdt(AbstractDetector):
    ARGUMENT = "erc20-transferfrom-return-value-unchecked-usdt"
    HELP = "Protocol-level .transfer/.transferFrom on storage token var without SafeERC20 or return-value check — USDT pre-2018 and non-standard ERC20s break silently and desync accounting."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc20-transferfrom-return-value-unchecked-usdt.yaml"
    WIKI_TITLE = "Unchecked ERC20 transfer/transferFrom return on protocol storage token (USDT-sensitive)"
    WIKI_DESCRIPTION = "A production protocol function calls `.transfer(...)` or `.transferFrom(...)` directly on a canonical storage token variable (e.g. `token`, `asset`, `underlying`, `stakingToken`, `rewardToken`) and does not wrap the call with OpenZeppelin's SafeERC20 or a require on the bool return. USDT (pre-2018) and several widely-used non-standard ERC20s either revert on success, omit the bool return entirely,"
    WIKI_EXPLOIT_SCENARIO = "Protocol's `deposit(uint256 amt)` calls `token.transferFrom(msg.sender, address(this), amt)` and immediately increments the user's internal balance. The token is USDT-style and silently returns false because the user has zero allowance or balance. Protocol has credited the user as if they deposited while no USDT actually moved into the contract. The user then calls `withdraw(amt)` and drains real "
    WIKI_RECOMMENDATION = "Always wrap ERC20 interactions on production storage tokens with OpenZeppelin's SafeERC20 `safeTransfer` / `safeTransferFrom`. These helpers handle missing-return tokens and revert on false returns. If SafeERC20 cannot be imported, use the compile-time idiom `(bool ok, bytes memory data) = address(t"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.body_contains_regex': '(token|_token|asset|_asset|underlying|stakingToken|rewardToken)\\.\\s*transferFrom\\s*\\(|(token|_token|asset|_asset|underlying|stakingToken|rewardToken)\\.\\s*transfer\\s*\\('}, {'function.body_not_contains_regex': 'safeTransferFrom|safeTransfer\\s*\\(|SafeERC20|IERC20Permit|_safeTransfer'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — erc20-transferfrom-return-value-unchecked-usdt: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
