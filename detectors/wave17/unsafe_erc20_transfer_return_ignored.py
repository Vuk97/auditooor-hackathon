"""
unsafe-erc20-transfer-return-ignored — generated from reference/patterns.dsl/unsafe-erc20-transfer-return-ignored.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py unsafe-erc20-transfer-return-ignored.yaml
Source: auto-mined-from-diffs/added-safe-transfer-cluster
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UnsafeErc20TransferReturnIgnored(AbstractDetector):
    ARGUMENT = "unsafe-erc20-transfer-return-ignored"
    HELP = "External/public function calls ERC-20 transfer / transferFrom / approve without checking the return bool or using OpenZeppelin SafeERC20. Non-reverting tokens (USDT, BNB, OMG) that return false on failure cause silent accounting drift and insolvency."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/unsafe-erc20-transfer-return-ignored.yaml"
    WIKI_TITLE = "Unsafe ERC-20 transfer: return value ignored, SafeERC20 not used"
    WIKI_DESCRIPTION = "A state-mutating public function calls `token.transfer`, `token.transferFrom`, or `token.approve` directly and discards the returned `bool success`. The ERC-20 specification permits tokens to return `false` on failure instead of reverting — USDT is the widely cited example — which means a failed transfer is indistinguishable from success at the caller. Integrations of this shape exhibit two common"
    WIKI_EXPLOIT_SCENARIO = "A lending protocol's `withdraw` function calls `asset.transfer(msg.sender, amount)` without checking the bool return. The asset is USDT. A sanctioned address has been blacklisted by Tether; the transfer returns `false` but the contract decrements `balances[msg.sender] -= amount` before the call. The sanctioned address is repeatedly allowed to 'withdraw' on-paper, depleting the internal ledger whil"
    WIKI_RECOMMENDATION = "Import `@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol` and declare `using SafeERC20 for IERC20;` at the top of the contract. Replace every `token.transfer(...)` with `token.safeTransfer(...)`, `token.transferFrom(...)` with `token.safeTransferFrom(...)`, and `token.approve(...)` with `toke"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'IERC20|ERC20|SafeERC20|safeTransfer|\\btoken\\.transfer'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.not_slither_synthetic': True}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.has_high_level_call_named': 'transferFrom'}, {'function.body_contains_regex': '\\.transfer\\s*\\(|\\.transferFrom\\s*\\(|\\.approve\\s*\\('}, {'function.body_not_contains_regex': 'safeTransfer|safeTransferFrom|safeApprove|forceApprove|require\\s*\\([^;]*\\.transfer|require\\s*\\([^;]*\\.approve'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — unsafe-erc20-transfer-return-ignored: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
