"""
token-transfer-to-self-no-recovery-path — generated from reference/patterns.dsl/token-transfer-to-self-no-recovery-path.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py token-transfer-to-self-no-recovery-path.yaml
Source: auditooor-R78-polymarket-WrappedCollateral
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class TokenTransferToSelfNoRecoveryPath(AbstractDetector):
    ARGUMENT = "token-transfer-to-self-no-recovery-path"
    HELP = "Token contract accepts transfers to its own address (address(this)) without a guard AND lacks an admin recovery function. Mistyped user transfers to the contract address are unrecoverable."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/token-transfer-to-self-no-recovery-path.yaml"
    WIKI_TITLE = "Token contract accepts transfers to self but has no rescue path — user mistakes permanent"
    WIKI_DESCRIPTION = "ERC-20 / ERC-1155 tokens often accept transfers where `to == address(this)` because `_transfer(from, to, amount)` has no recipient check. If the token contract also lacks an admin rescue function for tokens mistakenly sent to its own address, user typos result in permanent losses. Common for wrapped tokens, vault receipts, and LP tokens that integrators type-deref."
    WIKI_EXPLOIT_SCENARIO = "User meant to transfer 1000 wcol to the NegRiskAdapter but typoed the recipient to the WrappedCollateral contract itself. 1000 wcol is burned-pending from their balance to the contract. No onERC20Received rejects this (ERC-20 doesn't have the hook). No admin recovery function exists. The 1000 wcol is stuck; the underlying 1000 USDC backing it stays locked but unredeemable."
    WIKI_RECOMMENDATION = "Add (a) a `require(to != address(this))` in the transfer hook, (b) a `recoverStuck(address recipient, uint256 amount)` admin-only function, or (c) both. The check-at-transfer is safest."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)ERC20|_transfer|_burn|_mint'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(wrap|unwrap|transfer|transferFrom|recover|rescue|sweep)$'}, {'function.body_not_contains_regex': '(?i)(to\\s*!=\\s*address\\s*\\(\\s*this\\s*\\)|require\\s*\\(\\s*_?to\\s*!=\\s*address\\s*\\(\\s*this\\s*\\))'}, {'function.has_high_level_call_named': '(?i)_(burn|mint|transfer)'}, {'contract.has_no_function_body_matching': '(?i)(function\\s+(recover|rescueStuck|sweepStuck|retrieveMisdirected)[A-Z])'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — token-transfer-to-self-no-recovery-path: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
