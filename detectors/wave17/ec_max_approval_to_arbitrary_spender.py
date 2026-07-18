"""
ec-max-approval-to-arbitrary-spender — generated from reference/patterns.dsl/ec-max-approval-to-arbitrary-spender.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ec-max-approval-to-arbitrary-spender.yaml
Source: economic-mining-R61
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcMaxApprovalToArbitrarySpender(AbstractDetector):
    ARGUMENT = "ec-max-approval-to-arbitrary-spender"
    HELP = "Function grants type(uint256).max ERC-20 approval to a non-constant address without whitelist check; compromised or attacker-controlled target can drain approved tokens."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ec-max-approval-to-arbitrary-spender.yaml"
    WIKI_TITLE = "Infinite ERC-20 approval to non-whitelisted address"
    WIKI_DESCRIPTION = "The function calls token.approve(target, type(uint256).max) where `target` is derived from a function parameter, storage variable, or computed value rather than a hardcoded constant. If the target address is ever compromised, upgraded maliciously, or is user-supplied, the infinite approval allows a single transferFrom call to drain the full token balance from this contract."
    WIKI_EXPLOIT_SCENARIO = "Protocol has approveAndSwap(address router, bytes calldata data). For each swap it approves router for max. Attacker supplies malicious router address — contract grants infinite approval. Attacker calls malicious router which calls IERC20(token).transferFrom(protocol, attacker, balance). Protocol drained."
    WIKI_RECOMMENDATION = "Only grant exact-amount approvals: `token.approve(router, amountIn)` instead of max. If gas efficiency requires persistent approvals, maintain a whitelist of trusted routers checked before approval. Use OpenZeppelin's SafeERC20.forceApprove only with immutable, audited integration addresses."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'approve|safeApprove|forceApprove|type.*uint256.*max'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.body_contains_regex': 'approve\\s*\\(.*type\\s*\\(\\s*uint256\\s*\\)\\s*\\.max|safeApprove\\s*\\(.*type\\s*\\(\\s*uint256\\s*\\)\\s*\\.max|forceApprove.*type.*max'}, {'function.body_contains_regex': 'approve\\s*\\(.*\\w+\\s*,\\s*type|approve\\s*\\(\\s*_\\w+'}, {'function.body_not_contains_regex': 'require\\s*\\(.*whitelist|isApprovedTarget|trustedRouter|TRUSTED'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ec-max-approval-to-arbitrary-spender: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
