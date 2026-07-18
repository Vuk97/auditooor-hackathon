"""
glider-approve-arbitrary-spender — generated from reference/patterns.dsl/glider-approve-arbitrary-spender.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-approve-arbitrary-spender.yaml
Source: hexens-glider/detect-approve-calls-where-spender-is-arbitrary
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderApproveArbitrarySpender(AbstractDetector):
    ARGUMENT = "glider-approve-arbitrary-spender"
    HELP = "Public function accepts an arbitrary spender address and approves it for the contract's own ERC-20 balance. Attacker supplies their own address, gets approval, and then pulls the tokens via a separate `transferFrom`. Classic aggregator-integration footgun."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-approve-arbitrary-spender.yaml"
    WIKI_TITLE = "Approve called with user-controlled spender: token drain"
    WIKI_DESCRIPTION = "When a contract integrates with an aggregator / router, it often approves the aggregator for its own held tokens before calling the aggregator's swap endpoint. If the aggregator address is user-supplied (or reachable via user-supplied calldata), the attacker can nominate themselves as the 'aggregator', collect approval for the contract's full balance, and then drain via `transferFrom` in a follow-"
    WIKI_EXPLOIT_SCENARIO = "Vault exposes `swapVia(address router, bytes calldata data) external` which calls `token.approve(router, type(uint256).max)` before delegating the swap to `router.call(data)`. Attacker calls `vault.swapVia(attacker, emptyData)`. The vault approves `attacker` for its entire token balance; the subsequent `call` is a no-op because `attacker` is an EOA. Attacker then calls `token.transferFrom(vault, a"
    WIKI_RECOMMENDATION = "Maintain an `approvedRouters` / `trustedSpenders` whitelist set by governance and validate the user-supplied address against it: `require(approvedRouters[router], \"router not approved\")`. Additionally, approve only the exact amount needed (`approve(router, amount)` rather than `type(uint256).max`)"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'approve|safeApprove|forceApprove'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_param_of_type': 'address'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.body_contains_regex': '\\.approve\\s*\\(\\s*(?:spender|router|target|to|recipient|callee|exchange|dex)\\s*,|safeApprove\\s*\\(\\s*(?:spender|router|target|to|recipient|callee|exchange|dex)\\s*,|forceApprove\\s*\\(\\s*(?:spender|router|target|to|recipient|callee|exchange|dex)\\s*,'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*(?:whitelist|allowed|trusted|approved[Rr]outers?|approved[Ss]penders?)\\[|onlyOwner|onlyAdmin|hasRole'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-approve-arbitrary-spender: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
