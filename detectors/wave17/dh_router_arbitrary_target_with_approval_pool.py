"""
dh-router-arbitrary-target-with-approval-pool — generated from reference/patterns.dsl/dh-router-arbitrary-target-with-approval-pool.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py dh-router-arbitrary-target-with-approval-pool.yaml
Source: defihacklabs/LiFi-2024-07+Socket-2024-01+Gamma-2024-01
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DhRouterArbitraryTargetWithApprovalPool(AbstractDetector):
    ARGUMENT = "dh-router-arbitrary-target-with-approval-pool"
    HELP = "Router accepts (target, data) and executes low-level call while holding third-party ERC20 approvals — drain via forged transferFrom payload."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/dh-router-arbitrary-target-with-approval-pool.yaml"
    WIKI_TITLE = "Router arbitrary-target call with active approval pool"
    WIKI_DESCRIPTION = "When a contract holds ERC-20 allowances from users and also exposes a function that forwards a raw `call(data)` to a user-chosen target, attacker can set target = the approved token and data = `transferFrom(victim, attacker, amount)`. The token sees the router (approver) as msg.sender, authorising the transfer."
    WIKI_EXPLOIT_SCENARIO = "LiFi 2024-07 $10M, Socket Gateway 2024-01 $3.3M, Gamma 2024-01 $6.3M, Li.Fi-II, Paraswap patch, Hedgey claim. All share: (1) router has `setApprovalForAll` or stored allowances; (2) `swap(target, data)` or `dispatch(call)` does low-level call; (3) no allowlist of target contracts."
    WIKI_RECOMMENDATION = "Maintain an allowlist of permitted call targets (DEX factories, known routers). Never forward raw calldata to a user-supplied address while holding approvals. Alternative: pull assets from the user inside the same call rather than pre-approve."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'allowance|approve|transferFrom|IERC20'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_param_of_type': 'address'}, {'function.has_param_of_type': 'bytes'}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.body_contains_regex': '\\.call\\s*\\(\\s*[a-zA-Z_]+\\s*\\)|\\.call\\s*\\{[^}]*\\}\\s*\\(\\s*[a-zA-Z_]+\\s*\\)|\\.delegatecall\\s*\\(\\s*[a-zA-Z_]+\\s*\\)'}, {'function.body_not_contains_regex': 'allowedTargets|whitelistedTargets|_isApprovedTarget|targetWhitelist'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — dh-router-arbitrary-target-with-approval-pool: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
