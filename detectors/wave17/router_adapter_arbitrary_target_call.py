"""
router-adapter-arbitrary-target-call — generated from reference/patterns.dsl/router-adapter-arbitrary-target-call.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py router-adapter-arbitrary-target-call.yaml
Source: defihacklabs/LiFi-2024-07+Socket-2024-01+Gamma-2024-01
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RouterAdapterArbitraryTargetCall(AbstractDetector):
    ARGUMENT = "router-adapter-arbitrary-target-call"
    HELP = "Router/adapter function accepts (target, data) and forwards `target.call(data)` with no target allowlist. Attackers can craft data=transferFrom(victim,...) to drain every user approval the router holds."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/router-adapter-arbitrary-target-call.yaml"
    WIKI_TITLE = "Router arbitrary-target call drains user approvals"
    WIKI_DESCRIPTION = "Aggregator/bridge contracts accumulate persistent ERC-20 approvals from users. If any external function accepts a user-controlled `target` and `data` and executes `target.call(data)`, an attacker can point `target` at any ERC-20 the router has approvals for and craft `data = transferFrom(victim, attacker, allowance)`. All approvals in the router become a drain surface."
    WIKI_EXPLOIT_SCENARIO = "LiFi 2024-07: attacker called `swap(...)` on LiFiDiamond with `swapData.callTo = USDT`, `swapData.callData = transferFrom(victimA, attacker, 1e10)`. LiFiDiamond forwarded the call; USDT saw LiFiDiamond as msg.sender which held pre-approved allowance from victimA. $10M drained across many victims over minutes."
    WIKI_RECOMMENDATION = "Maintain an allowlist of permitted call-targets (per-DEX-aggregator / per-bridge) and `require(approvedTargets[target])` before every forwarded call. Alternatively, use per-swap one-shot approvals (`approve(target, amount); call; approve(target, 0);`) with zero persistent approvals."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'IERC20|transferFrom|SafeERC20|allowance'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(swap|bridge|execute|forward|dispatch|route|aggregate|fill|call|multicall)[A-Z_]?|^(swap|bridge|execute|forward|dispatch|route|aggregate|fill)$'}, {'function.has_param_of_type': 'bytes'}, {'function.has_param_of_type': 'address'}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.body_contains_regex': '\\w+\\.call\\s*\\(|\\w+\\.delegatecall\\s*\\('}, {'function.body_not_contains_regex': 'approvedTarget|allowedTarget|isWhitelisted|require\\s*\\(\\s*\\w*[wW]hitelist|onlyApprovedAdapter|targetRegistry\\s*\\[|require\\s*\\(\\s*is\\w*Approved'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — router-adapter-arbitrary-target-call: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
