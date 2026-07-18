"""
aggregator-user-executor-unrestricted-call — generated from reference/patterns.dsl/aggregator-user-executor-unrestricted-call.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py aggregator-user-executor-unrestricted-call.yaml
Source: defihacklabs/2025-09-Kame
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AggregatorUserExecutorUnrestrictedCall(AbstractDetector):
    ARGUMENT = "aggregator-user-executor-unrestricted-call"
    HELP = "DEX-aggregator swap() takes user-supplied executor + executeParams and forwards an arbitrary call. Combined with a shared token-approve contract, any user's existing approval to the aggregator is drainable by anyone invoking swap with crafted executeParams."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/aggregator-user-executor-unrestricted-call.yaml"
    WIKI_TITLE = "Aggregator forwards call to user-supplied executor with user-supplied calldata"
    WIKI_DESCRIPTION = "A classic DEX aggregator anti-pattern: the aggregator exposes `swap(params)` where `params.executor` is caller-chosen and `params.executeParams` is opaque calldata. After pulling `params.amount` of `params.srcToken` from msg.sender via a privileged TokenApprove contract, the aggregator does `executor.call(executeParams)`. Because the executor is not an allow-listed pool and executeParams is unchec"
    WIKI_EXPLOIT_SCENARIO = "Kame aggregator (Sep 2025, 18k USD loss): attacker sets `srcToken = syUSD, dstToken = syUSD, amount = 0, executor = USDC, executeParams = abi.encodeWithSignature('transferFrom(address,address,uint256)', victim, attacker, victim.usdcBalance)`. The aggregator pulls 0 syUSD (noop), then does `USDC.call(executeParams)`. USDC's transferFrom runs against the TokenApprove contract's allowance to USDC — d"
    WIKI_RECOMMENDATION = "Either (a) allow-list executors to a known set of on-chain pools, or (b) decode and validate executeParams shape so it cannot be a transferFrom whose `from` is an arbitrary user. Never let `executor == ERC20 token` pass."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Aggregat|Router|executor|ExecuteParams'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(swap|_swap|execute|route|aggregate)'}, {'function.has_param_name_matching': '(executor|callbackTarget|target|spender)'}, {'function.has_param_of_type': 'bytes'}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.body_contains_regex': '\\w*executor\\w*\\.call\\s*\\(|\\w*target\\w*\\.call\\s*\\(|\\.delegatecall\\s*\\('}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*allowedExecutor|whitelisted|allowedTarget|require\\s*\\(\\s*\\w+executor\\s*==|require\\s*\\(\\s*\\w*target\\s*==|executor\\s*!=\\s*address\\s*\\(\\s*this'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — aggregator-user-executor-unrestricted-call: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
