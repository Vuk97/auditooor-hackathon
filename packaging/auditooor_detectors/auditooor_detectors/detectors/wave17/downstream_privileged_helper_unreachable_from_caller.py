"""
downstream-privileged-helper-unreachable-from-caller — generated from reference/patterns.dsl/downstream-privileged-helper-unreachable-from-caller.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py downstream-privileged-helper-unreachable-from-caller.yaml
Source: auditooor-R75-c4-yield-2024-04-renzo-87
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DownstreamPrivilegedHelperUnreachableFromCaller(AbstractDetector):
    ARGUMENT = "downstream-privileged-helper-unreachable-from-caller"
    HELP = "Vault calls a helper on sibling contract that is gated onlyRestakeManager — but the caller is not the RestakeManager. Full withdrawal path DoSes when buffer > 0."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/downstream-privileged-helper-unreachable-from-caller.yaml"
    WIKI_TITLE = "OperatorDelegator calls onlyRestakeManager helper and bricks every withdrawal when buffer deficit > 0"
    WIKI_DESCRIPTION = "Multi-contract restaking stacks often have one hub contract (RestakeManager) that owns gated helpers on siblings (DepositQueue.fillERC20withdrawBuffer is `onlyRestakeManager`). A satellite contract (OperatorDelegator) calls that gated helper directly inside its withdrawal finalization path. Because the satellite is not the hub, the `onlyRestakeManager` check reverts — every completeQueuedWithdrawa"
    WIKI_EXPLOIT_SCENARIO = "OperatorDelegator.completeQueuedWithdrawal() checks `withdrawQueue.getBufferDeficit(token) > 0` and calls `restakeManager.depositQueue().fillERC20withdrawBuffer(token, amount)`. DepositQueue.fillERC20withdrawBuffer has `onlyRestakeManager`. Because `msg.sender == operatorDelegator != restakeManager`, the call reverts. Every stETH withdrawal fails until the buffer is manually topped up — which stil"
    WIKI_RECOMMENDATION = "Audit access control by call-graph: for every `onlyX` function, grep all cross-contract callers and verify `msg.sender` matches. In CI, generate a call-graph and flag any cross-contract edge whose destination has a modifier the source does not satisfy."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, 'contract.name_matches: (?i)(operator.*delegator|strategy.*manager)']
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(completeQueuedWithdrawal|completeWithdrawal|flushBuffer)'}, {'function.has_high_level_call_named': '(?i)^(fillBuffer|fillERC20withdrawBuffer|fillWithdrawBuffer|transferToQueue)$'}, {'function.body_contains_regex': '\\.(fillBuffer|fillERC20withdrawBuffer|fillWithdrawBuffer|transferToQueue)\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — downstream-privileged-helper-unreachable-from-caller: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
