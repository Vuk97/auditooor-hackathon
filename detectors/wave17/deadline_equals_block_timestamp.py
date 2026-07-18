"""
deadline-equals-block-timestamp — generated from reference/patterns.dsl/deadline-equals-block-timestamp.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py deadline-equals-block-timestamp.yaml
Source: auditooor
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DeadlineEqualsBlockTimestamp(AbstractDetector):
    ARGUMENT = "deadline-equals-block-timestamp"
    HELP = "Deadline hard-coded to block.timestamp is always-satisfied and enforces no real expiry. Prefer block.timestamp + N or a user-supplied future timestamp so stale transactions can be rejected by the mempool."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/deadline-equals-block-timestamp.yaml"
    WIKI_TITLE = "Deadline equals block.timestamp: no actual deadline enforcement"
    WIKI_DESCRIPTION = "When a contract sets a deadline parameter to `block.timestamp` (or forwards `block.timestamp` into a downstream swap/permit deadline slot), the check `block.timestamp <= deadline` is satisfied by construction in every block the transaction could possibly land. The deadline exists in name only. This defeats the entire purpose of the deadline — which is to let a user's pending swap expire and become"
    WIKI_EXPLOIT_SCENARIO = "1) User calls a router's swap via a helper contract that passes `block.timestamp` as the deadline. 2) The transaction sits in the mempool; prices move adversely. 3) A validator or searcher selects a block where the movement is maximum for them (not the user) and includes the transaction. 4) The deadline check `block.timestamp <= block.timestamp` trivially passes. The user eats the worst realized p"
    WIKI_RECOMMENDATION = "Accept a `deadline` parameter from the caller (preferred: a concrete future timestamp the user's wallet signs over). If synthesizing on-chain, use `block.timestamp + MAX_DELAY` with a short, fixed window (30-300s). Never pass `block.timestamp` itself as the deadline argument to a downstream swap/per"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.body_contains_regex': 'deadline\\s*=\\s*block\\.timestamp\\b|deadline\\s*:\\s*block\\.timestamp\\b|,\\s*block\\.timestamp\\s*\\)'}, {'function.body_not_contains_regex': 'block\\.timestamp\\s*\\+|userDeadline|_deadline'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — deadline-equals-block-timestamp: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
