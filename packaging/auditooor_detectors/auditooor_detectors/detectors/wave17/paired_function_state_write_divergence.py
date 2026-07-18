"""
paired-function-state-write-divergence — generated from reference/patterns.dsl/paired-function-state-write-divergence.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py paired-function-state-write-divergence.yaml
Source: code4arena/slice_ac-GTE-Spot-H03,Kinetiq-M03,Virtuals-H06
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PairedFunctionStateWriteDivergence(AbstractDetector):
    ARGUMENT = "paired-function-state-write-divergence"
    HELP = "Paired sibling entry points (single/batch, post/amend, enqueue/cancel) maintain divergent state-write invariants. One path writes a counter/guard, the other skips it — enabling bypass of per-tx limits, access control, or reward accrual."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/paired-function-state-write-divergence.yaml"
    WIKI_TITLE = "Paired entry-points (single vs batch / post vs amend) diverge on state writes"
    WIKI_DESCRIPTION = "Protocols that expose both single-operation and batch-variant (or place vs amend) entry points must maintain identical invariants across both. When the batch/amend path omits a counter update or access check that the single/post path enforces, attackers route through the weaker sibling. Classic examples: amendOrder skips maxLimitsPerTx, promptMulti forgets to update prevAgentId, cancelWithdrawal d"
    WIKI_EXPLOIT_SCENARIO = "GTE Spot (May 2025): placeOrder decrements maxLimitsPerTx, but amendOrder does not. Attacker fills one order per block using place, then amends each to bypass the per-tx limit — enabling DoS on a market's limit book."
    WIKI_RECOMMENDATION = "Factor shared invariants into a private helper both siblings call. Introduce a diff-style unit test: run each entry point and snapshot every storage slot written, assert every slot touched by `post` is also touched by `amend`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(amend|editOrder|multi|Batch|batch)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(amend|editOrder|_amend|promptMulti|executeBatch|batch)[A-Z_]?'}, {'function.body_contains_regex': 'orders\\s*\\[\\s*\\w+\\s*\\]\\s*=|position\\s*\\[|state\\s*\\[|prevAgentId\\s*='}, {'function.body_not_contains_regex': '_checkPerTxLimit|maxLimitsPerTx|limitsPerTx|assertLimit|prevAgentId\\s*=|_updatePrev'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — paired-function-state-write-divergence: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
