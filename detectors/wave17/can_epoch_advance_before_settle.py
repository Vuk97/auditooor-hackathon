"""
can-epoch-advance-before-settle — generated from reference/patterns.dsl/can-epoch-advance-before-settle.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py can-epoch-advance-before-settle.yaml
Source: cantina/2024-2025-stakedao-gauge-epoch-race-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CanEpochAdvanceBeforeSettle(AbstractDetector):
    ARGUMENT = "can-epoch-advance-before-settle"
    HELP = "Epoch counter incremented BEFORE previous epoch's pending rewards/state is settled — claims after the advance read an empty new-epoch slot instead of their owed balance."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/can-epoch-advance-before-settle.yaml"
    WIKI_TITLE = "Epoch advance overwrites unsettled rewards"
    WIKI_DESCRIPTION = "Gauge / bribing / vote-escrow systems advance a per-round counter (epoch, period) whenever a user action crosses the round boundary. If the advance happens before the previous epoch's accumulator is flushed into claimant-addressable state, any user who claims after the advance (but for the prior epoch) reads the new epoch's zero-initialized slot. The pending reward is effectively deleted."
    WIKI_EXPLOIT_SCENARIO = "StakeDAO / Curve-gauge-family class: `notifyRewardAmount` advances `currentEpoch++` then writes the new epoch's accumulator, clobbering any unclaimed prev-epoch balance that lived at that index. A user who locked 100 veCRV in epoch N, missed the claim window, and attempts to claim in epoch N+1 reads `rewards[user][currentEpoch]` (= 0 for the new slot) instead of `rewards[user][N]`. Funds stuck; on"
    WIKI_RECOMMENDATION = "Always settle before advancing. Pattern: inside the rollover, iterate unclaimed users for the outgoing epoch and flush their accumulator into a claim queue, THEN increment the counter. Simpler: store per-epoch accumulators in a mapping keyed by epoch number and never overwrite — users claim from `re"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'epoch|currentEpoch|period|currentPeriod'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(claim|harvest|notifyReward|syncEpoch|rolloverEpoch|checkpoint|updateEpoch|_updateEpoch)'}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.body_contains_regex': '(currentEpoch|epoch|period|currentPeriod)\\s*(\\+\\+|=\\s*\\w+\\s*\\+\\s*1|=\\s*block\\.timestamp)'}, {'function.body_contains_regex': '(transfer|safeTransfer|_mint|rewards\\[|accumulator)'}, {'function.body_not_contains_regex': '_settle\\w*\\s*\\(|finalizeEpoch|settlePrevEpoch|epoch\\s*-\\s*1'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — can-epoch-advance-before-settle: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
