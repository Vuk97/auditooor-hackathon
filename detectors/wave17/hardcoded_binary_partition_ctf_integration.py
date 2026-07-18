"""
hardcoded-binary-partition-ctf-integration — generated from reference/patterns.dsl/hardcoded-binary-partition-ctf-integration.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py hardcoded-binary-partition-ctf-integration.yaml
Source: auditooor-r112-polymarket-source-mine-AssetOperations._getPartition
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class HardcodedBinaryPartitionCtfIntegration(AbstractDetector):
    ARGUMENT = "hardcoded-binary-partition-ctf-integration"
    HELP = "ConditionalTokens helper hardcodes a 2-outcome partition [1, 2]. Multi-outcome conditions silently mint incomplete position sets or revert."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/hardcoded-binary-partition-ctf-integration.yaml"
    WIKI_TITLE = "Hardcoded binary partition in ConditionalTokens helper breaks multi-outcome markets"
    WIKI_DESCRIPTION = "Wrappers around Gnosis ConditionalTokens often expose a `_getPartition()` helper that returns a fixed `[1, 2]` partition for `splitPosition`/`mergePositions`. This is correct for binary markets (2 outcomes — YES/NO) but silently fails for any condition prepared with `outcomeSlotCount > 2`: `splitPosition` reverts on length-mismatch (or, if the partition's bit-set covers only 2 of N slots, mints an"
    WIKI_EXPLOIT_SCENARIO = "An exchange contract supports both 2-outcome and N-outcome (N>2) conditions via the same `_mint(conditionId, amount)` helper. The helper internally calls `_getPartition()` which returns `[1, 2]`. For a 3-outcome condition, the call to `IConditionalTokens.splitPosition(collateral, 0, conditionId, [1,2], amount)` either (a) reverts with `InvalidPartition()` (loss of liveness) or (b) on a permissive "
    WIKI_RECOMMENDATION = "Derive the partition from `IConditionalTokens.getOutcomeSlotCount(conditionId)` at call time: build a length-N array where `partition[i] = 1 << i`. Alternatively, gate the helper to refuse `conditionId`s whose outcomeSlotCount != 2 with a clear `BinaryConditionRequired()` revert."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)splitPosition|mergePositions|IConditionalTokens|conditionalTokens'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '(?i)_?getPartition|_?buildPartition|_?makePartition|_?defaultPartition'}, {'function.body_contains_regex': '(?i)mstore\\s*\\(\\s*\\w+\\s*,\\s*2\\s*\\)[\\s\\S]*?mstore[\\s\\S]*?,\\s*1\\s*\\)[\\s\\S]*?mstore[\\s\\S]*?,\\s*2\\s*\\)|partition\\[0\\]\\s*=\\s*1\\s*;[\\s\\S]*?partition\\[1\\]\\s*=\\s*2|new\\s+uint256\\[\\]\\(\\s*2\\s*\\)[\\s\\S]*?\\[0\\]\\s*=\\s*1[\\s\\S]*?\\[1\\]\\s*=\\s*2'}, {'function.body_not_contains_regex': '(?i)outcomeSlotCount|getOutcomeSlotCount|payoutNumerators|partitionLength|outcomeCount|slotCount\\s*\\(|conditionsToPositionIds|partition\\s*=\\s*new\\s+uint256\\[\\]\\s*\\(\\s*\\w+\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — hardcoded-binary-partition-ctf-integration: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
