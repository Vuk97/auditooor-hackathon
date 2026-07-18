"""
checkpoint-getat-block-ambiguous-read — generated from reference/patterns.dsl/checkpoint-getat-block-ambiguous-read.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py checkpoint-getat-block-ambiguous-read.yaml
Source: phase-33-novel-surfacer-triangle-entries-getatblock-block
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CheckpointGetatBlockAmbiguousRead(AbstractDetector):
    ARGUMENT = "checkpoint-getat-block-ambiguous-read"
    HELP = "checkpoint-getat-block-ambiguous-read"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/checkpoint-getat-block-ambiguous-read.yaml"
    WIKI_TITLE = "checkpoint-getat-block-ambiguous-read"
    WIKI_DESCRIPTION = "checkpoint-getat-block-ambiguous-read"
    WIKI_EXPLOIT_SCENARIO = "checkpoint-getat-block-ambiguous-read"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(checkpoints|_checkpoints|Checkpoint|ERC20Votes|ERC721Votes|Votes)'}, {'function.kind': 'external_or_public'}, {'function.name_matches': '^(getPastVotes|getPastTotalSupply|getAtBlock|getVotesAt|balanceOfAt|votingPowerAt|getPriorVotes|checkpointAt)$'}, {'function.body_matches_regex': '(?i)(checkpoints\\s*\\[|_checkpoints\\s*\\[)'}, {'function.body_matches_regex': '(?i)(binarySearch|findUpperBound|_upperBinaryLookup|_checkpointsLookup|upperLookup)'}, {'function.not_body_matches_regex': '(?i)(BLOCK_FINALIZED|require\\s*\\(\\s*block\\.number\\s*>|_validateBlock|finalisedBlock|finalizedBlock|block\\.number\\s*-\\s*1\\s*>=)'}, {'function.not_source_matches_regex': '(?i)(mock|test|fixture|t\\.sol$)'}]
    _MATCH = [{'function.body_contains_regex': '(?i)(blockNumber|timepoint|_timepoint\\b)'}, {'function.body_contains_regex': '(?i)(return\\s+checkpoints|return\\s+_checkpoints|\\.votes\\b|\\._value\\b|\\.amount\\b)'}]

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
                info = [f, f" — checkpoint-getat-block-ambiguous-read: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
