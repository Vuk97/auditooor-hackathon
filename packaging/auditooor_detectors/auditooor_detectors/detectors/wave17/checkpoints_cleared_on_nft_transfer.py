"""
checkpoints-cleared-on-nft-transfer — generated from reference/patterns.dsl/checkpoints-cleared-on-nft-transfer.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py checkpoints-cleared-on-nft-transfer.yaml
Source: solodit-novel/slice_ac-NftCheckpoints
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CheckpointsClearedOnNftTransfer(AbstractDetector):
    ARGUMENT = "checkpoints-cleared-on-nft-transfer"
    HELP = "NFT transfer hook zeros or deletes the per-token vote-checkpoint history. Past votes become un-queryable; governance reconstructs wrong weights for historical proposals."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/checkpoints-cleared-on-nft-transfer.yaml"
    WIKI_TITLE = "NFT transfer deletes voting checkpoint history"
    WIKI_DESCRIPTION = "Checkpointed voting weight must be preserved for ALL historical blocks. A transfer hook that deletes or resets the `checkpoints[tokenId]` array destroys provenance — any proposal that snapshotted at a pre-transfer block silently reads wrong weights."
    WIKI_EXPLOIT_SCENARIO = "Voter delegates 100 votes, proposal snapshot taken at block N with 100 votes registered. Voter transfers NFT; transfer hook deletes checkpoints. Proposal execution reads voter's historical weight = 0, quorum fails."
    WIKI_RECOMMENDATION = "Use OpenZeppelin Votes pattern: append a new checkpoint on each transfer rather than deleting history."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'checkpoints|_checkpoints|Checkpoint'}]
    _MATCH = [{'function.kind': 'internal_or_public'}, {'function.name_matches': '^(_beforeTokenTransfer|_update|_afterTokenTransfer|transferFrom|_transfer)'}, {'function.body_contains_regex': '(checkpoints|_checkpoints)\\s*\\[[^\\]]+\\]\\s*=\\s*(new|\\[\\]|delete)|delete\\s+_?checkpoints\\s*\\[|checkpoints\\s*\\[[^\\]]+\\]\\.length\\s*=\\s*0'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — checkpoints-cleared-on-nft-transfer: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
