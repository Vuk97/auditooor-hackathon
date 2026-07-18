"""
r94-loop-vote-checkpoint-same-block-overwrite-missing — generated from reference/patterns.dsl/r94-loop-vote-checkpoint-same-block-overwrite-missing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-vote-checkpoint-same-block-overwrite-missing.yaml
Source: solodit-3265-c4-nouns-builder
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopVoteCheckpointSameBlockOverwriteMissing(AbstractDetector):
    ARGUMENT = "r94-loop-vote-checkpoint-same-block-overwrite-missing"
    HELP = "r94-loop-vote-checkpoint-same-block-overwrite-missing"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-vote-checkpoint-same-block-overwrite-missing.yaml"
    WIKI_TITLE = "r94-loop-vote-checkpoint-same-block-overwrite-missing"
    WIKI_DESCRIPTION = "r94-loop-vote-checkpoint-same-block-overwrite-missing"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-vote-checkpoint-same-block-overwrite-missing"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(ERC721Votes|Votes|Checkpoint|Checkpoints)'}]
    _MATCH = [{'function.kind': 'internal_or_private_or_public'}, {'function.name_matches': '(?i)(_writeCheckpoint|writeCheckpoint|pushCheckpoint|appendCheckpoint|recordCheckpoint|addCheckpoint)'}, {'function.source_matches_regex': '(checkpoints\\.push\\s*\\(|checkpoints\\[\\w*length\\s*\\]\\s*=\\s*Checkpoint|ckpts\\.push\\s*\\()'}, {'function.not_source_matches_regex': '(last\\.fromBlock\\s*==\\s*block\\.number|last\\.block\\s*==|last\\.timestamp\\s*==|lastCheckpoint\\.timestamp\\s*==|checkpoints\\[[^\\]]+\\]\\.fromBlock\\s*==|ckpts\\[[^\\]]+\\]\\.fromBlock\\s*==|if\\s*\\(\\s*\\w*pos\\s*>\\s*0\\s*&&\\s*\\w*last\\.\\w*(from|block|timestamp)|overwriteLastCheckpoint)'}]

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
                info = [f, f" — r94-loop-vote-checkpoint-same-block-overwrite-missing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
