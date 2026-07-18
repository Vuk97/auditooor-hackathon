"""
r94-loop-entropy-seed-reveal-reorg — generated from reference/patterns.dsl/r94-loop-entropy-seed-reveal-reorg.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-entropy-seed-reveal-reorg.yaml
Source: loop-cycle-34-promotion-from-staged
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopEntropySeedRevealReorg(AbstractDetector):
    ARGUMENT = "r94-loop-entropy-seed-reveal-reorg"
    HELP = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. Flags entropy/VRF reveal functions gated by fixed block confirmations without explicit finalized-block verification."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-entropy-seed-reveal-reorg.yaml"
    WIKI_TITLE = "Entropy seed reveal gated by confirmation count can be reorg-sensitive"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. This row detects public/external entropy reveal flows that gate on `block.number` confirmation deltas but do not verify finalized/safe block ancestry."
    WIKI_EXPLOIT_SCENARIO = "A protocol reveals randomness after a fixed confirmation threshold. During a probabilistic-finality reorg window, an attacker can land reveal-dependent flow on a soon-to-be-replaced block and influence downstream settlement timing."
    WIKI_RECOMMENDATION = "Bind reveal acceptance to finalized/safe block checks or inclusion proofs rather than confirmation count alone, and keep this row NOT_SUBMIT_READY until evidence extends beyond owned fixture smoke."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Entropy|Randao|VRF|reveal|randomSeed)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(revealSeed|reveal|finalizeRandom|provideEntropy|commitAndReveal)'}, {'function.source_matches_regex': '(block\\.number\\s*[-+]\\s*\\w*confirmation|confirmations?\\s*>=\\s*\\d+)'}, {'function.not_source_matches_regex': '(finalizedBlock|safeBlock|beaconFinalized|rootFinalized|isFinalizedBlock\\s*\\(|checkInclusionProof)'}]

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
                info = [f, f" — r94-loop-entropy-seed-reveal-reorg: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
