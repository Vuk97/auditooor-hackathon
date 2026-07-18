"""
r94-loop-merkle-proof-depth-not-enforced-forgery — generated from reference/patterns.dsl/r94-loop-merkle-proof-depth-not-enforced-forgery.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-merkle-proof-depth-not-enforced-forgery.yaml
Source: solodit-21288-trailofbits-succinct-telepathy
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopMerkleProofDepthNotEnforcedForgery(AbstractDetector):
    ARGUMENT = "r94-loop-merkle-proof-depth-not-enforced-forgery"
    HELP = "r94-loop-merkle-proof-depth-not-enforced-forgery"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-merkle-proof-depth-not-enforced-forgery.yaml"
    WIKI_TITLE = "r94-loop-merkle-proof-depth-not-enforced-forgery"
    WIKI_DESCRIPTION = "r94-loop-merkle-proof-depth-not-enforced-forgery"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-merkle-proof-depth-not-enforced-forgery"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Merkle|SimpleSerialize|BeaconChain|Telepathy|verifyBranch|SSZ)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(verifyMerkleBranch|verify_merkle|verifyProof|verifyBranch|merkleVerify|isValidMerkleProof)'}, {'function.source_matches_regex': '(for\\s*\\([^)]*\\bi\\s*<\\s*\\w*proof\\.length|for\\s*\\([^)]*\\bi\\s*<\\s*\\w*branch\\.length|\\w*proof\\[\\s*\\w+\\s*\\]|\\w*branch\\[\\s*\\w+\\s*\\])'}, {'function.not_source_matches_regex': '(require\\s*\\(\\s*\\w*proof\\.length\\s*==\\s*\\w+|require\\s*\\(\\s*\\w*branch\\.length\\s*==\\s*\\w*(DEPTH|TREE_DEPTH|depth)|assert\\s*\\(\\s*\\w*proof\\.length\\s*==)'}]

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
                info = [f, f" — r94-loop-merkle-proof-depth-not-enforced-forgery: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
