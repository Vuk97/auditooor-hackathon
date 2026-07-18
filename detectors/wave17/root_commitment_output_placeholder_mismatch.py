"""
root-commitment-output-placeholder-mismatch - generated from reference/patterns.dsl/root-commitment-output-placeholder-mismatch.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py root-commitment-output-placeholder-mismatch.yaml
Source: root-hash-mismatch lane 2026-06-02
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RootCommitmentOutputPlaceholderMismatch(AbstractDetector):
    ARGUMENT = "root-commitment-output-placeholder-mismatch"
    HELP = "Root finalization path compares, stores, emits, or returns a root-shaped placeholder instead of the computed committed root."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/root-commitment-output-placeholder-mismatch.yaml"
    WIKI_TITLE = "Root commitment output uses an unbound placeholder"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. This pattern flags root finalization and commitment functions that compute a root-like value but compare, store, emit, or return a placeholder, zero, stale, default, or otherwise unbound root instead of the computed commitment."
    WIKI_EXPLOIT_SCENARIO = "A batch finalizer computes a new tree root and updates canonical storage, but validates and publishes a stale outputRoot placeholder. Downstream indexers, bridge verifiers, or settlement consumers that trust the exposed root observe a commitment that does not match canonical state."
    WIKI_RECOMMENDATION = "Bind every compared, stored, emitted, and returned root to the same computed value that is committed to storage. Add a negative test asserting event root, return root, stored output root, and canonical storage root are equal after every finalize path."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(root|merkle|tree|commit|finalize|apphash|stateRoot)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.not_slither_synthetic': True}, {'function.source_matches_regex': '(?is)(finalize|commit|process|build|compute).*(root|tree|merkle)|(root|tree|merkle).*(finalize|commit|process|build|compute)'}, {'function.source_matches_regex': '(?is)(bytes32\\s+(storageRoot|rootHash|merkleRoot|emittedRoot|outputRoot|exposedRoot|reportedRoot|observedRoot|publishedRoot|placeholderRoot)\\s*(=\\s*(bytes32\\s*\\(\\s*0\\s*\\)|0x0|last[A-Za-z0-9_]*Root|previous[A-Za-z0-9_]*Root|cached[A-Za-z0-9_]*Root|default[A-Za-z0-9_]*Root|committedRoot))?\\s*;|returns\\s*\\([^)]*bytes32\\s+(storageRoot|rootHash|merkleRoot|emittedRoot|outputRoot|exposedRoot|reportedRoot|observedRoot|publishedRoot|placeholderRoot)[^)]*\\))'}, {'function.source_matches_regex': '(?is)(for\\s*\\([^)]*\\.length|while\\s*\\([^)]*\\.length|keccak256\\s*\\(|hashPair\\s*\\(|_hashPair\\s*\\(|MerkleProof)'}, {'function.source_matches_regex': '(?is)(emit\\s+[A-Za-z0-9_]+\\s*\\([^;]*(storageRoot|rootHash|merkleRoot|emittedRoot|outputRoot|exposedRoot|reportedRoot|observedRoot|publishedRoot|placeholderRoot)|return\\s+(storageRoot|rootHash|merkleRoot|emittedRoot|outputRoot|exposedRoot|reportedRoot|observedRoot|publishedRoot|placeholderRoot)\\s*;|(storageRoot|rootHash|merkleRoot|emittedRoot|outputRoot|exposedRoot|reportedRoot|observedRoot|publishedRoot|placeholderRoot)\\s*=\\s*(storageRoot|rootHash|merkleRoot|emittedRoot|outputRoot|exposedRoot|reportedRoot|observedRoot|publishedRoot|placeholderRoot)\\s*;|require\\s*\\([^;]*(storageRoot|rootHash|merkleRoot|emittedRoot|outputRoot|exposedRoot|reportedRoot|observedRoot|publishedRoot|placeholderRoot)[^;]*(==|!=)|if\\s*\\([^;]*(storageRoot|rootHash|merkleRoot|emittedRoot|outputRoot|exposedRoot|reportedRoot|observedRoot|publishedRoot|placeholderRoot)[^;]*(==|!=))'}, {'function.not_source_matches_regex': '(?is)(storageRoot|rootHash|merkleRoot|emittedRoot|outputRoot|exposedRoot|reportedRoot|observedRoot|publishedRoot|placeholderRoot)\\s*=\\s*(keccak256\\s*\\(|_computeRoot\\s*\\(|computeRoot\\s*\\(|buildRoot\\s*\\(|nextRoot|computedRoot|committedRoot|newRoot|root)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" - root-commitment-output-placeholder-mismatch: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
