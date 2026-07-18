"""
merkle-proof-depth-unbounded — generated from reference/patterns.dsl/merkle-proof-depth-unbounded.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py merkle-proof-depth-unbounded.yaml
Source: code4arena/slice_ab-Unruggable-M01
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MerkleProofDepthUnbounded(AbstractDetector):
    ARGUMENT = "merkle-proof-depth-unbounded"
    HELP = "Merkle / trie proof verifier iterates `proof.length` without asserting an upper bound. Attacker supplies a proof deeper than the true tree, either DoS'ing the verifier or forging collisions against the target leaf's hash."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/merkle-proof-depth-unbounded.yaml"
    WIKI_TITLE = "Merkle / trie verifier accepts unbounded proof depth"
    WIKI_DESCRIPTION = "Whenever a proof-verification function trusts the caller to supply a proof array with a correct length, the absence of a `require(proof.length <= MAX_DEPTH)` opens two failure modes: (1) gas-exhaustion DoS inside a batched/relayed context, and (2) for protocols that allow leaves at arbitrary depths (Scroll zkTrie, Patricia, sparse Merkle), crafting a proof that leads to collision against the targe"
    WIKI_EXPLOIT_SCENARIO = "Scroll's zkTrieVerifier iterates until `proof.length` is exhausted. Attacker submits a 10_000-node proof in a batched cross-chain settlement call; the verifier runs out of gas and the batch reverts — griefing every other message in the same batch."
    WIKI_RECOMMENDATION = "Hard-cap the proof length at the protocol's maximum tree depth (e.g. 32 for Merkle-of-tx, 256 for sparse). `require(proof.length <= MAX_DEPTH, 'depth')` before entering the iteration loop."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Merkle|Patricia|zkTrie|Proof|proof'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(verify|_verify|verifyProof|check|validate)'}, {'function.has_param_of_type': 'bytes32'}, {'function.body_contains_regex': 'for\\s*\\([^)]*proof\\.length|for\\s*\\([^)]*siblings\\.length|for\\s*\\([^)]*_proof\\.length'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*\\w*proof\\.length\\s*<=|require\\s*\\(\\s*\\w*siblings\\.length\\s*<=|proof\\.length\\s*<\\s*MAX_DEPTH|MAX_TREE_HEIGHT|MAX_PROOF_LEN'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — merkle-proof-depth-unbounded: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
