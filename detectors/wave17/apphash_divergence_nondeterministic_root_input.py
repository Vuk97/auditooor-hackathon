"""
apphash-divergence-nondeterministic-root-input - generated from reference/patterns.dsl/apphash-divergence-nondeterministic-root-input.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py apphash-divergence-nondeterministic-root-input.yaml
Source: S4 solidity recall lift 2026-06-02
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ApphashDivergenceNondeterministicRootInput(AbstractDetector):
    ARGUMENT = "apphash-divergence-nondeterministic-root-input"
    HELP = "Root, checkpoint, output, or app hash is finalized from nondeterministic or incomplete material instead of a canonical ordered input set."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/apphash-divergence-nondeterministic-root-input.yaml"
    WIKI_TITLE = "App hash root derived from nondeterministic root input"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. This pattern flags functions that store, emit, or return root-like commitments after deriving them from block-dependent material, mutable storage iteration, sentinel placeholders, or other incomplete inputs. Consensus roots and cross-chain checkpoints must be deterministic across honest executors."
    WIKI_EXPLOIT_SCENARIO = "A checkpoint finalizer rebuilds an app hash by looping over a mutable storage collection and mixing block.timestamp into the root. Different executors can observe a different storage order, timing value, or incomplete set, then persist incompatible checkpoint roots for the same logical state transition."
    WIKI_RECOMMENDATION = "Build final roots from canonical ordered calldata or a committed snapshot. Reject block-dependent material, sentinel placeholders, and mutable storage iteration in root material. Add tests that run the same logical state transition from two orderings and assert the same committed root."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(root|checkpoint|output|appHash|apphash|stateHash|stateRoot|commitment)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.not_slither_synthetic': True}, {'function.is_mutating': True}, {'function.source_matches_regex': '(?is)(root|checkpoint|output|appHash|apphash|stateHash|stateRoot|commitment)'}, {'function.source_matches_regex': '(?is)(keccak256\\s*\\(|abi\\.encode(?:Packed)?\\s*\\(|bytes32\\s+[A-Za-z0-9_]*(root|checkpoint|output|hash|commit)[A-Za-z0-9_]*)'}, {'function.source_matches_regex': '(?is)(for\\s*\\([^;]*;[^;]*(\\w+)\\s*<\\s*(\\w+)\\.length|while\\s*\\([^)]*\\.length|block\\.(timestamp|number|prevrandao|coinbase|basefee|hash)\\s*(?:\\(|\\b)|\\b(blockhash|gasleft)\\s*\\(|bytes32\\s*\\(\\s*0\\s*\\)|0x0|TODO|PLACEHOLDER|pending[A-Za-z0-9_]*(Root|Hash)|last[A-Za-z0-9_]*(Root|Hash)|previous[A-Za-z0-9_]*(Root|Hash)|cached[A-Za-z0-9_]*(Root|Hash)|default[A-Za-z0-9_]*(Root|Hash))'}, {'function.source_matches_regex': '(?is)((root|checkpoint|output|appHash|apphash|stateHash|stateRoot|commitment)[A-Za-z0-9_]*\\s*=|emit\\s+[A-Za-z0-9_]+\\s*\\([^;]*(root|checkpoint|output|appHash|apphash|stateHash|stateRoot|commitment)|return\\s+[A-Za-z0-9_]*(root|checkpoint|output|hash|commit)[A-Za-z0-9_]*\\s*;)'}, {'function.not_source_matches_regex': '(?is)require\\s*\\([^;]*(expected|supplied|declared|provided)[A-Za-z0-9_]*(Root|Hash|Commitment|Checkpoint)[^;]*==[^;]*(nextRoot|computedRoot|newRoot|calculatedRoot|canonicalRoot|rootHash|computedHash|nextHash|computedCheckpoint)'}, {'function.not_source_matches_regex': '(?is)for\\s*\\([^;]*;[^;]*(\\w+)\\s*<\\s*(leaves|proof|nodes|headers|validators|accounts|items|entries)\\.length[^)]*\\)[\\s\\S]{0,320}(require|revert)\\s*\\([^;]*(ordered|sorted|index|sequence|length)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" - apphash-divergence-nondeterministic-root-input: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
