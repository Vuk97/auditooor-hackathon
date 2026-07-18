"""
r94-loop-storage-root-assignment-missing — generated from reference/patterns.dsl/r94-loop-storage-root-assignment-missing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-storage-root-assignment-missing.yaml
Source: loop-cycle-24-storage-root-sol-sibling
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopStorageRootAssignmentMissing(AbstractDetector):
    ARGUMENT = "r94-loop-storage-root-assignment-missing"
    HELP = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. Flags tree/root finalization flows where a storage-root placeholder is declared or zero-assigned but never replaced by a computed root assignment."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-storage-root-assignment-missing.yaml"
    WIKI_TITLE = "Storage root placeholder is never replaced by computed root"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. This row detects finalize/compute/build root functions that keep `storageRoot`/`rootHash`/`merkleRoot` as an unassigned placeholder and omit assignment from a computed root value."
    WIKI_EXPLOIT_SCENARIO = "A batching contract finalizes tree updates and emits a root-dependent event, but the finalize path leaves `storageRoot` at zero/default while downstream systems treat the root as committed state. Attackers can force inconsistent settlement or proof verification against an unset root."
    WIKI_RECOMMENDATION = "Assign the computed root to canonical storage before return/emit, and keep this row NOT_SUBMIT_READY until evidence extends beyond owned fixture smoke."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(storageRoot|rootHash|merkleRoot|finalizeTree)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(?i)(handleTree|finalizeTree|computeRoot|buildRoot|storageRoot)'}, {'function.source_matches_regex': '(bytes32\\s+(storageRoot|rootHash|merkleRoot)\\s*;|(storageRoot|rootHash|merkleRoot)\\s*=\\s*(bytes32\\s*\\(\\s*0\\s*\\)|0x0))'}, {'function.not_source_matches_regex': '(storageRoot|rootHash|merkleRoot)\\s*=\\s*(keccak256|merkleRoot|_computeRoot|computedRoot)'}]

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
                info = [f, f" — r94-loop-storage-root-assignment-missing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
