"""
merkle-index-no-bitsize-bound — generated from reference/patterns.dsl/merkle-index-no-bitsize-bound.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py merkle-index-no-bitsize-bound.yaml
Source: solodit/hexens/eigenlayer-EIG10-53493
"""

# NOT_SUBMIT_READY: fixture-smoke/source-shape proof only for this row.

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MerkleIndexNoBitsizeBound(AbstractDetector):
    ARGUMENT = "merkle-index-no-bitsize-bound"
    HELP = "Layered Merkle-proof verifier bounds some sub-indexes with `require(idx < 2**HEIGHT)` but forgets one. The unbounded index overflows into the prefix bits, redirecting traversal into a different sub-tree and enabling proof forgery."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/merkle-index-no-bitsize-bound.yaml"
    WIKI_TITLE = "Composite Merkle index missing bit-size bound on one sub-index enables proof forgery"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row matches Merkle-proof verifier functions that build one composite generalized index from multiple shifted sub-indexes, visibly bound at least one `*Index` with `require(index < 2**TREE_HEIGHT)`, and visibly omit the analogous bound for a secondary index such as `historicalSummaryIndex`. It does not yet prove protocol-specific tree semantics, so the row remains NOT_SUBMIT_READY."
    WIKI_EXPLOIT_SCENARIO = "EigenLayer's `verifyWithdrawal` bounds `blockRootIndex` and `withdrawalIndex` but not `historicalSummaryIndex`. An attacker supplies a large `historicalSummaryIndex` whose high bits collide with the prefix bits reserved for `HISTORICAL_SUMMARIES_INDEX`, redirecting traversal into a different beacon-state subtree. A forged witness can then be interpreted as a valid withdrawal proof."
    WIKI_RECOMMENDATION = "Require every sub-index that is shifted into the composite path to stay within its layer bit-width, including the outermost historical/state index. Keep this row NOT_SUBMIT_READY until evidence expands beyond the owned fixture pair and shows the detector separates real protocol shapes from adjacent Merkle index arithmetic."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'verifyInclusion|merkleVerify|MerkleProof\\.verify'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '<<\\s*\\([^)]*TREE_HEIGHT[^)]*\\)'}, {'function.body_contains_regex': 'uint256\\s*\\(\\s*\\w+\\.\\w*Index\\s*\\)\\s*<<'}, {'function.body_contains_regex': 'verifyInclusion\\w*\\s*\\(|MerkleProof\\.verify|merkleVerify'}, {'function.body_contains_regex': 'require\\s*\\(\\s*\\w+\\.\\w*Index\\s*<\\s*2\\s*\\*\\*\\s*\\w+TREE_HEIGHT'}, {'function.body_contains_regex': '(?:\\.\\w+Index|uint256\\s*\\(\\s*\\w+\\.\\w*Index\\s*\\))\\s*<<'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*\\w+\\.historical\\w*Index\\s*<|require\\s*\\(\\s*\\w+\\.state\\w*Index\\s*<|require\\s*\\(\\s*\\w+\\.epochIndex\\s*<'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — merkle-index-no-bitsize-bound: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
