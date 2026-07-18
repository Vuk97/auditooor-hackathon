"""
r94-loop-restaking-operator-heap-removed-id-stale-divzero — generated from reference/patterns.dsl/r94-loop-restaking-operator-heap-removed-id-stale-divzero.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-restaking-operator-heap-removed-id-stale-divzero.yaml
Source: solodit-30903-sherlock-rio-network
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopRestakingOperatorHeapRemovedIdStaleDivzero(AbstractDetector):
    ARGUMENT = "r94-loop-restaking-operator-heap-removed-id-stale-divzero"
    HELP = "r94-loop-restaking-operator-heap-removed-id-stale-divzero"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-restaking-operator-heap-removed-id-stale-divzero.yaml"
    WIKI_TITLE = "r94-loop-restaking-operator-heap-removed-id-stale-divzero"
    WIKI_DESCRIPTION = "r94-loop-restaking-operator-heap-removed-id-stale-divzero"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-restaking-operator-heap-removed-id-stale-divzero"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(OperatorHeap|OperatorRegistry|UtilizationHeap|OperatorQueue|Restaking|LRT)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(allocateDeposits|allocateWithdrawals|distributeDeposits|distributeWithdrawals|selectOperator|pickOperator|nextOperator|rebalanceHeap|walkHeap)'}, {'function.source_matches_regex': '(operatorHeap|operatorQueue|utilizationHeap|activeOperators|priorityQueue|heap\\[)'}, {'function.not_source_matches_regex': '(if\\s*\\(\\s*[\\w\\.]*operatorId\\s*==\\s*0|if\\s*\\(\\s*[\\w\\.]*opId\\s*==\\s*0|isRemoved|isActive\\s*\\(|hasBeenRemoved|isTombstone|heap\\.isLive|entry\\.active)'}]

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
                info = [f, f" — r94-loop-restaking-operator-heap-removed-id-stale-divzero: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
