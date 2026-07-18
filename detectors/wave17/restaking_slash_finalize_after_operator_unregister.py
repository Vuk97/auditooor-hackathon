"""
restaking-slash-finalize-after-operator-unregister — generated from reference/patterns.dsl/restaking-slash-finalize-after-operator-unregister.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py restaking-slash-finalize-after-operator-unregister.yaml
Source: auditooor-R75-c4-mined-2024-07-karak-4
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RestakingSlashFinalizeAfterOperatorUnregister(AbstractDetector):
    ARGUMENT = "restaking-slash-finalize-after-operator-unregister"
    HELP = "Possible missing finalize-time registration re-check in a restaking slashing flow; manual review required."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/restaking-slash-finalize-after-operator-unregister.yaml"
    WIKI_TITLE = "finalizeSlashing succeeds after operator unregisters from DSS, violates registration invariant"
    WIKI_DESCRIPTION = "Review-lead/source-shape detector only: it flags a slashing finalizer that consumes queued slash state or earmarked stake state without an obvious current DSS/operator registration re-check. It does not prove the full pending-slash queue, unregister reachability, timer ordering, or economic impact."
    WIKI_EXPLOIT_SCENARIO = "Manual review scenario to confirm before escalation: a pending slash can be requested, the operator can unregister or finalize unstaking before slash finalization, and finalizeSlashing still settles against stale queuedSlashing/earmarkedStakes without checking current DSS registration. Fixture smoke only proves the source-shape guard is absent in a toy fixture."
    WIKI_RECOMMENDATION = "In finalizeSlashing, re-assert `isOperatorRegisteredToDSS(operator, queuedSlashing.dss)` before executing. If the operator unregistered, the slash must revert (or the veto must be shorter than unstake delay so the sequencing can't occur). Structural fix: enforce SLASHING_VETO_WINDOW < (MIN_STAKE_UPD"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Core|SlasherLib|finalizeSlashing|unregisterOperator'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '^(finalizeSlashing|executeSlashing|_finalizeSlashing|slashOperator)$'}, {'function.body_contains_regex': 'queuedSlashing|earmarkedStakes'}, {'function.body_not_contains_regex': '(isOperatorRegisteredToDSS\\s*\\(\\s*operator\\s*,|operatorRegistered\\[dss\\]\\[operator\\]|require\\s*\\(\\s*registered|checkDSSRegistration|DSSOperatorRegistered)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — restaking-slash-finalize-after-operator-unregister: review-lead source shape matched. See WIKI for required manual proof."]
                results.append(self.generate_result(info))
        return results
