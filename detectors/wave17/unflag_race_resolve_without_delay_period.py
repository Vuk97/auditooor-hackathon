"""
unflag-race-resolve-without-delay-period — generated from reference/patterns.dsl/unflag-race-resolve-without-delay-period.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py unflag-race-resolve-without-delay-period.yaml
Source: auditooor-R77-polymarket-NegRiskOperator-resolveQuestion
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UnflagRaceResolveWithoutDelayPeriod(AbstractDetector):
    ARGUMENT = "unflag-race-resolve-without-delay-period"
    HELP = "Permissionless resolveQuestion gate relies on a DELAY_PERIOD constant that equals 0, making resolution race-able against admin unflag actions (and front-runnable)."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/unflag-race-resolve-without-delay-period.yaml"
    WIKI_TITLE = "NegRisk-style resolve race: DELAY_PERIOD = 0 eliminates admin veto window"
    WIKI_DESCRIPTION = "The operator contract has a permissionless `resolveQuestion` that only checks `onlyNotFlagged` and `block.timestamp >= reportedAt + DELAY_PERIOD`. With `DELAY_PERIOD = 0`, the moment an admin unflags a question, anyone can call `resolveQuestion` in the same block to commit the oracle-reported result. Admin's intended action of unflag-to-review is instead unflag-to-final-commit. The admin can't eme"
    WIKI_EXPLOIT_SCENARIO = "Oracle reports questionId X with potentially-wrong result. Admin flags to review. Admin later submits unflagQuestion(X) intending to emergencyResolveQuestion with correct outcome. Attacker watches mempool, front-runs with resolveQuestion(X) at higher gas. The wrong oracle result is committed to CTF irreversibly. Admin's emergency-override now fails with OnlyFlagged."
    WIKI_RECOMMENDATION = "Set DELAY_PERIOD to a non-zero value (e.g., 1 hour) so unflagging doesn't enable instant resolution. Alternatively, require admin's explicit `approveResolution(questionId)` step in addition to `!flagged`. Or: `unflag` should set `pending_unflag_since = block.timestamp` and `resolveQuestion` should r"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)flaggedAt|unflagQuestion|DELAY_PERIOD'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)resolveQuestion|_?commitResolution'}, {'function.has_modifier': '(?i)onlyNotFlagged|whenNotFlagged'}, {'function.body_contains_regex': '(?i)block\\.timestamp\\s*<\\s*\\w+\\s*\\+\\s*DELAY_PERIOD|block\\.timestamp\\s*<\\s*\\w*[Rr]eportedAt\\s*\\+'}, {'contract.source_matches_regex': '(?i)DELAY_PERIOD\\s*=\\s*0'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — unflag-race-resolve-without-delay-period: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
