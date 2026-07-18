"""
flag-unflag-race-delay-period-zero — generated from reference/patterns.dsl/flag-unflag-race-delay-period-zero.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py flag-unflag-race-delay-period-zero.yaml
Source: polymarket-draft-5
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FlagUnflagRaceDelayPeriodZero(AbstractDetector):
    ARGUMENT = "flag-unflag-race-delay-period-zero"
    HELP = "Permissionless resolveQuestion/settle/finalize is gated by a flag mechanism but `DELAY_PERIOD = 0`, so admin's flag→unflag→emergencyResolve safety window has zero width — any mempool observer can front-run admin's `unflagQuestion` with a permissionless resolve and lock in the oracle outcome."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/flag-unflag-race-delay-period-zero.yaml"
    WIKI_TITLE = "Flag/unflag race with `DELAY_PERIOD = 0` — admin emergency override preempted by permissionless resolve (Polymarket Draft 5)"
    WIKI_DESCRIPTION = "An external/public `resolveQuestion` / `resolve` / `settle` / `finalize` / `consummate` function on an Operator/Resolver/Adapter/Oracle/Dispute/Safety contract is gated by an `isFlagged` / `flagged[qid]` / `.flag == true` guard. The contract declares `DELAY_PERIOD = 0` as a literal constant, and the function body does not enforce any non-zero cooldown (`require(DELAY_PERIOD > 0)`, `require(block.t"
    WIKI_EXPLOIT_SCENARIO = "Polymarket NegRiskOperator. Oracle reports outcome `true` for question X; admin flags X because they suspect the report is wrong. Admin calls `unflagQuestion(X)` as a documented intermediate step (e.g. to re-validate before emergency-resolve). Mallory watches the mempool and bundles `resolveQuestion(X)` immediately after the admin's `unflagQuestion` with equal gas. Because `DELAY_PERIOD = 0`, the "
    WIKI_RECOMMENDATION = "Set `DELAY_PERIOD` to a non-zero value (24h / 48h is typical). Inside `resolveQuestion`, enforce `require(block.timestamp >= flaggedAt[qid] + DELAY_PERIOD)` (or the inverse: `require(flaggedAt[qid] == 0 || block.timestamp >= flaggedAt[qid] + DELAY_PERIOD)`) so any flag inside the cooldown window blo"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Operator|Resolver|Adapter|Oracle|Dispute|Safety)'}, {'contract.has_function_body_matching': 'DELAY_PERIOD\\s*=\\s*0'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(?!emergency|admin)(resolveQuestion|resolve|settle|finalize|consummate)\\w*$'}, {'function.body_contains_regex': '(?i)(isFlagged|flagged|flag\\s*\\[|\\.flag\\s*==\\s*true)'}, {'function.body_not_contains_regex': '(?i)(DELAY_PERIOD\\s*>\\s*0|block\\.timestamp\\s*>=?\\s*[^;]*DELAY|require\\s*\\([^;]*flaggedAt\\s*\\+)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — flag-unflag-race-delay-period-zero: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
