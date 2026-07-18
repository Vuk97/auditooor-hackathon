"""
construct-payouts-no-tie-revert-sentinel — generated from reference/patterns.dsl/construct-payouts-no-tie-revert-sentinel.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py construct-payouts-no-tie-revert-sentinel.yaml
Source: polymarket-draft-4
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ConstructPayoutsNoTieRevertSentinel(AbstractDetector):
    ARGUMENT = "construct-payouts-no-tie-revert-sentinel"
    HELP = "External/public payouts producer assigns the payout vector but lacks any defensive guard (tie, sum, equal-leg check) before returning. Downstream consumers enforcing `sum(payout)==1` revert on tied/zero/over-sum vectors, bricking resolution."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/construct-payouts-no-tie-revert-sentinel.yaml"
    WIKI_TITLE = "Payout-array constructor returns vector without sum/tie sanity check"
    WIKI_DESCRIPTION = "An external or public function named *constructPayouts / computePayouts / resolvePayouts / finalize|settleOutcome* writes the entries of a payout array (`payouts[0] = ...; payouts[1] = ...;` or `payouts[i] = ...` in a loop) and returns it to a downstream consumer without any local invariant check. Downstream CTF / NegRisk / ConditionalTokens consumers that strictly enforce `sum(payouts) == 1` (or "
    WIKI_EXPLOIT_SCENARIO = "A binary prediction market is escalated to UMA's DVM. DVM votes `0.5 ether` (tie/unknown — its routine sentinel for ambiguous questions). The adapter's `_constructPayouts(0.5 ether)` returns `[1, 1]` because no equal-leg check rejects the tie. The downstream NegRiskOperator.reportPayouts requires `payout0 + payout1 == 1` and reverts `InvalidPayouts()`. Every retry of `resolve(questionID)` reverts "
    WIKI_RECOMMENDATION = "Add a local sanity check in the payouts producer that matches the downstream consumer's invariant. For NegRisk-backed adapters, e.g.: `require(payouts[0] != payouts[1] || allowTies, \"TIE_UNSUPPORTED\");` or explicitly route the DVM-tie case through a dedicated `flagAndAdminResolve` path instead of "

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(Adapter|Operator|Oracle|Resolver|Outcome|Market)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(?i)(_?constructPayouts|_?computePayouts|_?resolvePayouts|finalizeOutcome|settleOutcome)'}, {'function.body_contains_regex': '(?i)(payouts?\\s*\\[\\s*0\\s*\\]\\s*=|payouts?\\[i\\]\\s*=)'}, {'function.body_not_contains_regex': '(?i)(require\\s*\\([^)]*tie|payouts?\\.length\\s*>|require\\s*\\([^)]*sum|sum\\s*of\\s*payouts|require\\s*\\([^)]*!=\\s*payouts?\\[1\\]|allowTies|isNegRisk)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — construct-payouts-no-tie-revert-sentinel: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
