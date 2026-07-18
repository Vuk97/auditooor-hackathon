"""
oracle-callback-no-reentrancy-guard — generated from reference/patterns.dsl/oracle-callback-no-reentrancy-guard.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py oracle-callback-no-reentrancy-guard.yaml
Source: auditooor-R82-polymarket-UmaCtfAdapter-priceDisputed
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OracleCallbackNoReentrancyGuard(AbstractDetector):
    ARGUMENT = "oracle-callback-no-reentrancy-guard"
    HELP = "UMA / oracle callback handler performs an external call followed by storage mutation without nonReentrant. OO (or operator) can be tricked into re-entering via token-transfer hooks during the callback, enabling cross-function state desync."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/oracle-callback-no-reentrancy-guard.yaml"
    WIKI_TITLE = "UMA oracle-callback handler lacks reentrancy guard on external-call-then-write"
    WIKI_DESCRIPTION = "Contracts that implement an UMA / optimistic-oracle callback interface (priceDisputed, priceSettled, prepareQuestion) receive control from the oracle. If the handler performs an external call (e.g. rewardToken.transfer, IConditionalTokens.prepareCondition, CTF.mint) before mutating its own storage (e.g. questionData[id] = ...), a malicious token, conditional-tokens mock, or re-entrant 1155 receive"
    WIKI_EXPLOIT_SCENARIO = "UmaCtfAdapter.priceDisputed(...) calls `rewardToken.safeTransfer(creator, refund)` before writing `questionData[qID].refund = true`. Attacker registers a non-standard rewardToken whose `transfer` hook re-enters `initialize(qID)` on the adapter, observing `refund=false` and committing a second question with the same ancillary bytes. Downstream resolution uses the overwritten data; creator's origina"
    WIKI_RECOMMENDATION = "Add `nonReentrant` to every oracle-callback handler (priceDisputed, priceSettled, prepareQuestion, onPriceSettled). Alternatively, reorder to strict CEI: all storage writes first, then any external call. For callback handlers shared with unknown token addresses (user-supplied rewardToken), the guard"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)IOptimisticRequester|priceDisputed|priceSettled|onPriceSettled|OOV2|optimisticOracle|prepareQuestion'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(priceDisputed|priceSettled|onPriceSettled|onPriceDisputed|prepareQuestion|_?oracleCallback)$'}, {'function.has_external_call': True}, {'function.post_external_call_mutates_state': True}, {'function.body_not_contains_regex': '(?i)(nonReentrant|ReentrancyGuard|_locked|_status\\s*=\\s*\\d|noReentry|_reentrancyLock)'}, {'function.not_in_slither_synthetic': True}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — oracle-callback-no-reentrancy-guard: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
