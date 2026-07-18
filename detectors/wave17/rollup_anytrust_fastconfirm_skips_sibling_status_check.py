"""
rollup-anytrust-fastconfirm-skips-sibling-status-check — generated from reference/patterns.dsl/rollup-anytrust-fastconfirm-skips-sibling-status-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py rollup-anytrust-fastconfirm-skips-sibling-status-check.yaml
Source: auditooor-R75-c4-mined-2024-05-arbitrum-foundation-23
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RollupAnytrustFastconfirmSkipsSiblingStatusCheck(AbstractDetector):
    ARGUMENT = "rollup-anytrust-fastconfirm-skips-sibling-status-check"
    HELP = "`fastConfirmNewAssertion` (invoked by the AnyTrust committee multisig) skips deadline/prev/challenge validation but also forgets to check whether the parent assertion already has a confirmed child. Result: two sibling assertions from the same parent can both be confirmed, creating two canonical chai"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/rollup-anytrust-fastconfirm-skips-sibling-status-check.yaml"
    WIKI_TITLE = "fastConfirmNewAssertion does not reject parent that already has a confirmed child"
    WIKI_DESCRIPTION = "anyTrustFastConfirmer is a multisig-backed trusted confirmer for AnyTrust chains. It calls fastConfirmNewAssertion(assertionHash) which delegates to confirmAssertionInternal. confirmAssertionInternal validates parentAssertionHash, confirmState, and that the assertion is currently pending. It does NOT validate sibling state — specifically, it does not check that the parent's other child has not alr"
    WIKI_EXPLOIT_SCENARIO = "Chain: A -- B -- C (C confirmed). anyTrustFastConfirmer wants to also confirm D under B. Calls fastConfirmNewAssertion(hash(D)). confirmAssertionInternal: parentAssertionHash(D) == hash(B) ✓; confirmState ✓; D.status == Pending ✓. D becomes Confirmed. Now parent B has two confirmed children C and D with contradictory state roots. L1 bridge first reads C's outbox root, processes withdrawals. Advers"
    WIKI_RECOMMENDATION = "In fastConfirmNewAssertion, add: `require(getAssertionStorage(parentAssertionHash).firstChildBlock == 0 || !isConfirmed(firstChild(parentAssertionHash)), 'sibling already confirmed')`. Or, simpler: reject fastConfirm if `getAssertionStorage(parentAssertionHash).numChildConfirmed > 0`. Invariant test"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'fastConfirm|anyTrustFastConfirmer|confirmAssertion'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '^(fastConfirmNewAssertion|fastConfirmAssertion|confirmAssertionInternal|_fastConfirm)$'}, {'function.body_contains_regex': 'fastConfirmer|anyTrustFastConfirmer'}, {'function.body_contains_regex': 'parentAssertionHash|confirmState|assertionHash'}, {'function.body_not_contains_regex': '(siblingHash|rival|firstChildBlock.*confirmed|parent\\.numChildren|secondChild\\.status|hasConfirmedSibling|siblingStatus)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — rollup-anytrust-fastconfirm-skips-sibling-status-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
