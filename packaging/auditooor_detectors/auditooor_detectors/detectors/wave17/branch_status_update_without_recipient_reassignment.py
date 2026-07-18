"""
branch-status-update-without-recipient-reassignment — generated from reference/patterns.dsl/branch-status-update-without-recipient-reassignment.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py branch-status-update-without-recipient-reassignment.yaml
Source: cross-engagement-base-azul-FN1-AggregateVerifier-resolve
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BranchStatusUpdateWithoutRecipientReassignment(AbstractDetector):
    ARGUMENT = "branch-status-update-without-recipient-reassignment"
    HELP = "A resolve / finalize / settle path has multiple branches that all transition `status` to a 'other side wins' terminal value, but at least one branch (a parent-loss short-circuit, emergency resolver, or oracle-override) updates `status` without reassigning the `recipient` / `bondRecipient` / `payee` "
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/branch-status-update-without-recipient-reassignment.yaml"
    WIKI_TITLE = "Resolve short-circuit updates status but not recipient — bond paid to wrong party"
    WIKI_DESCRIPTION = "A `resolve()` (or `finalize` / `settle`) function in a dispute / challenge / liquidation contract has two or more branches reaching a terminal state. The local-resolution branch sets both `status` AND `recipient` (e.g. `bondRecipient = challenger`). A short-circuit branch — typically `if (parentStatus == CHALLENGER_WINS)`, `if (oracleSaid)`, or `if (emergencyOverride)` — sets `status` to the same "
    WIKI_EXPLOIT_SCENARIO = "An aggregate verifier's `resolve()` has a parent-loss branch: `if (parentStatus == CHALLENGER_WINS) { status = CHALLENGER_WINS; }` — and an `else` branch that runs the full local-resolution flow including `bondRecipient = challengerProver`. Honest challenger submits a valid ZK challenge to game G1 under fraudulent parent G0. G0 resolves CHALLENGER_WINS first; G1's resolve enters the parent-loss br"
    WIKI_RECOMMENDATION = "Every branch that writes a 'other-side wins' status must also write the corresponding recipient. For a parent-loss short-circuit, gate the recipient reassignment on whether a local challenge has already happened:\n\n```solidity\nif (parentGameStatus == GameStatus.CHALLENGER_WINS) {\n    status = Gam"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(resolve|challenge|dispute|game|bond|verifier|liquidat|auction)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(resolve|_resolve|finalize|_finalize|settle|_settle|close|_close)$'}, {'function.body_contains_regex': '\\bif\\s*\\([^)]*(parent|ancestor|inherited|override|upstream|emergency)[^)]*\\)\\s*\\{[^{}]*?\\b(status|state|outcome|result)\\s*=\\s*[\\w\\.]*(CHALLENGER_WINS|LOSER_WINS|REJECTED|REFUNDED|INVALID|REVERSED|VOIDED|CANCELLED|DISPUTED_WON|CHALLENGER_WON)\\b[^{}]*?\\}'}, {'function.body_contains_regex': '(?i)(bondRecipient|payee|beneficiary|payTo|claimant)\\s*=\\s*\\w'}, {'function.body_not_contains_regex': '\\bif\\s*\\([^)]*(parent|ancestor|inherited|override|upstream|emergency)[^)]*\\)\\s*\\{[^{}]*?(bondRecipient|payee|beneficiary|payTo|claimant)\\s*=[^{}]*?\\}'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — branch-status-update-without-recipient-reassignment: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
