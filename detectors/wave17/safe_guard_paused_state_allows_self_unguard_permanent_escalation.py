"""
safe-guard-paused-state-allows-self-unguard-permanent-escalation — generated from reference/patterns.dsl/safe-guard-paused-state-allows-self-unguard-permanent-escalation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py safe-guard-paused-state-allows-self-unguard-permanent-escalation.yaml
Source: auditooor-R75-c4-mined-2023-12-autonolas-440
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SafeGuardPausedStateAllowsSelfUnguardPermanentEscalation(AbstractDetector):
    ARGUMENT = "safe-guard-paused-state-allows-self-unguard-permanent-escalation"
    HELP = "A Safe/Gnosis guard contract's `checkTransaction` has a 'fail-open when paused' branch: `if (paused) return;`. But `checkTransaction` is the guard's ONLY mechanism for blocking setGuard(0), i.e., removing the guard itself. When paused, the Community Multisig can call `setGuard(address(0))` on itself"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/safe-guard-paused-state-allows-self-unguard-permanent-escalation.yaml"
    WIKI_TITLE = "Safe guard fail-open on pause allows multisig to permanently unguard itself"
    WIKI_DESCRIPTION = "GuardCM.checkTransaction starts with `if (paused) return;`. The stated purpose of pause is to give the Community Multisig emergency access while governance deliberates. But during that pause, nothing blocks a `setGuard(0)` call from the CM on itself. setGuard() is a self-call on the safe that clears the guard address. After the CM calls setGuard(0), even if governance unpauses GuardCM, it no longe"
    WIKI_EXPLOIT_SCENARIO = "Governance pauses GuardCM on day D due to an ongoing incident. On day D+0 the CM immediately calls `safe.execTransaction(setGuard(0))`. checkTransaction returns without reverting (paused branch). Guard address is now address(0). Day D+N: governance unpauses GuardCM. But `safe.guard == address(0)`, so setGuard's hook is never re-engaged. CM proceeds to call `timelock.execute(transferAllTokensToCM)`"
    WIKI_RECOMMENDATION = "Even when paused, the guard must still block self-calls that would change `safe.guard` or `safe.fallbackHandler`. Minimum:\n```\nif (to == multisig && (selector == SET_GUARD_SELECTOR || selector == SET_FALLBACK_SELECTOR)) revert NoSelfUnguard();\nif (paused) return;\n```\nInvariant test: deploy guar"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'GuardCM|SafeGuard|BaseGuard|checkTransaction'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(checkTransaction|checkAfterExecution|preCheck)$'}, {'function.body_contains_regex': 'if\\s*\\(\\s*paused\\s*(==\\s*true|!=\\s*0|\\)|\\s*\\&\\&).*return\\s*;|isPaused\\(\\).*return\\s*;|whenPaused.*return;'}, {'function.body_not_contains_regex': '(to\\s*==\\s*multisig|to\\s*==\\s*safe|selector\\s*==\\s*setGuard|SETGUARD_SELECTOR|_blockedSelector\\s*\\|\\|.*paused)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — safe-guard-paused-state-allows-self-unguard-permanent-escalation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
