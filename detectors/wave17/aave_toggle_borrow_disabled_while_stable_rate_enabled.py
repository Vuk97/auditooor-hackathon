"""
aave-toggle-borrow-disabled-while-stable-rate-enabled — generated from reference/patterns.dsl/aave-toggle-borrow-disabled-while-stable-rate-enabled.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py aave-toggle-borrow-disabled-while-stable-rate-enabled.yaml
Source: auditooor-R71-fixdiff-mined-aave-v3-core-5d9938d326
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AaveToggleBorrowDisabledWhileStableRateEnabled(AbstractDetector):
    ARGUMENT = "aave-toggle-borrow-disabled-while-stable-rate-enabled"
    HELP = "Configurator toggles variable-rate borrowing on/off without enforcing the invariant that stable-rate borrowing can only be enabled when variable borrowing is enabled — produces 'enabled stable rate borrow on disabled asset' state that breaks validateBorrow."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/aave-toggle-borrow-disabled-while-stable-rate-enabled.yaml"
    WIKI_TITLE = "setReserveBorrowing allows disabling variable borrow while stableRateBorrowingEnabled=true"
    WIKI_DESCRIPTION = "Aave v3 reserve configuration has two independent flags: `borrowingEnabled` (master borrow switch) and `stableRateBorrowingEnabled` (stable-rate branch). The protocol invariant is `stableRateBorrowingEnabled ⇒ borrowingEnabled`. Pre-fix setReserveBorrowing(asset, false) did not verify that stableRateBorrowingEnabled was already off — an admin could disable variable borrowing on a reserve while sta"
    WIKI_EXPLOIT_SCENARIO = "(1) A reserve is live with both variable and stable borrowing enabled. (2) Risk admin tries to pause new borrows on this asset due to a market event and calls setReserveBorrowing(asset, false). Pre-fix the call succeeds without touching the stable flag. (3) An attacker front-runs the pause tx and opens a stable-rate borrow: validateBorrow's stable-rate branch only checks stableRateBorrowingEnabled"
    WIKI_RECOMMENDATION = "In setReserveBorrowing, when disabling: `require(!currentConfig.getStableRateBorrowingEnabled(), STABLE_BORROWING_ENABLED)`. In setReserveStableRateBorrowing, when enabling: `require(currentConfig.getBorrowingEnabled(), BORROWING_NOT_ENABLED)`. Keep the invariant `stableEnabled ⇒ variableEnabled` as"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': 'setReserveBorrowing|setBorrowingEnabled|setReserveStableRateBorrowing'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'setReserveBorrowing|setBorrowingEnabled|setReserveStableRateBorrowing|setStableRateBorrowingEnabled'}, {'function.body_contains_regex': 'setBorrowingEnabled|setStableRateBorrowingEnabled'}, {'function.body_not_contains_regex': 'getStableRateBorrowingEnabled\\s*\\(\\s*\\)[\\s\\S]{0,80}require|getBorrowingEnabled\\s*\\(\\s*\\)[\\s\\S]{0,80}require|STABLE_BORROWING_ENABLED|BORROWING_NOT_ENABLED'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — aave-toggle-borrow-disabled-while-stable-rate-enabled: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
