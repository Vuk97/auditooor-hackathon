"""
aave-set-siloed-borrow-while-reserve-has-debt — generated from reference/patterns.dsl/aave-set-siloed-borrow-while-reserve-has-debt.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py aave-set-siloed-borrow-while-reserve-has-debt.yaml
Source: auditooor-R71-fixdiff-mined-aave-v3-core-ab5be8ebb1
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AaveSetSiloedBorrowWhileReserveHasDebt(AbstractDetector):
    ARGUMENT = "aave-set-siloed-borrow-while-reserve-has-debt"
    HELP = "Admin can flip a reserve to siloed-borrowing while users already hold debts on it — all existing borrowers become instantly non-compliant with the siloed-borrowing invariant."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/aave-set-siloed-borrow-while-reserve-has-debt.yaml"
    WIKI_TITLE = "setSiloedBorrowing permits flip with non-zero outstanding debt"
    WIKI_DESCRIPTION = "Marking a reserve as siloed retroactively changes the validation rules for every user already borrowing it: a user with mixed (X, Y) debt becomes instantly in violation the moment X is flipped to siloed. The protocol has no background sweeper to close those positions, so the flag flip silently creates a state that validateBorrow would otherwise reject on creation. PR #721 adds an on-flip invariant"
    WIKI_EXPLOIT_SCENARIO = "Risk admin flips asset X to siloed after observing oracle risk. Pre-fix the call succeeds even though 50 users are currently borrowing X alongside other debts. Those users' positions are in a state that should have been forbidden at creation; validateHFAndLtv still works but any subsequent borrow/repay/amend path that calls validateBorrow on those users will revert with SILOED_BORROWING_VIOLATION,"
    WIKI_RECOMMENDATION = "In setSiloedBorrowing (and analogous flags whose semantics retroactively invalidate positions), require `IPoolDataProvider(provider).getTotalDebt(asset) == 0` before enabling. Export a `getTotalDebt(asset) = stableDebt.totalSupply() + variableDebt.totalSupply()` helper. Combine with the existing `_c"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': 'setSiloedBorrowing|setSiloed'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'setSiloedBorrowing|setSiloed|_setSiloedBorrowing'}, {'function.body_contains_regex': 'setSiloedBorrowing\\s*\\(|setSiloed\\s*\\('}, {'function.body_not_contains_regex': 'getTotalDebt|totalDebt\\s*==\\s*0|stableDebtTokenAddress\\s*\\)\\s*\\.totalSupply|variableDebtTokenAddress\\s*\\)\\s*\\.totalSupply|RESERVE_DEBT_NOT_ZERO'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — aave-set-siloed-borrow-while-reserve-has-debt: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
