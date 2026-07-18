"""
aave-siloed-borrow-prevented-only-when-already-siloed — generated from reference/patterns.dsl/aave-siloed-borrow-prevented-only-when-already-siloed.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py aave-siloed-borrow-prevented-only-when-already-siloed.yaml
Source: auditooor-R71-fixdiff-mined-aave-v3-core-a810abafa7
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AaveSiloedBorrowPreventedOnlyWhenAlreadySiloed(AbstractDetector):
    ARGUMENT = "aave-siloed-borrow-prevented-only-when-already-siloed"
    HELP = "Siloed-borrow validation only rejects new borrows when the user is *already* borrowing a siloed asset — it forgets the symmetric case of trying to open a siloed-asset borrow while already having other debts."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/aave-siloed-borrow-prevented-only-when-already-siloed.yaml"
    WIKI_TITLE = "Siloed borrow only checked in one direction — new siloed borrow while having non-siloed debt allowed"
    WIKI_DESCRIPTION = "Aave v3's siloed-borrowing rule: 'a user may borrow at most one siloed asset, and nothing else while in it.' Pre-fix validateBorrow implemented only the first half: `if user is currently borrowing a siloed asset, the new borrow asset must be the same siloed asset`. The symmetric case — user has one or more normal borrows and tries to open a borrow on a reserve whose configuration flag getSiloedBor"
    WIKI_EXPLOIT_SCENARIO = "(1) Governance lists asset X as siloed because of oracle risk. (2) User deposits collateral and takes a normal USDC borrow. (3) User then borrows asset X (siloed); pre-fix validateBorrow sees siloedBorrowingEnabled==false on the existing position (no siloed borrow yet), goes down the non-siloed branch and never checks the target reserve's silo flag. (4) User now holds mixed (USDC, X) debt. (5) If "
    WIKI_RECOMMENDATION = "Inside validateBorrow after computing siloedBorrowingEnabled/siloedBorrowingAddress, check BOTH directions: `if (siloedBorrowingEnabled) require(siloedBorrowingAddress == params.asset, SILOED_BORROWING_VIOLATION); else if (userConfig.isBorrowingAny()) require(!reserveConfig.getSiloedBorrowing(), SIL"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': 'validateBorrow|executeBorrow'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': 'validateBorrow|_validateBorrow'}, {'function.body_contains_regex': 'siloedBorrowingEnabled|siloedBorrowingAddress|SILOED_BORROWING_VIOLATION'}, {'function.body_not_contains_regex': 'isBorrowingAny\\s*\\(\\s*\\)[\\s\\S]{0,200}getSiloedBorrowing\\s*\\(\\s*\\)|!\\s*\\w+\\.getSiloedBorrowing\\s*\\(\\s*\\)\\s*,\\s*Errors\\.SILOED_BORROWING_VIOLATION'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — aave-siloed-borrow-prevented-only-when-already-siloed: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
