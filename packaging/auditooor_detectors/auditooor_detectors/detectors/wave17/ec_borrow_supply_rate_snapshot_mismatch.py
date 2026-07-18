"""
ec-borrow-supply-rate-snapshot-mismatch — generated from reference/patterns.dsl/ec-borrow-supply-rate-snapshot-mismatch.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ec-borrow-supply-rate-snapshot-mismatch.yaml
Source: economic-mining-R61
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcBorrowSupplyRateSnapshotMismatch(AbstractDetector):
    ARGUMENT = "ec-borrow-supply-rate-snapshot-mismatch"
    HELP = "Borrow rate and supply rate read in the same function without first calling accrueInterest(); rates computed from mismatched state snapshots."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ec-borrow-supply-rate-snapshot-mismatch.yaml"
    WIKI_TITLE = "Borrow/supply rate snapshot mismatch — accrueInterest not called before dual rate read"
    WIKI_DESCRIPTION = "A function reads both borrowRate and supplyRate (or exchangeRate) without first calling accrueInterest(). The two rate calculations depend on totalBorrows and totalReserves. Without accrual, one rate uses a cached totalBorrows while the other reflects an already-updated value — or both use a stale value that diverges from the real on-chain state. This enables attackers to time deposits/withdrawals"
    WIKI_EXPLOIT_SCENARIO = "User deposits 1000 USDC. Protocol computes share price from stale exchangeRate (pre-accrual). Several blocks later, accrueInterest runs. User redeems more assets than deposited because the share price used on deposit was computed against stale totalBorrows."
    WIKI_RECOMMENDATION = "Always call accrueInterest() as the first operation in any function that computes rates, share prices, or amounts. If both rates are needed, call accrueInterest once and read both from the post-accrual state within the same transaction."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'accrueInterest|totalBorrows|borrowRate|supplyRate|exchangeRate'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'borrowRate|borrowRatePerBlock|getBorrowRate'}, {'function.body_contains_regex': 'supplyRate|supplyRatePerBlock|getSupplyRate|exchangeRate'}, {'function.body_not_contains_regex': 'accrueInterest\\(\\)|_accrueInterest\\(\\)|accrue\\(\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ec-borrow-supply-rate-snapshot-mismatch: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
