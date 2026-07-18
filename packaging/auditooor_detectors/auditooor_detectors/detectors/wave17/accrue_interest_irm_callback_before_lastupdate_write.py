"""
accrue-interest-irm-callback-before-lastupdate-write — generated from reference/patterns.dsl/morpho-accrue-interest-irm-cei.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py morpho-accrue-interest-irm-cei.yaml
Source: auditooor-R71-fixdiff-mined-morpho-1d6161e
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AccrueInterestIrmCallbackBeforeLastupdateWrite(AbstractDetector):
    ARGUMENT = "accrue-interest-irm-callback-before-lastupdate-write"
    HELP = "Interest-accrual calls IRM (external) before updating lastUpdate — a malicious IRM can re-enter and double-accrue or skip accrual for the current block."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/morpho-accrue-interest-irm-cei.yaml"
    WIKI_TITLE = "Accrue-interest CEI violation: IRM borrowRate called before lastUpdate timestamp write"
    WIKI_DESCRIPTION = "Lending protocols that delegate rate calculation to a user-selected IRM contract must treat IRM.borrowRate() as an untrusted external call. If lastUpdate is written only after the IRM call returns, any re-entrant call path from IRM back into the lending contract still observes the pre-accrual lastUpdate, enabling double-accrual or fee double-minting."
    WIKI_EXPLOIT_SCENARIO = "Morpho Blue pre-audit (2023): attacker-controlled IIrm.borrowRate callback re-enters supply() during the accrual call. Because lastUpdate still reflects the previous block, the re-entrant supply triggers _accrueInterest again, re-reads inflated totalBorrowAssets, and double-counts fees for feeRecipient."
    WIKI_RECOMMENDATION = "Move the `lastUpdate = block.timestamp` write BEFORE the external IRM call, so any re-entry hits the elapsed == 0 early-return. Alternatively, guard the full accrual path with a nonReentrant modifier."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(lastUpdate|lastAccrual|lastAccrued|lastTimestamp|lastInterestAccrued)'}]
    _MATCH = [{'function.kind': 'internal'}, {'function.name_matches': '(_accrueInterest|_accrue|accrueInterest)'}, {'function.body_contains_regex': 'IIrm|borrowRate\\s*\\(|IInterestRateModel'}, {'function.body_contains_regex': 'lastUpdate\\s*=|lastAccrual\\s*=|lastAccrued\\s*='}, {'function.body_not_contains_regex': 'lastUpdate\\s*=\\s*[^;]*;[\\s\\S]*?borrowRate|lastAccrual\\s*=[^;]*;[\\s\\S]*?borrowRate|nonReentrant|reentrancyGuard'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — accrue-interest-irm-callback-before-lastupdate-write: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
