"""
distribute-lacks-caller-asset-validation — generated from reference/patterns.dsl/distribute-lacks-caller-asset-validation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py distribute-lacks-caller-asset-validation.yaml
Source: auditooor-R75-code4rena-2024-04-gondi-64
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DistributeLacksCallerAssetValidation(AbstractDetector):
    ARGUMENT = "distribute-lacks-caller-asset-validation"
    HELP = "distribute() is permissionless and forwards caller-supplied (loanId, principalAddress, amount) to lender callbacks — attacker can pass a junk ERC20 to poison the pool's accounting."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/distribute-lacks-caller-asset-validation.yaml"
    WIKI_TITLE = "Permissionless distribute lets attacker poison lender accounting with arbitrary ERC20"
    WIKI_DESCRIPTION = "Liquidation/settlement distributors iterate a loan's tranches and call `lender.loanLiquidation(...)` on anyone implementing the LoanManager interface. The function is permissionless and trusts caller-supplied struct data. The pool's `loanLiquidation` does not re-derive the principalAddress from a trusted registry — it treats the received tokens as its quote asset. An attacker calls distribute() wi"
    WIKI_EXPLOIT_SCENARIO = "Attacker deploys JunkToken. Constructs a fake Loan struct with tranche.lender = victim USDC pool, principalAddress = JunkToken. Calls `distributor.distribute(fakeLoan)`. Junk tokens are sent to the USDC pool. The pool calls `_loanTermination` which updates `getCollectedFees` and reduces `outstandingValues` as if USDC were repaid — all users' share prices are now wrong."
    WIKI_RECOMMENDATION = "Restrict `distribute()` to known loan contracts via a registry modifier (`onlyLoanContract`). Also pass `principalAddress` into `loanLiquidation` and require it matches the pool's asset."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)distribute|finalize|liquidate|settle\\w*'}, {'function.body_contains_regex': '(?i)LoanManager\\(|IReceiver\\(|ILoanHandler\\(|\\.loanLiquidation\\(|\\.onReceive\\('}, {'function.body_not_contains_regex': '(?i)onlyAcceptedCallers|onlyLoanContract|require\\s*\\(\\s*isLoanContract|require\\s*\\(\\s*trusted\\[msg\\.sender'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — distribute-lacks-caller-asset-validation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
