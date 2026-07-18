"""
repay-loan-arbitrary-borrower-pull — generated from reference/patterns.dsl/repay-loan-arbitrary-borrower-pull.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py repay-loan-arbitrary-borrower-pull.yaml
Source: solodit/repay-loan-pull-funds
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RepayLoanArbitraryBorrowerPull(AbstractDetector):
    ARGUMENT = "repay-loan-arbitrary-borrower-pull"
    HELP = "`repayLoan(borrower, ...)` pulls the repayment token from `borrower` via `transferFrom` without asserting `msg.sender == borrower` or a consent flag. Anyone who has previously approved the protocol can be force-repaid, and any borrower-side approval lying around on an adjacent contract can be hijack"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/repay-loan-arbitrary-borrower-pull.yaml"
    WIKI_TITLE = "`repayLoan(borrower)` pulls from borrower without consent check"
    WIKI_DESCRIPTION = "A 'repay on behalf' flow is convenient but dangerous if the contract reads the repayment from the borrower's balance rather than the caller's. The attack surface is: any stale ERC-20 allowance the borrower granted to this contract (e.g. for an earlier deposit) is now weaponisable — a third party can trigger repayment at an inopportune moment, burning the borrower's capital (and potentially closing"
    WIKI_EXPLOIT_SCENARIO = "Alice borrows in protocol P and maintains a 10_000 USDC allowance. Later she plans to keep the loan open to accumulate reward-token emissions. Bob front-runs her reward-claim transaction with `repayLoan(alice, fullDebt)`. P executes `USDC.transferFrom(alice, vault, fullDebt)`, Alice's debt is cleared, her position is closed, and she stops accruing rewards. She has lost (a) the rewards she was expe"
    WIKI_RECOMMENDATION = "Either (1) pull from `msg.sender` — the caller pays: `token.safeTransferFrom(msg.sender, address(this), amount);`; or (2) require explicit opt-in via a `allowedRepayer[borrower][msg.sender]` mapping; or (3) if pulling from the borrower is a hard requirement, use `permit` on a fresh signed message pe"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'loan|loans|debt|borrower|position'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(repay|repayLoan|_repayLoan|repayOnBehalf|_repay)$'}, {'function.has_param_name_matching': 'borrower|loanId|loanID|loan|user|account'}, {'function.body_contains_regex': '(?:safeT|t)ransferFrom\\s*\\(\\s*(?:borrower|loan\\.borrower|loans\\[[^\\]]+\\]\\.borrower|position\\.owner|user)'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*msg\\.sender\\s*==\\s*(?:borrower|loan\\.borrower|position\\.owner|user)|authorized\\[borrower\\]\\[msg\\.sender\\]|approvedRepayer'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — repay-loan-arbitrary-borrower-pull: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
