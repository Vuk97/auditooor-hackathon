"""
create-loan-deterministic-id-frontrun-dos — generated from reference/patterns.dsl/create-loan-deterministic-id-frontrun-dos.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py create-loan-deterministic-id-frontrun-dos.yaml
Source: solodit-cluster-C0035
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CreateLoanDeterministicIdFrontrunDos(AbstractDetector):
    ARGUMENT = "create-loan-deterministic-id-frontrun-dos"
    HELP = "Loan creation derives its storage key from purely caller-supplied inputs (keccak256 of user args) with no per-user nonce, and reverts on duplicate — a griefer copies the mempool args and front-runs to permanently block the victim's creation."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/create-loan-deterministic-id-frontrun-dos.yaml"
    WIKI_TITLE = "Create-loan DoS via deterministic ID front-run"
    WIKI_DESCRIPTION = "A loan or account creation path computes its storage key as `keccak256(abi.encode(userArgs...))` and reverts if the key already exists (a 'must not exist' sanity check). Because the pre-image contains only caller-supplied fields and no per-user nonce, any observer of the mempool can copy the victim's arguments, send the same transaction with a higher gas tip, and claim the key first. The victim's "
    WIKI_EXPLOIT_SCENARIO = "A cross-chain lending protocol's Spoke sends `createLoan(asset, amount, collateral, borrower)` to the Hub, which computes `id = keccak256(asset, amount, collateral, borrower)`. An attacker watches the Hub's mempool, sees the pending message payload, front-runs with an identical `createLoan(asset, amount, collateral, borrower)` from their own Spoke message. The attacker's loan is created at id X. T"
    WIKI_RECOMMENDATION = "Mix a per-caller nonce into the storage key pre-image: `id = keccak256(caller, nonces[caller]++, ...)`. This makes the key unpredictable to observers without reading the caller's per-user counter, which is incremented atomically at key creation. Alternatively use a monotonic global counter (loan_cou"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '(createLoan|createLoanAndDeposit|openLoan|openPosition|createAccount)'}, {'contract.has_state_var_matching': '(loans|positions|accounts|activeLoans|loanStore)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(createLoan|createLoanAndDeposit|openLoan|openPosition|createAccount)[A-Za-z]*$'}, {'function.writes_storage_matching': '(loan|position|account)'}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.body_contains_regex': 'keccak256\\s*\\(\\s*abi\\.encode(Packed)?\\s*\\('}, {'function.body_not_contains_regex': '(nonces\\s*\\[|userNonce|_nonces\\s*\\[|perUserCounter|accountCounter\\s*\\[|msg\\.sender\\s*,\\s*(nonce|counter))'}, {'function.body_contains_regex': 'require\\s*\\(\\s*[a-zA-Z_0-9\\.\\[\\]]*\\s*==\\s*address\\s*\\(\\s*0\\s*\\)\\s*\\)|require\\s*\\(\\s*!\\s*(exists|isActive|created)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — create-loan-deterministic-id-frontrun-dos: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
