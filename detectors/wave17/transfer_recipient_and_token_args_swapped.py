"""
transfer-recipient-and-token-args-swapped — generated from reference/patterns.dsl/transfer-recipient-and-token-args-swapped.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py transfer-recipient-and-token-args-swapped.yaml
Source: auditooor-R73-code4rena-2024-08-superposition-84
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class TransferRecipientAndTokenArgsSwapped(AbstractDetector):
    ARGUMENT = "transfer-recipient-and-token-args-swapped"
    HELP = "Protocol-fee collection swaps the (token, recipient) argument order when invoking the transfer helper."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/transfer-recipient-and-token-args-swapped.yaml"
    WIKI_TITLE = "Protocol fee collection: token/recipient arguments swapped in transfer helper call"
    WIKI_DESCRIPTION = "Helpers with a `(token, recipient, amount)` signature fail silently when caller passes `(recipient, token, amount)` — the EVM call attempts `transfer(pool, amount)` on the recipient's EOA, which has no code and reverts. This DoSes any fee withdrawal and can permanently lock protocol revenue."
    WIKI_EXPLOIT_SCENARIO = "Admin calls `collectProtocol(pool, token_0_amount, token_1_amount, recipient=multisig)`. The code runs `transfer_to_addr(recipient, pool, token_0_amount)`. The VM tries to execute an ERC20 `transfer()` on the multisig address — reverts. Fees accumulate in the pool indefinitely."
    WIKI_RECOMMENDATION = "Use named arguments (`transfer_to_addr(token: pool, recipient: multisig, amount: token_0)`). Add a positive-path unit test for every privileged withdrawal entry point. Consider statically typing helper parameters as newtypes (`TokenAddress`, `RecipientAddress`) so mis-orderings fail at compile time."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)collectProtocol|collectFees|withdrawProtocol|skim'}, {'function.body_contains_regex': '(?i)transfer_to_addr\\s*\\(\\s*recipient\\s*,|safeTransfer\\(\\s*recipient\\s*,\\s*(pool|token|feeToken)\\s*,'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — transfer-recipient-and-token-args-swapped: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
