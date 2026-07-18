"""
erc4337-paymaster-no-sender-validation — generated from reference/patterns.dsl/erc4337-paymaster-no-sender-validation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc4337-paymaster-no-sender-validation.yaml
Source: auditooor-cross-cluster
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc4337PaymasterNoSenderValidation(AbstractDetector):
    ARGUMENT = "erc4337-paymaster-no-sender-validation"
    HELP = "ERC-4337 paymaster validates a UserOp without binding the sender to an allowlist or approved intent — anyone can have the paymaster pay for their gas, draining the deposit."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc4337-paymaster-no-sender-validation.yaml"
    WIKI_TITLE = "ERC-4337 paymaster sponsors any UserOp — no sender validation"
    WIKI_DESCRIPTION = "An ERC-4337 paymaster exposes `validatePaymasterUserOp` (or the internal `_validatePaymasterUserOp`) without checking `userOp.sender` against a whitelist, intent signature, or approved sponsorship request. The EntryPoint calls the paymaster to confirm it will pay for a given UserOp; if the paymaster returns success unconditionally, the paymaster's deposit becomes an open gas faucet. Any account ab"
    WIKI_EXPLOIT_SCENARIO = "A team deploys a paymaster intended to sponsor gas for their dApp users only. The `validatePaymasterUserOp` implementation checks a signature from the paymaster's operator over `userOpHash` but never inspects `userOp.sender`. An attacker copies the operator's signature format from a legitimate sponsored UserOp, constructs a new UserOp whose `sender` is an attacker-controlled SCA, points the `callD"
    WIKI_RECOMMENDATION = "Bind sponsorship to the caller. In `validatePaymasterUserOp`, verify one of: (a) `userOp.sender` is in a contract-maintained allowlist, (b) the `paymasterAndData` field carries an operator-signed quote over `(userOp.sender, maxCost, validUntil, validAfter)` and the recovered signer is the paymaster "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': 'validatePaymasterUserOp|_validatePaymasterUserOp'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(validatePaymasterUserOp|_validatePaymasterUserOp)$'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*(userOp\\.sender|sender|user)\\s*==|isWhitelisted|allowlist|approvedSenders|_verifyIntent|sponsored'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — erc4337-paymaster-no-sender-validation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
