"""
multisig-threshold-bypass — generated from reference/patterns.dsl/multisig-threshold-bypass.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py multisig-threshold-bypass.yaml
Source: solodit-cluster/C0001
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MultisigThresholdBypass(AbstractDetector):
    ARGUMENT = "multisig-threshold-bypass"
    HELP = "Multisig execute/checkSignatures mutates state after an external call without a reentrancy guard; signers can re-enter to bypass threshold."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/multisig-threshold-bypass.yaml"
    WIKI_TITLE = "Multisig threshold bypass via post-external-call state mutation"
    WIKI_DESCRIPTION = "A multisig or signer-gate contract exposes an execute-family entrypoint (execute, executeTx, checkSignatures, reconcileSigner, _executeTransaction) that performs an external call and then writes to state (e.g. nonce, signer set, threshold accounting) without a nonReentrant guard. A malicious callee can re-enter the contract and adjust the effective threshold or signer set before the post-call book"
    WIKI_EXPLOIT_SCENARIO = "A compromised signer submits a batched execute that calls a contract they control. Inside the callback they invoke a signer-management function (addOwner / removeSigner / setThreshold) whose own guard is threshold-based; because the outer execute hasn't yet decremented the pending-operation counter or incremented the nonce, the re-entrant call passes checks. The outer call then completes, committi"
    WIKI_RECOMMENDATION = "Add OpenZeppelin ReentrancyGuard (nonReentrant) to every signer/threshold-touching entrypoint, or re-order the function to Checks-Effects-Interactions so all threshold bookkeeping (nonce increment, signer-set update, threshold write) happens BEFORE any external call. Additionally, cache the threshol"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'threshold|minSignatures|maxSignatures|requiredSignatures|quorum|signerCount'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'execute|executeTx|checkSignatures|reconcileSigner|_executeTransaction'}, {'function.post_external_call_mutates_state': True}, {'function.has_modifier': {'includes': ['nonReentrant', 'reentrancyGuard', 'lock'], 'negate': True}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — multisig-threshold-bypass: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
