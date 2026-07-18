"""
operator-deactivation-fee-recipient-swap-strands-accrued — generated from reference/patterns.dsl/operator-deactivation-fee-recipient-swap-strands-accrued.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py operator-deactivation-fee-recipient-swap-strands-accrued.yaml
Source: auditooor-R108-kiln-v1-deactivate-operator
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OperatorDeactivationFeeRecipientSwapStrandsAccrued(AbstractDetector):
    ARGUMENT = "operator-deactivation-fee-recipient-swap-strands-accrued"
    HELP = "Admin-gated `deactivateOperator` / `disableOperator` writes a deactivation flag AND swaps the operator's `feeRecipient` to a temporary admin-supplied address in the same call, without first harvesting accrued fees for the OLD recipient. After the swap, every subsequent fee dispatch routes via `getOp"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/operator-deactivation-fee-recipient-swap-strands-accrued.yaml"
    WIKI_TITLE = "Operator deactivation swaps fee recipient without harvesting accrued — old recipient loses claim"
    WIKI_DESCRIPTION = "Distinct from generic `setFeeRecipients` / `setRecipientsList` (covered by `fee-recipient-replace-without-harvest`), the bug here lives inside a deactivate / disable / kill / retire admin function whose PRIMARY purpose is to flip an `active = false` flag. As a side effect, the function reassigns the operator's fee recipient to an admin-supplied temporary address — but does NOT first flush accrued "
    WIKI_EXPLOIT_SCENARIO = "Kiln-V1 `StakingContract.deactivateOperator(idx, tempRecipient)`: operator A has accrued $50K commission on an EL FeeRecipient clone (lazy-pull, never claimed). Admin calls deactivateOperator(idx_A, kilnTempRecipient) for routine rotation. Before the deactivate, A could have called withdrawELFee on each pubkey; after the deactivate, withdrawELFee(pubkey) reads getOperatorFeeRecipient(pubkeyRoot) →"
    WIKI_RECOMMENDATION = "Inside the deactivate function, harvest the OLD recipient before the swap. Per-pubkey fan-out is expensive — instead snapshot the per-recipient owed amount into a `pendingClaims[oldRecipient]` mapping that survives the swap and is claimable by the original owner. Skeleton:\n\n```solidity\nfunction d"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'feeRecipient|fee_recipient|FeeRecipient|FeeReceiver|operatorFeeRecipient|recipient'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(deactivate|disable|kill|retire|suspend|terminate|deactivateOperator|disableOperator|removeOperator|deactivatePool|disablePool|deactivateProvider)[A-Za-z0-9_]*$'}, {'function.body_contains_regex': '\\.\\s*feeRecipient\\s*=\\s*[A-Za-z_][A-Za-z0-9_]*|\\.\\s*recipient\\s*=\\s*[A-Za-z_][A-Za-z0-9_]*|operatorFeeRecipient\\s*=\\s*[A-Za-z_][A-Za-z0-9_]*'}, {'function.body_contains_regex': 'deactivated\\s*=\\s*true|active\\s*=\\s*false|disabled\\s*=\\s*true|paused\\s*=\\s*true|enabled\\s*=\\s*false|alive\\s*=\\s*false|kill[A-Z]?\\s*=\\s*true'}, {'function.body_not_contains_regex': '_?harvest[A-Z][a-zA-Z]*\\s*\\(|_?claimFees\\s*\\(|_?distributeAccrued\\s*\\(|_?withdrawAccrued\\s*\\(|_?flushPending\\s*\\(|_?deployAndWithdraw\\s*\\(|_?settleAccrued\\s*\\(|_?finalizeFees\\s*\\(|pendingClaims\\s*\\['}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyGovernance', 'onlyRole', 'onlyRoles', 'auth', 'onlyAuthorized'], 'negate': False}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — operator-deactivation-fee-recipient-swap-strands-accrued: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
