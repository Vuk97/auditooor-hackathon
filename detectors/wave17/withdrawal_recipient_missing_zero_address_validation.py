"""
withdrawal-recipient-missing-zero-address-validation — generated from reference/patterns.dsl/withdrawal-recipient-missing-zero-address-validation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py withdrawal-recipient-missing-zero-address-validation.yaml
Source: auditooor-R102-morpho-oracles-periphery-preliq
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class WithdrawalRecipientMissingZeroAddressValidation(AbstractDetector):
    ARGUMENT = "withdrawal-recipient-missing-zero-address-validation"
    HELP = "Withdrawal or unwrap path forwards custody-held assets to a recipient address without rejecting address(0); funds can be burned or stranded."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/withdrawal-recipient-missing-zero-address-validation.yaml"
    WIKI_TITLE = "Withdrawal recipient lacks zero-address validation"
    WIKI_DESCRIPTION = "A user-facing unwrap/withdraw/redeem/release path takes a recipient address and forwards assets to it, but never rejects address(0). In wrapper-style contracts that custody underlying assets, a zero recipient burns or strands withdrawals; in bridge/adaptor flows, the same omission can misroute value to an unusable address and block recovery."
    WIKI_EXPLOIT_SCENARIO = "A caller invokes unwrap(...) with recipient set to address(0) or a miscomputed empty address. The function pulls assets from custody and transfers them out without validating the recipient. Depending on token semantics the funds burn, revert late, or become trapped in the protocol with no user-visible recovery path."
    WIKI_RECOMMENDATION = "Reject zero recipients at the external boundary, or route through a nonzero default like msg.sender. If the wrapper must allow a contract-controlled recipient, validate it explicitly and add a regression fixture that asserts the zero-address case reverts before any transfer."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(CollateralToken|WrappedCollateral|Wrapper|Vault|Adapter|Bridge|Token)'}, {'contract.has_function_matching': '(?i)^(unwrap|withdraw|redeem|release)$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(unwrap|withdraw|redeem|release)$'}, {'function.has_param_of_type': 'address'}, {'function.has_param_name_matching': '(?i)^(_?to|recipient|receiver|beneficiary)$'}, {'function.body_contains_regex': '(?i)(safeTransferFrom|safeTransfer|transferFrom|call\\s*\\{\\s*value\\s*:|\\.transfer\\s*\\()'}, {'function.body_not_contains_regex': '(?i)(require\\s*\\([^)]*(?:_?to|recipient|receiver|beneficiary)\\s*!=\\s*address\\s*\\(\\s*0\\s*\\)|if\\s*\\(\\s*(?:_?to|recipient|receiver|beneficiary)\\s*==\\s*address\\s*\\(\\s*0\\s*\\)\\s*\\)\\s*revert|revert\\s+InvalidRecipient\\s*\\(|ZeroRecipient|zero recipient)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — withdrawal-recipient-missing-zero-address-validation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
