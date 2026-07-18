"""
fee-recipient-replace-without-harvest — generated from reference/patterns.dsl/fee-recipient-replace-without-harvest.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fee-recipient-replace-without-harvest.yaml
Source: auditooor-R68-kiln-vSuite-M8
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FeeRecipientReplaceWithoutHarvest(AbstractDetector):
    ARGUMENT = "fee-recipient-replace-without-harvest"
    HELP = "Admin-gated function replaces the fee-recipient array / splits without first harvesting (claiming) the commission accrued to the prior recipients. Prior recipients lose their pending claim; new recipients receive what was owed to their predecessors."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fee-recipient-replace-without-harvest.yaml"
    WIKI_TITLE = "Fee-recipient replacement without harvesting accrued commission"
    WIKI_DESCRIPTION = "An admin-gated function `setFeeRecipients` / `setFeeSplit` / `setDispatchers` replaces the stored recipient list (array in storage) with a new list. In lazy-pull fee accrual designs, commissions accrue on the dispatcher contract's ETH / share balance and are claimed later by the recipients (via a `harvest` / `claim` function keyed on the recipient address). Because the replacement overwrites the m"
    WIKI_EXPLOIT_SCENARIO = "An integrator has 2 commission recipients: A (70% split) and B (30% split). Over 30 days, the dispatcher accrues 10 ETH in commission; neither A nor B has claimed. The admin calls `setFeeRecipients([C, D], [70, 30])`, replacing A+B with C+D. The 10 ETH that was destined for A+B is now, in the lazy-pull claim mapping, destined for C+D. A + B have permanently lost 10 ETH of earned commission; C + D "
    WIKI_RECOMMENDATION = "Harvest for every existing recipient BEFORE the replacement:\n\n```solidity\nfunction setFeeRecipients(address[] newRecipients, uint256[] newSplits) external onlyAdmin {\n    // First: harvest pending for every current recipient.\n    address[] memory current = $feeRecipients.toAddressA();\n    for "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '_setFeeSplit|setFeeSplit|setFeeRecipients|setRecipients|updateFeeRecipients|changeFeeRecipients|changeRecipients|setDispatchers'}, {'function.body_contains_regex': '(\\$feeRecipients|\\$recipients|feeRecipients|recipients)\\s*=\\s*|(\\$feeRecipients|\\$recipients|feeRecipients|recipients)\\[[^\\]]+\\]\\s*=|toAddressA\\(\\)\\.push\\('}, {'function.body_not_contains_regex': '(harvest[A-Z]|_harvest|claim[A-Z]|_claim|distribute[A-Z]|_distribute|flush[A-Z]|_flush|withdrawAccrued|pullAccrued)\\s*\\('}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyGovernance', 'onlyRole', 'onlyRoles', 'auth'], 'negate': False}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fee-recipient-replace-without-harvest: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
