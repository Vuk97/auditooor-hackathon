"""
fee-split-zero-allowed-causes-transfer-revert — generated from reference/patterns.dsl/fee-split-zero-allowed-causes-transfer-revert.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fee-split-zero-allowed-causes-transfer-revert.yaml
Source: auditooor-R68-kiln-vSuite-M4
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FeeSplitZeroAllowedCausesTransferRevert(AbstractDetector):
    ARGUMENT = "fee-split-zero-allowed-causes-transfer-revert"
    HELP = "setFeeSplit / setRecipients admin function accepts a splits[] array that may contain 0-entries. On payout, zero-split → zero-value transfer → downstream transfer revert (notNullValue guard) → whole payout DoS'd."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fee-split-zero-allowed-causes-transfer-revert.yaml"
    WIKI_TITLE = "Fee-split setter accepts zero-split entry, DoSing payouts via zero-value transfer"
    WIKI_DESCRIPTION = "The admin / operator can call `setFeeSplit(recipients, splits)` (or sibling `_setFeeSplit` / `setSplits`) to configure how commissions are divvied up across a set of recipients. The setter validates that the splits sum to 100% (BASIS_POINTS / 10000) but does NOT reject individual zero-valued entries. During payout, the dispatcher loops over every (recipient, split) pair, computes `amount = total *"
    WIKI_EXPLOIT_SCENARIO = "A MultiPool integrator has three commission recipients with splits 60/30/10. Admin later configures a new recipient set including one address with split=0 (perhaps a paused grantee, or a mis-configured frontend form that submitted an empty split for a recipient the operator intended to remove). The `setFeeSplit` accepts it because the sum still equals 10000. On the next user exit request, `_exitCo"
    WIKI_RECOMMENDATION = "In `setFeeSplit` (and every sibling setter), add a per-entry guard:\n\n```solidity\nfor (uint256 i = 0; i < recipients.length; i++) {\n    uint256 split = splits[i];\n    require(split > 0, \"split must be nonzero\");\n    sum += split;\n    // ...\n}\n```\n\nAlternative (defensive downstream): in t"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'setFeeSplit|_setFeeSplit|setSplits|setRecipients|setFeeRecipients|setFeeShares|setCommissionSplit|setDispatch'}, {'function.has_param_of_type': 'uint256[]|uint128[]|uint64[]|uint32[]'}, {'function.body_contains_regex': 'for\\s*\\(\\s*uint[0-9]*\\s+i\\s*=\\s*0\\s*;\\s*i\\s*<\\s*[a-zA-Z_]+\\.length'}, {'function.body_contains_regex': 'sum\\s*\\+=|total\\s*\\+=|BASIS_POINTS|BPS|10000'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*splits\\[i\\]\\s*>\\s*0|if\\s*\\(\\s*splits\\[i\\]\\s*==\\s*0\\s*\\)\\s*revert|require\\s*\\(\\s*split\\s*>\\s*0|if\\s*\\(\\s*split\\s*==\\s*0\\s*\\)\\s*revert'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fee-split-zero-allowed-causes-transfer-revert: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
