"""
unauth-balance-sweep-to-caller-recipient — generated from reference/patterns.dsl/unauth-balance-sweep-to-caller-recipient.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py unauth-balance-sweep-to-caller-recipient.yaml
Source: auditooor-R67-snowbridge-L1Adaptor
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UnauthBalanceSweepToCallerRecipient(AbstractDetector):
    ARGUMENT = "unauth-balance-sweep-to-caller-recipient"
    HELP = "Permissionless function sweeps entire contract balance (balanceOf(this) or address(this).balance) to a caller-supplied `recipient` address. Any attacker can call with recipient=themselves and drain whatever balance the contract holds — this works on pre-fund amounts AND on leftover dust; it is not a"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/unauth-balance-sweep-to-caller-recipient.yaml"
    WIKI_TITLE = "Permissionless balance sweep to caller-supplied recipient"
    WIKI_DESCRIPTION = "The function is externally callable without an auth modifier, takes an `address recipient` parameter, and at the end of execution unconditionally transfers the full `IERC20(token).balanceOf(address(this))` (or `address(this).balance`) to that recipient. Even if the function is named/documented as a deposit/swap/bridge entry that expects a pre-fund, nothing prevents an attacker from calling it with"
    WIKI_EXPLOIT_SCENARIO = "A bridge adaptor is documented as a two-tx flow: (tx-1) legitimate user transfers 10,000 USDC to the adaptor to pre-fund; (tx-2) user calls `adaptor.depositToken(params, myAddress, topic)` which forwards the funds to the downstream bridge and sweeps any remainder back. Between the two transactions, an attacker observes the adaptor's USDC balance and front-runs with `adaptor.depositToken(craftedPar"
    WIKI_RECOMMENDATION = "Capture the funder at function entry and use that as the refund target, not a caller-supplied recipient:\n  `address refundTo = msg.sender;`\n  `…`\n  `IERC20(token).safeTransfer(refundTo, remaining);`\n\nStronger fix — require the inbound transfer to happen inside the same tx so the contract never "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyRoles', 'onlyGovernance', 'auth', 'nonReentrant_onlyOwner', 'onlyRole'], 'negate': True}}, {'function.has_param_name_matching': 'recipient|receiver|to|beneficiary|_to|destination'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': 'balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)|address\\s*\\(\\s*this\\s*\\)\\.balance'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': 'safeTransfer\\s*\\(\\s*(recipient|receiver|to|beneficiary|_to|destination)|call\\s*\\{\\s*value\\s*:\\s*remaining\\b'}, {'function.body_not_contains_regex': 'address\\s+(refundTo|funder|payer|caller|originator|depositor)\\s*=\\s*msg\\.sender'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — unauth-balance-sweep-to-caller-recipient: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
