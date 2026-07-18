"""
eip7702-approval-sweep-via-delegate — generated from reference/patterns.dsl/eip7702-approval-sweep-via-delegate.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py eip7702-approval-sweep-via-delegate.yaml
Source: auditooor-R73-eip7702-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Eip7702ApprovalSweepViaDelegate(AbstractDetector):
    ARGUMENT = "eip7702-approval-sweep-via-delegate"
    HELP = "A protocol that persists ERC20/721 approvals to a contract expects those approvals to become harmless once the target contract changes. With EIP-7702, an EOA can later delegate to a contract that inherits those pre-existing approvals and sweeps them."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/eip7702-approval-sweep-via-delegate.yaml"
    WIKI_TITLE = "Pre-existing ERC20 approvals become sweep targets after EIP-7702 delegation"
    WIKI_DESCRIPTION = "EIP-7702 delegates an EOA to run contract bytecode under the EOA's address. Storage under that address persists: any approval the EOA previously granted to itself (or to any address), or any approval OTHER parties granted TO this EOA, is fully preserved. A malicious 7702 delegate can, at delegation-activation time, loop `token.transferFrom(grantor, attacker, balance)` for every approval it can dis"
    WIKI_EXPLOIT_SCENARIO = "A user approves `unlimited` to a reputable helper contract H. Months later, the user authorizes EIP-7702 to delegate their EOA to a 'smart-wallet' contract W. The protocol W was supplied by an attacker. W's init hook scans the EOA's allowance table and transfers every token with outstanding approvals to the attacker. Approvals never had to be to W directly — they just had to live in the EOA's stor"
    WIKI_RECOMMENDATION = "(a) Wallets offering 7702 authorization must explicitly revoke legacy approvals at delegation time — set allowance[token][*]=0 in a sweep of known tokens. (b) Protocols that ask users to `approve(address(this), MAX)` should now require a time-bounded Permit2 allowance or a daily limit. (c) Token sta"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)approve|allowance|transferFrom|permit'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_high_level_call_named': 'approve|safeApprove'}, {'function.body_contains_regex': '(?i)(approve|safeApprove)\\s*\\(\\s*(address\\(this\\)|_delegate|delegate|pullAddr)\\s*,'}, {'function.body_not_contains_regex': '(?i)revokeOnDelegation|onDeauthorize|7702|isDelegated'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — eip7702-approval-sweep-via-delegate: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
