"""
aurora-delegatecall-inherits-msgvalue-without-eth-transfer — generated from reference/patterns.dsl/aurora-delegatecall-inherits-msgvalue-without-eth-transfer.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py aurora-delegatecall-inherits-msgvalue-without-eth-transfer.yaml
Source: auditooor-R76-immunefi-aurora-$6M
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AuroraDelegatecallInheritsMsgvalueWithoutEthTransfer(AbstractDetector):
    ARGUMENT = "aurora-delegatecall-inherits-msgvalue-without-eth-transfer"
    HELP = "Exit/withdraw precompile credits sender based on msg.value without verifying the current call is a normal CALL. Under DELEGATECALL, msg.value is inherited but no ETH was actually transferred here — attacker mints free credit."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/aurora-delegatecall-inherits-msgvalue-without-eth-transfer.yaml"
    WIKI_TITLE = "Precompile trusts msg.value without rejecting DELEGATECALL context"
    WIKI_DESCRIPTION = "A bridge-exit or ERC-20-wrapper precompile (e.g. ExitToNear) credits the caller proportional to msg.value and emits a withdrawal/exit log. The precompile does NOT check the call-type. An attacker-deployed contract performs a DELEGATECALL into the precompile with a non-zero msg.value inherited from its own entrypoint. The precompile sees msg.value > 0, emits an exit log, and the off-chain relayer ("
    WIKI_EXPLOIT_SCENARIO = "Aurora's ExitToNear precompile checked `msg.value > 0` and emitted an Exit log. An attacker contract received 1 ETH, delegatecalled ExitToNear, kept the 1 ETH, and still got 1 nETH credited on NEAR. Looping this drained the bridge. Payout: $6M."
    WIKI_RECOMMENDATION = "Reject DELEGATECALL explicitly in precompiles that depend on msg.value semantics. In EVM, compare `address(this)` balance delta or require `call_type == Call`. In Substrate/Frontier, consult the EVM context's call_kind. Disable STATICCALL and DELEGATECALL for any precompile that mutates state based "

    # Anchor on the delegatecall/msg.value semantics so renamed adapters still surface.
    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)delegatecall|msg\\.value|callType|DelegateCall'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)exit\\w*|withdraw\\w*|deposit\\w*|onCredit\\w*'}, {'function.body_contains_regex': '(?i)msg\\.value\\s*(?:>|!=)\\s*0|require\\s*\\(\\s*msg\\.value'}, {'function.body_not_contains_regex': '(?i)address\\(this\\)\\.balance|require\\s*\\(\\s*msg\\.sender\\s*==\\s*tx\\.origin|ASSERT_CALL_TYPE|call_type\\s*!=\\s*DelegateCall|callType\\s*!=\\s*DelegateCall|DELEGATECALL_DISABLED'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — aurora-delegatecall-inherits-msgvalue-without-eth-transfer: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
