"""
imm-exit-precompile-delegatecall-msgvalue-inherit — generated from reference/patterns.dsl/imm-exit-precompile-delegatecall-msgvalue-inherit.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py imm-exit-precompile-delegatecall-msgvalue-inherit.yaml
Source: immunefi/aurora-infinite-spend
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ImmExitPrecompileDelegatecallMsgvalueInherit(AbstractDetector):
    ARGUMENT = "imm-exit-precompile-delegatecall-msgvalue-inherit"
    HELP = "Bridge exit precompile records outbound amount as msg.value. DELEGATECALL preserves the outer frame's msg.value, so a malicious contract can delegatecall the precompile repeatedly and bridge out funds it never actually sent."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/imm-exit-precompile-delegatecall-msgvalue-inherit.yaml"
    WIKI_TITLE = "Exit precompile trusts msg.value under DELEGATECALL (Aurora ExitToNear)"
    WIKI_DESCRIPTION = "Native-bridge exit precompiles (Aurora's ExitToNear, NEAR's exitToEthereum, any custom `withdrawNative` implementation) use `msg.value` to determine how much native currency the caller is burning on this side of the bridge. EVM semantics: when contract A `DELEGATECALL`s the precompile at address P, the precompile runs in A's storage but with A's ORIGINAL msg.value — the same msg.value the original"
    WIKI_EXPLOIT_SCENARIO = "Aurora ExitToNear (Apr 2022): attacker's contract receives 1 ETH, then loops `precompile.delegatecall(abi.encode(recipient, 1e18))`. Each iteration emits a VAA-style Exit event with amount = msg.value = 1 ETH. NEAR side mints N × 1 ETH of aETH to the recipient for a single 1 ETH input. Whitehat paid $6M. Fix: precompile checks `address(this) != __self` (delegatecall detected) or `msg.sender != tx."
    WIKI_RECOMMENDATION = "Precompiles / bridge exits that settle based on msg.value must assert they run in their own storage context: record `address private immutable __self = address(this);` at construction and `require(address(this) == __self, \"delegated\");` at the top of every value-accepting entrypoint. Additionally,"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'exitToNear|bridgeExit|burnFrom|withdrawNative|exitTo[A-Z]|__exit|msg\\.value'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(exitToNear|exitToEthereum|bridgeExit|burnFromCaller|withdrawNative|_exit)$'}, {'function.body_contains_regex': 'msg\\.value'}, {'function.body_contains_regex': 'amount\\s*=\\s*msg\\.value|_credit\\s*\\(\\s*[^,]+,\\s*msg\\.value|emit\\s+Exit[^;]+msg\\.value'}, {'function.body_not_contains_regex': 'address\\s*\\(\\s*this\\s*\\)\\s*==\\s*__self|notDelegated|require\\s*\\(\\s*msg\\.sender\\s*==\\s*tx\\.origin|assembly\\s*\\{\\s*.*caller|require\\s*\\(\\s*!_inDelegateCall|_preventDelegateCall'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — imm-exit-precompile-delegatecall-msgvalue-inherit: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
