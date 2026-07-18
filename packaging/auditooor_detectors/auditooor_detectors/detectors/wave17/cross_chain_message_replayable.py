"""
cross-chain-message-replayable — generated from reference/patterns.dsl/cross-chain-message-replayable.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py cross-chain-message-replayable.yaml
Source: solodit/C0211
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CrossChainMessageReplayable(AbstractDetector):
    ARGUMENT = "cross-chain-message-replayable"
    HELP = "Cross-chain receive-side function processes a message without both (a) binding msg.sender to the canonical bridge/messenger AND (b) consuming a per-message replay guard. Attacker replays finalization to double-spend."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/cross-chain-message-replayable.yaml"
    WIKI_TITLE = "Cross-chain message relay missing sender-bind and replay guard"
    WIKI_DESCRIPTION = "Receive-side entry points on cross-chain messaging layers (`relayMessage`, `finalizeDeposit`, `finalizeWithdrawal`, `handleMessage`, etc.) must enforce two independent checks: the caller is the canonical bridge contract for the local chain, and the specific message identifier has not already been executed. When either is missing an attacker can either (a) call the function directly from an EOA, by"
    WIKI_EXPLOIT_SCENARIO = "An L2 withdrawal-finalization contract exposes `finalizeWithdrawal(bytes32 msgHash, address to, uint256 amount, bytes proof)`. The function verifies `proof` but never stores `msgHash` as processed and never checks that `msg.sender` is the canonical L2→L1 messenger. An attacker captures a legitimate finalization, calls the function repeatedly with the same calldata, and mints `amount` to `to` on ev"
    WIKI_RECOMMENDATION = "Enforce a single-use guard: `require(!processed[msgHash], \"replay\"); processed[msgHash] = true;` at the top of the function. Bind the caller with `require(msg.sender == messenger)` (or `onlyCanonical` modifier, or `IMessenger(messenger).xDomainMessageSender() == trustedRemote`). Both checks are re"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(messenger|bridge|l1Messenger|l2Messenger|canonicalBridge|canonical)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.not_slither_synthetic': True}, {'function.is_mutating': True}, {'function.name_matches': '(relayMessage|receiveMessage|finalizeDeposit|finalizeWithdraw|finalizeWithdrawal|handleMessage|_relayMessage|onRelay)'}, {'function.body_not_contains_regex': 'processed\\[|consumed\\[|seen\\[|relayed\\[|_executed\\[|msgHash|nonces\\[[^\\]]*\\]\\s*=\\s*true|usedNonces\\[|executedMessages\\['}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*msg\\.sender\\s*==\\s*(messenger|bridge|canonical|l1Messenger|l2Messenger|canonicalBridge)|onlyCanonical|onlyBridge|onlyMessenger|\\.xDomainMessageSender\\s*\\(\\s*\\)\\s*=='}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — cross-chain-message-replayable: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
