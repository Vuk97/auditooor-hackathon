"""
bridge-watchdog-suspend-unsuspend-forges-proof-receipt — generated from reference/patterns.dsl/bridge-watchdog-suspend-unsuspend-forges-proof-receipt.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-watchdog-suspend-unsuspend-forges-proof-receipt.yaml
Source: auditooor-R75-c4-mined-2024-03-taiko-278
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeWatchdogSuspendUnsuspendForgesProofReceipt(AbstractDetector):
    ARGUMENT = "bridge-watchdog-suspend-unsuspend-forges-proof-receipt"
    HELP = "A bridge 'watchdog/pause' role that toggles a message's proofReceipt timestamp between `type(uint64).max` (suspend) and `block.timestamp` (unsuspend) will promote an otherwise-unproven message to proven status, because downstream logic treats any `receivedAt != 0` as 'message was proven'. The watchd"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-watchdog-suspend-unsuspend-forges-proof-receipt.yaml"
    WIKI_TITLE = "Bridge watchdog suspend/unsuspend forges proof receipt and drains bridge"
    WIKI_DESCRIPTION = "The `suspendMessages(msgHashes,bool)` function is restricted to a semi-trusted `bridge_watchdog` role whose stated power is only to pause/ban messages. It stores `proofReceipt[msgHash].receivedAt = _suspend ? type(uint64).max : block.timestamp`. Downstream, `isMessageProven` is implemented as `receivedAt != 0`. The watchdog can construct an arbitrary message hash with value=drainAmount and calldat"
    WIKI_EXPLOIT_SCENARIO = "Bridge holds 10,000 ETH. `bridge_watchdog` constructs Message{from=bridge, to=attacker, value=10000 ETH, data=''} and hashes to H. Calls `suspendMessages([H], true)`: proofReceipt[H].receivedAt = type(uint64).max. Calls `suspendMessages([H], false)`: proofReceipt[H].receivedAt = block.timestamp. Attacker calls `processMessage(Message, proof=empty)`. isMessageProven(H) returns true because received"
    WIKI_RECOMMENDATION = "Do not reuse `proofReceipt.receivedAt` as both the suspension flag and the proof-of-delivery witness. Store suspension in a separate `mapping(bytes32 => bool) suspended` (or a bitmap). When un-suspending, reset receivedAt to 0 if it was never proven by the signal service. Invariant test: for any msg"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Bridge|SignalService|proofReceipt'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(suspendMessages?|pauseMessages?|quarantineMessages?)$'}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.body_contains_regex': 'proofReceipt\\s*\\[\\s*\\w+\\s*\\]\\s*(\\.receivedAt)?\\s*=\\s*(_?timestamp|block\\.timestamp|uint\\w*\\.max)'}, {'function.body_not_contains_regex': 'proofReceipt\\[\\w+\\]\\.receivedAt\\s*!=\\s*0\\s*\\&\\&\\s*\\w+'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — bridge-watchdog-suspend-unsuspend-forges-proof-receipt: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
