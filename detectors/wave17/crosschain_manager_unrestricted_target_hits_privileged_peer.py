"""
crosschain-manager-unrestricted-target-hits-privileged-peer — generated from reference/patterns.dsl/crosschain-manager-unrestricted-target-hits-privileged-peer.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py crosschain-manager-unrestricted-target-hits-privileged-peer.yaml
Source: auditooor-R76-rekt-poly-network-2021
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CrosschainManagerUnrestrictedTargetHitsPrivilegedPeer(AbstractDetector):
    ARGUMENT = "crosschain-manager-unrestricted-target-hits-privileged-peer"
    HELP = "Cross-chain relay dispatches verified messages to an arbitrary `toContract` without excluding sibling privileged contracts (keeper/config/admin modules that trust the relay). Attackers forge a selector-collision payload to invoke keeper rotation."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/crosschain-manager-unrestricted-target-hits-privileged-peer.yaml"
    WIKI_TITLE = "Cross-chain manager has no allow/deny-list for dispatched target contracts"
    WIKI_DESCRIPTION = "A cross-chain manager verifies signatures/proofs over a tuple (toContract, methodName, args) and invokes `toContract.call(abi.encodeWithSelector(keccak256(methodName)[:4], args))`. If the manager is itself the owner/caller-of-record on a sibling contract holding privileged state (keeper set, epoch pubkeys, admin roles, upgrade authority), any attacker who can produce a signed cross-chain message c"
    WIKI_EXPLOIT_SCENARIO = "Attacker crafts a cross-chain message with toContract = EthCrossChainData and method name `f1121318093(bytes,bytes,uint64)` whose keccak256[:4] equals selector `0x41973cd9` = `putCurEpochConPubKeyBytes(bytes)`. The header-verify path passes (the attacker constructs a valid proof on the source chain). The manager calls `EthCrossChainData.putCurEpochConPubKeyBytes(attackerKeeper)`, accepting the cal"
    WIKI_RECOMMENDATION = "Maintain an explicit deny-list or allow-list of target contracts the manager is permitted to dispatch to. At minimum, forbid dispatching to any contract the manager itself can administrate (sibling CrossChainData, admin registry, upgrade proxy). Also bind the full method name (not just its 4-byte se"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, 'Cross-chain manager dispatches a verified message via a low-level call to a target contract chosen by the message payload.']
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)verifyHeaderAndExecuteTx|executeCrossChain|processCrossChain|verifyAndExecute|relayMessage'}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.body_contains_regex': '(?i)\\.call\\s*\\(|\\.delegatecall\\s*\\(|_executeCrossChainTx|ExecuteCrossChainTx'}, {'function.body_not_contains_regex': '(?i)require\\s*\\([^;]*toContract\\s*!=[^;]*|whitelist|blacklist|toContract\\s*!=\\s*address\\(this\\)|isBannedTarget|privilegedPeer'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — crosschain-manager-unrestricted-target-hits-privileged-peer: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
