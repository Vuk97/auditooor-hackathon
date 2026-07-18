"""
halborn-crosschain-bridge-message-not-chainscoped — generated from reference/patterns.dsl/halborn-crosschain-bridge-message-not-chainscoped.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py halborn-crosschain-bridge-message-not-chainscoped.yaml
Source: auditooor-R75-halborn-deBridge-CrossChainSwap
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class HalbornCrosschainBridgeMessageNotChainscoped(AbstractDetector):
    ARGUMENT = "halborn-crosschain-bridge-message-not-chainscoped"
    HELP = "Bridge receiver hashes (nonce, sender, payload) for replay protection but omits srcChainId/dstChainId — the same message valid on one chain can be replayed on another chain where the same bridge is deployed."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/halborn-crosschain-bridge-message-not-chainscoped.yaml"
    WIKI_TITLE = "Bridge replay-key omits chainId — same message can be executed on multiple chains"
    WIKI_DESCRIPTION = "Cross-chain bridge executors track message execution via a `processed[hash]` mapping where the hash binds (sender, nonce, payload). Without explicit `srcChainId` and `dstChainId` fields in the hash preimage, identical (sender, nonce, payload) tuples on different source or destination chains collide in the hash — execution of the message on chain A marks it as processed, but the same hash preimage "
    WIKI_EXPLOIT_SCENARIO = "deBridge-style cross-chain swap: user on Ethereum sends `swap(token=USDC, amount=100k, to=alice, nonce=777)` with destination 'Arbitrum'. Bridge-A on Arbitrum executes, sends 100k USDC to Alice, marks processed[hash(sender, 777, payload)] = true. Attacker replays the same signed message to bridge-A-clone on Optimism (canonical deploy, identical selectors, identical verifier set). Optimism's `proce"
    WIKI_RECOMMENDATION = "Include both `srcChainId` and `dstChainId` in the message struct that gets hashed AND signed. At verify time: `require(msg.dstChainId == block.chainid, 'wrong-chain');`. Make the processed-hash `keccak256(abi.encode(srcChainId, dstChainId, nonce, sender, payload))`. If the bridge uses EIP-712, the c"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Bridge|CrossChain|deBridge|LayerZero|Wormhole|Hyperlane|Message|Relay'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'receiveMessage|_processMessage|claim|relayMessage|executeSwap|fulfill'}, {'function.body_contains_regex': 'processed|usedNonce|isExecuted|_processed|nonceUsed'}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.body_contains_regex': 'keccak256\\s*\\(\\s*abi\\.encode\\s*\\(\\s*nonce|keccak256\\(abi\\.encode\\(.*nonce'}, {'function.body_not_contains_regex': 'block\\.chainid|srcChainId|dstChainId|chainId|CHAIN_ID|message\\.chainId'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — halborn-crosschain-bridge-message-not-chainscoped: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
