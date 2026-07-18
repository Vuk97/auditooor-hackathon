"""
bridge-replay-missing-nonce-check — generated from reference/patterns.dsl/bridge-replay-missing-nonce-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-replay-missing-nonce-check.yaml
Source: solodit-cluster-C0181
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeReplayMissingNonceCheck(AbstractDetector):
    ARGUMENT = "bridge-replay-missing-nonce-check"
    HELP = "Bridge receive-side entrypoint mints/releases or recovers a signature without consuming a per-message nonce — the same inbound message can be replayed to double-spend."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-replay-missing-nonce-check.yaml"
    WIKI_TITLE = "Bridge replay: receive-side entrypoint does not consume a per-message nonce"
    WIKI_DESCRIPTION = "Cross-chain messengers and mint/release controllers must track which inbound messages have already been processed. When the receive-side function mints tokens, releases escrowed funds, or validates an attestation signature but never records the message id (processed/consumed/seen/usedNonces mapping) or advances a per-source nonce, the same payload can be resubmitted to mint or release funds repeat"
    WIKI_EXPLOIT_SCENARIO = "An attacker observes a valid inbound message (or its attestation signature) that credits address A with X tokens on the destination chain. Because the receive function does not mark the message as consumed, the attacker resubmits the identical calldata to the bridge endpoint. Each resubmission re-triggers the mint / release and drains the destination-side escrow or inflates totalSupply."
    WIKI_RECOMMENDATION = "Bind every inbound message to a unique id (sourceChain, sourceAddress, nonce) and record it in a `mapping(bytes32 => bool) processed` (or advance a per-source monotonic `nonces[src]`) before performing any value-bearing side effect. Revert when the id / nonce is already consumed. For signature-attes"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(bridge|messenger|endpoint|relayer|mailbox|lzReceive|ccipReceive|Wormhole|Hyperlane|Axelar|LayerZero|CCIP|OFT|crossChain)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'receiveMessage|executeMessage|handleMessage|_handleMessage|onReceive|processMessage|mintFromBridge|releaseFromBridge|lzReceive|ccipReceive'}, {'function.body_contains_regex': {'regex': 'ecrecover\\s*\\(|SignatureChecker|isValidSignature|validateSignature|balances\\s*\\[|totalSupply|_mint\\s*\\(|_burn\\s*\\(|safeTransfer\\s*\\(|release\\s*\\('}}, {'function.body_not_contains_regex': 'processed\\s*\\[|consumed\\s*\\[|seen\\s*\\[|usedNonces\\s*\\[|nonces\\s*\\[[^\\]]+\\]\\s*(=|\\+=)'}, {'function.not_source_matches_regex': '(onlyEndpoint|onlyRouter|onlyMailbox|onlyBridge|ILayerZeroEndpoint|IRouterClient|IMailbox|IWormhole|NonblockingLzApp|CCIPReceiver|TypeCasts\\.bytes32ToAddress)'}]

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
                info = [f, f" — bridge-replay-missing-nonce-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
