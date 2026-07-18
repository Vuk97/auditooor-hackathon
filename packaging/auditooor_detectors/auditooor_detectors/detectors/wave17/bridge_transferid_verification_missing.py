"""
bridge-transferid-verification-missing — generated from reference/patterns.dsl/bridge-transferid-verification-missing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-transferid-verification-missing.yaml
Source: solodit-cluster-C0215
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeTransferidVerificationMissing(AbstractDetector):
    ARGUMENT = "bridge-transferid-verification-missing"
    HELP = "Bridge destination entrypoint acts on a user-supplied transferId / messageId without verifying it was signed or committed on the source side — attacker spoofs the transferId to drain escrow."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-transferid-verification-missing.yaml"
    WIKI_TITLE = "Bridge transferId verification missing on destination-side settlement"
    WIKI_DESCRIPTION = "Cross-chain bridges commit each transfer on the source chain (via a signature, Merkle root, or canonical message lib) and replay it on the destination chain keyed by a transferId. When the destination-side settlement function (finalizeBridge, claimBridge, releaseTokens, processTransfer, etc.) takes the transferId as user input but never checks a signature / Merkle proof / verifier contract tying i"
    WIKI_EXPLOIT_SCENARIO = "An attacker calls `finalizeBridgeERC20(attacker, token, amount, transferId=0xdead)` on the destination bridge. The function reads `transferId` from calldata, uses it to key its bookkeeping, and releases `amount` of escrowed `token` to the attacker — without ever verifying that `0xdead` was emitted or signed by the source-chain bridge. Because the transferId is not anchored to a source-side commitm"
    WIKI_RECOMMENDATION = "Require a signature (ecrecover / SignatureChecker / ERC-1271), a Merkle inclusion proof against a committed source-chain root, or a canonical message-lib verifier (LayerZero / CCIP / Hyperlane) before taking any value-bearing action on a user-supplied transferId. Treat transferId as untrusted input "

    _PRECONDITIONS = [{'contract.has_state_var_matching': 'bridge|messenger|relayer|transferId|nonces'}, {'contract.source_matches_regex': '(?i)(bridge|messenger|relayer|Bridge|Messenger|Relayer|finalize|claim|settle)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'finalizeBridge|claimBridge|executeBridge|_finalize|releaseTokens|processTransfer|onBridgeReceive|handleBridgedAsset'}, {'function.body_contains_regex': {'regex': 'transferId|_transferId|messageId|srcTransferId|ccipMessageId'}}, {'function.body_not_contains_regex': 'ecrecover|SignatureChecker|isValidSignature|merkleProof|verifySignature|\\.verify\\s*\\(|MessageLib\\.verify|LayerZero\\.verify'}, {'function.not_source_matches_regex': '(NonblockingLzApp|CCIPReceiver|AxelarExecutable|AbstractMessageIdAuth|CrossDomainOwnable|IMessageRecipient|onlyAuthorizedInbox|OnlyEndpoint|onlyMailbox)'}]

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
                info = [f, f" — bridge-transferid-verification-missing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
