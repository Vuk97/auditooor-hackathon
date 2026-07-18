"""
bridge-destination-settlement-unproven-source-commitment - generated from reference/patterns.dsl/bridge-destination-settlement-unproven-source-commitment.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-destination-settlement-unproven-source-commitment.yaml
Source: slice56-bridge-proof-domain-bypass-recall
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeDestinationSettlementUnprovenSourceCommitment(AbstractDetector):
    ARGUMENT = "bridge-destination-settlement-unproven-source-commitment"
    HELP = "Destination-side bridge settlement releases/mints/credits value from a user-supplied transfer/message id without verifying a source-chain commitment."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-destination-settlement-unproven-source-commitment.yaml"
    WIKI_TITLE = "Bridge destination settlement lacks source-commitment proof"
    WIKI_DESCRIPTION = "Destination bridges should treat transferId/messageId/claimId values as untrusted until they are verified against a source-chain signature, Merkle root, state proof, or canonical message library. If the settlement function only marks the id used and then releases escrow, credits balances, or mints assets, every unused id becomes a fabricated source transfer."
    WIKI_EXPLOIT_SCENARIO = "An attacker calls `finalizeBridgeERC20(attacker, 100_000e6, transferId=0xdead)`. The destination bridge checks `!processed[0xdead]`, sets it true, and credits escrow to the attacker without proving that `0xdead` was emitted, signed, or committed on the source chain."
    WIKI_RECOMMENDATION = "Verify the transfer/message id against a source-chain commitment before any replay marker or value-bearing side effect. Acceptable checks include source-chain Merkle proof, validator signature, canonical bridge verifier, or message-library verification."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(bridge|cross.?chain|messenger|relayer|escrow|transferId|messageId|claimId|nonces)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(finalize|claim|release|settle|execute|process|complete|receive).*(Bridge|Transfer|Message|Claim|Withdrawal|ERC20)?|^(onBridgeReceive|handleBridgedAsset)$'}, {'function.source_matches_regex': '(?i)\\b(bytes32|uint256)\\s+\\w*(transferId|messageId|claimId|proofId|txId|nonce)\\w*\\b'}, {'function.body_contains_regex': '(?i)(transferId|messageId|claimId|proofId|txId|nonce)'}, {'function.body_contains_regex': '(?i)(nonces|processed|used|finalized|claimed|completed)\\w*\\s*\\['}, {'function.body_contains_regex': '(?i)(nonces|processed|used|finalized|claimed|completed)\\w*\\s*\\[[^\\]]+\\]\\s*=\\s*(true|1)'}, {'function.body_contains_regex': '(?i)(safeTransfer|transfer\\s*\\(|_transfer|mint\\s*\\(|call\\s*\\{\\s*value\\s*:|escrow\\w*\\s*\\[|balances?\\w*\\s*\\[)'}, {'function.body_not_contains_regex': '(?i)(ecrecover|ECDSA\\.recover|SignatureChecker|isValidSignature|verifySignature|verifyMessage|validateMessage|MerkleProof\\.verify|verifyMerkleProof|verifyMultiproof|checkProof|MessageLib\\.verify|LayerZero\\.verify|Wormhole\\.verifyVM|AxelarGateway\\.validateContractCall|IBridgeVerifier\\.verify|verifyStorageProof|StateProofVerifier)'}, {'function.not_source_matches_regex': '(?i)(NonblockingLzApp|CCIPReceiver|AxelarExecutable|AbstractMessageIdAuth|CrossDomainOwnable|IMessageRecipient|onlyAuthorizedInbox|OnlyEndpoint|onlyMailbox)'}, {'function.not_source_matches_regex': '(?i)\\b(onlyBridge|onlyRelayer|onlyMessenger|onlyEndpoint|onlyMailbox)\\b'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" - bridge-destination-settlement-unproven-source-commitment: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
