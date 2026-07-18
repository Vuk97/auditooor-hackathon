"""
merkle-leaf-count-one-trivial-proof — generated from reference/patterns.dsl/merkle-leaf-count-one-trivial-proof.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py merkle-leaf-count-one-trivial-proof.yaml
Source: defimon-2026-04-13-hyperbridge-237k
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MerkleLeafCountOneTrivialProof(AbstractDetector):
    ARGUMENT = "merkle-leaf-count-one-trivial-proof"
    HELP = "Bridge HandlerV1 verifies a Merkle proof against a stored overlay/consensus root but accepts proofs with leafCount=1 — the trivial single-leaf tree where root == leaf. Combined with no challenge period, attacker forges messages by passing the publicly-readable stored root as the only leaf."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/merkle-leaf-count-one-trivial-proof.yaml"
    WIKI_TITLE = "Bridge handler accepts Merkle proofs with leafCount=1, making proof_root == storedRoot trivially valid"
    WIKI_DESCRIPTION = "Cross-chain handlers that verify state-machine proofs typically check `keccak256(reduce(proof.leaves, proof.witnessHashes)) == storedOverlayRoot[stateMachineId]`. For a single-leaf tree (leafCount=1), the reduction is the IDENTITY function: `root = leaf`. So a `(leafCount=1, leaves=[X], witnessHashes=[])` proof is accepted whenever `X == storedOverlayRoot[stateMachineId]`. Storage roots are public"
    WIKI_EXPLOIT_SCENARIO = "Hyperbridge HandlerV1 (Apr 13 2026, ~$237K drained, tx 0x240aeb9a8b2aabf64ed8e1e480d3e7be140cf530dc1e5606cb16671029401109). Attacker read `host.consensusStateMachineHeight(srcId).overlayRoot` from public state, then submitted `handlePostRequests({proof: {leafCount: 1, leaves: [overlayRoot], witnessHashes: []}, requests: [forgedMint(usdc, attacker, 237000e6)]})`. The verifier computed `proof_root ="
    WIKI_RECOMMENDATION = "Reject any proof whose `leafCount < 2` (or whatever minimum is meaningful for the protocol). For SPV-style verifiers, treat `leafCount == 1` as a legitimate edge case ONLY when the verifier ALSO checks that the leaf encodes a content payload distinct from the stored root — never accept a proof whose"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(handler|relayer|consensusClient|hostManager|messagingHub|crossChain|stateMachineHeight|overlayRoot|consensusState)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(?i)^(_?verifyProof|verifyConsensusProof|verifyStateProof|verifyPostRequest|_verifyMembership|verifyOverlayProof|_consume_proof)([A-Z_].*)?$'}, {'function.body_contains_regex': '(?i)(leafCount|numLeaves|leavesCount|numEntries|entriesCount|leaf_count)\\s*==\\s*1'}, {'function.body_contains_regex': '(?i)\\.leaves\\s*\\[\\s*0\\s*\\]\\s*==|leaves\\s*\\[\\s*0\\s*\\]\\s*=='}, {'function.body_not_contains_regex': '(?i)require\\s*\\(\\s*\\w*(leafCount|numLeaves|leavesCount|numEntries|entriesCount)\\s*(>|>=)\\s*[12]|require\\s*\\(\\s*\\w*(leafCount|numLeaves|leavesCount|numEntries)\\s*!=\\s*1|revert\\s+\\w*[Tt]rivial'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — merkle-leaf-count-one-trivial-proof: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
