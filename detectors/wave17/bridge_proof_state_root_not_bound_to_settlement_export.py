"""
bridge-proof-state-root-not-bound-to-settlement-export - generated from reference/patterns.dsl/bridge-proof-state-root-not-bound-to-settlement-export.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-proof-state-root-not-bound-to-settlement-export.yaml
Source: Incident HACKERMAN_V3 Lane I4 - VerusCoin Ethereum BTC-bridge 2026-05-17 (reported_unverified); sub-gap A - the hash the payout is validated against does not commit to a unique source-export identifier
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeProofStateRootNotBoundToSettlementExport(AbstractDetector):
    ARGUMENT = "bridge-proof-state-root-not-bound-to-settlement-export"
    HELP = "Bridge settlement verifies a proof against a state root but the payout hash / leaf binding does not commit to a unique source-export/txid identifier; attacker-authored components can satisfy the binding without naming a genuine authorized export"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-proof-state-root-not-bound-to-settlement-export.yaml"
    WIKI_TITLE = "Bridge state-root proof payout hash does not bind a unique source export identifier"
    WIKI_DESCRIPTION = "A cross-chain bridge dispatcher verifies payload components against a state-root or merkle-root proof, then releases custody (token transfer or mint). The payout hash / leaf construction does not include a unique source-export/txid identifier, so the proof establishes only that the supplied components are well-formed under the root - not that they correspond to a real, authorized, uniquely-identified source export. An attacker can assemble components that satisfy the hash binding (recipient, amount, token) while pointing at no genuine authorized export, or can reuse the same components against multiple payout calls. Sub-gap A of the VerusCoin 2026-05-17 pattern: the consume-once ledger gap (sub-gap B) is covered by bridge-state-root-proof-payout-unbound-to-export."
    WIKI_EXPLOIT_SCENARIO = "Anchor incident (reported_unverified): the 2026-05-17 VerusCoin Ethereum bridge payout computed a disbursement from deserialized payload bytes and validated it against a state-root proof, but the hash binding did not commit a unique source export/txid. An attacker authors (recipient=self, amount=max, token=ETH) components, constructs a valid leaf under the state root, and reaches the value transfer without the bridge verifying that the leaf names a real authorized export."
    WIKI_RECOMMENDATION = "Bind the disbursed (token, recipient, amount, source-chain, unique-source-export/txid) tuple into the exact verified leaf or commitment hash. The source-export/txid identifier must be a field that names a real authorized export on the source chain, not a freely-chosen attacker value. After binding, enforce a consume-once ledger (_processedTxids) to prevent replay."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(bridge|crosschain|cross-chain|dispatcher|stateRoot|merkleRoot|verifyProof|checkProof)'}]
    _MATCH = [{'function.name_matches': '(?i).*(payout|payOut|disburse|release|settle|withdraw|claimExport|processExport|finalize|dispatch).*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.is_mutating': True}, {'function.body_contains_regex': '(?i)(stateRoot|state_root|merkleRoot|merkle_root|verifyProof|checkProof|MerkleProof\\.verify|verifyMerkleProof|\\.verify\\s*\\()'}, {'function.body_contains_regex': '(?i)(\\.transfer\\s*\\(|\\.call\\{value|safeTransfer|_mint\\s*\\(|safeTransferFrom)'}, {'function.body_not_contains_regex': '(?i)(exportId|export_id|txid|sourceTxid|source_txid|outputId|output_id|utxoId|utxo_id|exportHash|export_hash|sourceExport|source_export)'}]

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
                info = [f, f" - bridge-proof-state-root-not-bound-to-settlement-export: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
