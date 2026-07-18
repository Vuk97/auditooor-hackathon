"""
eigenlayer-native-vault-start-snapshot-without-credentials-mints-shares — generated from reference/patterns.dsl/eigenlayer-native-vault-start-snapshot-without-credentials-mints-shares.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py eigenlayer-native-vault-start-snapshot-without-credentials-mints-shares.yaml
Source: auditooor-R75-c4-mined-2024-07-karak-58
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EigenlayerNativeVaultStartSnapshotWithoutCredentialsMintsShares(AbstractDetector):
    ARGUMENT = "eigenlayer-native-vault-start-snapshot-without-credentials-mints-shares"
    HELP = "NativeVault.startSnapshot(revertIfNoBalanceChange) is gated only by `nodeExists(msg.sender)` — not by `activeValidatorCount > 0` or any proof that the node has validated withdrawal credentials. If called before validateWithdrawalCredentials, `activeValidatorCount = 0`, so `remainingProofs = 0`, so `"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/eigenlayer-native-vault-start-snapshot-without-credentials-mints-shares.yaml"
    WIKI_TITLE = "NativeVault startSnapshot mints shares without validating withdrawal credentials"
    WIKI_DESCRIPTION = "createNode allocates an EigenPod-style contract and registers it against msg.sender. startSnapshot only checks `nodeExists(msg.sender)`. It creates a Snapshot with `remainingProofs = node.activeValidatorCount`. If validateWithdrawalCredentials was never called, activeValidatorCount = 0. Snapshot finalizes immediately (_updateSnapshot sees remainingProofs==0 branch): `node.withdrawableCreditedNodeE"
    WIKI_EXPLOIT_SCENARIO = "Mallory calls createNode → pod at address P. Mallory sends 32 ETH directly to P (or uses a pre-existing stuck balance). Mallory calls startSnapshot(revertIfNoBalanceChange=false). _startSnapshot: snapshot = {nodeBalanceWei: 32e18, remainingProofs: 0 (activeValidatorCount=0), …}. _updateSnapshot branch remainingProofs==0: node.withdrawableCreditedNodeETH += 32e18, shares minted: mint(Mallory, 32e18"
    WIKI_RECOMMENDATION = "startSnapshot must require `node.activeValidatorCount > 0`. Add an explicit guard: `require(node.activeValidatorCount > 0 || node.withdrawableCreditedNodeETH == 0, 'no validators registered')`. Or, only credit withdrawable ETH when the balance delta comes from validated validators, not from arbitrar"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'NativeVault|startSnapshot|validateWithdrawalCredentials|remainingProofs'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '^(startSnapshot|_startSnapshot|_updateSnapshot)$'}, {'function.body_contains_regex': 'remainingProofs\\s*[:=]\\s*node\\.activeValidatorCount|snapshot\\.remainingProofs\\s*==\\s*0'}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.body_contains_regex': 'withdrawableCreditedNodeETH\\s*\\+=\\s*snapshot\\.nodeBalanceWei|_mint\\s*\\(\\s*msg\\.sender'}, {'function.body_not_contains_regex': '(activeValidatorCount\\s*>\\s*0|require\\s*\\(\\s*hasValidValidator|validatorsActive|credentialsValidated)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — eigenlayer-native-vault-start-snapshot-without-credentials-mints-shares: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
