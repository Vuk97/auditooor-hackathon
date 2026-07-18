"""
zksync-aa-paymaster-msg-sender-bootloader — generated from reference/patterns.dsl/zksync-aa-paymaster-msg-sender-bootloader.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py zksync-aa-paymaster-msg-sender-bootloader.yaml
Source: auditooor-R73-chain-specific-zksync
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ZksyncAaPaymasterMsgSenderBootloader(AbstractDetector):
    ARGUMENT = "zksync-aa-paymaster-msg-sender-bootloader"
    HELP = "On zkSync Era, paymaster entry points are called by the bootloader system contract — `msg.sender` is the bootloader, not the user. Paymasters that use msg.sender for user identity or policy lookup are broken."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/zksync-aa-paymaster-msg-sender-bootloader.yaml"
    WIKI_TITLE = "zkSync paymaster msg.sender is the bootloader, not the end-user"
    WIKI_DESCRIPTION = "zkSync Era implements native Account Abstraction: paymaster contracts get `validateAndPayForPaymasterTransaction(txHash, suggestedSignedHash, transaction)` called by `BOOTLOADER_FORMAL_ADDRESS` (0x000…8001). The user identity lives inside the `transaction.from` field, not `msg.sender`. Paymasters that check `msg.sender == whitelistedUser` will reject every real transaction; paymasters that account"
    WIKI_EXPLOIT_SCENARIO = "A paymaster limits each user to 10 sponsored txs/day via `require(usageCount[msg.sender]++ < 10)`. In production, every paymaster-invoked call has msg.sender == bootloader. One counter is incremented for all users combined; after 10 txs the paymaster refuses everyone. Alternatively, if a paymaster restricts sponsorship to a whitelist, it checks `require(allowed[msg.sender])` — bootloader is not in"
    WIKI_RECOMMENDATION = "Always identify the transaction's real signer via `transaction.from` (the `Transaction calldata` struct from zkSync's `TransactionHelper`). Use `onlyBootloader` modifier to restrict callers, but key user-identity lookups off `transaction.from`. Add an integration test on zkSync local node (anvil-zks"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)paymaster|IPaymaster|validateAndPayForPaymasterTransaction|postTransaction'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)validateAndPayForPaymasterTransaction|postTransaction'}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.body_contains_regex': '(?i)msg\\.sender'}, {'function.body_not_contains_regex': '(?i)(BOOTLOADER_FORMAL_ADDRESS|msg\\.sender\\s*==\\s*\\w*[Bb]ootloader|onlyBootloader)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — zksync-aa-paymaster-msg-sender-bootloader: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
