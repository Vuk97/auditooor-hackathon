"""
w69-bridge-payload-recipient-unchecked — generated from reference/patterns.dsl/w69-bridge-payload-recipient-unchecked.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py w69-bridge-payload-recipient-unchecked.yaml
Source: W69 Phase-E weak-class recall lift - production cross-chain payload recipient shape
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class W69BridgePayloadRecipientUnchecked(AbstractDetector):
    ARGUMENT = "w69-bridge-payload-recipient-unchecked"
    HELP = "Cross-chain message handler decodes a recipient from payload and transfers funds to it without recipient validation or expected-recipient binding."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/w69-bridge-payload-recipient-unchecked.yaml"
    WIKI_TITLE = "Bridge payload recipient is paid without validation"
    WIKI_DESCRIPTION = "A bridge or LayerZero-style receive path decodes `(address recipient, uint256 amount)` from untrusted message bytes and immediately transfers tokens to that recipient. Without a zero-address check and a binding to the expected local account/message recipient, malformed or malicious payloads can burn, strand, or redirect funds. The detector is intentionally narrow: payload decode of an address+amou"
    WIKI_EXPLOIT_SCENARIO = "Cross-chain message handler decodes a recipient from payload and transfers funds to it without recipient validation or expected-recipient binding."
    WIKI_RECOMMENDATION = "Reject zero recipients and bind decoded recipients to authenticated message metadata or a previously committed expected recipient before transferring assets."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(lzReceive|lzCompose|receiveMessage|executeMessage|cross.?chain|bridge|payload|message)'}, {'contract.source_matches_regex': '(?i)(safeTransfer|transfer)\\s*\\('}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(?i)^(lzReceive|lzCompose|receiveMessage|executeMessage|claimRemote|finalizeMessage|handleMessage)$'}, {'function.body_contains_regex': 'abi\\.decode\\s*\\([^;]*\\(\\s*address\\s*,\\s*uint256\\s*\\)'}, {'function.body_contains_regex': '(?i)\\b(token|asset|currency)\\.safeTransfer\\s*\\(\\s*(recipient|receiver|to)\\s*,'}, {'function.body_not_contains_regex': '(?i)(recipient|receiver|to)\\s*(?:!=|>)\\s*address\\s*\\(\\s*0\\s*\\)|address\\s*\\(\\s*0\\s*\\)\\s*!=\\s*(recipient|receiver|to)|(recipient|receiver|to)\\s*==\\s*address\\s*\\(\\s*0\\s*\\)|ZeroRecipient|InvalidRecipient|trustedRecipients|recipientAllowlist|expectedRecipient|recipientOf|messageRecipient'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — w69-bridge-payload-recipient-unchecked: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
