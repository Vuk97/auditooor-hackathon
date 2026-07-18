"""
bridge-deserialized-payout-without-source-export-commitment - generated from reference/patterns.dsl/bridge-deserialized-payout-without-source-export-commitment.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-deserialized-payout-without-source-export-commitment.yaml
Source: Incident HACKERMAN_V3 Lane I4 - VerusCoin Ethereum BTC-bridge 2026-05-17 (reported_unverified); sub-gap - payout derives (recipient, amount, token) from abi.decode / deserialized bytes without binding a unique source-export/txid identifier into the verified commitment
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeDeserializedPayoutWithoutSourceExportCommitment(AbstractDetector):
    ARGUMENT = "bridge-deserialized-payout-without-source-export-commitment"
    HELP = "Bridge payout derives (recipient, amount, token) from abi.decode or deserialized bytes and performs a custody release without binding a unique source-export/txid identifier into the verified commitment; attacker-authored bytes can be crafted to pass without pointing at a genuine authorized export"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-deserialized-payout-without-source-export-commitment.yaml"
    WIKI_TITLE = "Bridge payout deserialized from bytes without source-export commitment in verified hash"
    WIKI_DESCRIPTION = "A cross-chain bridge payout function decodes its payment parameters (recipient, amount, token) from caller-supplied or relayer-supplied bytes via abi.decode or a custom deserializer, then performs a token transfer or mint. The decoded fields used for the value transfer do not include a unique source-export/txid identifier, and the verified commitment (proof leaf / hash) is not bound to such an identifier. The result: an attacker can craft payload bytes that decode to attacker-chosen (recipient, amount, token) values, satisfy any applicable proof check, and trigger a legitimate-looking payout. This is the deserialization-axis sub-gap of the VerusCoin 2026-05-17 pattern (reported_unverified): the bridge dispatcher accepted attacker-authored payload components that decoded cleanly and satisfied the state-root proof while not naming a genuine authorized source export."
    WIKI_EXPLOIT_SCENARIO = "The attacker crafts a byte payload abi.encode(attacker, maxAmount, ETH_TOKEN, /* no sourceTxid */). The bridge decodes this and constructs a leaf that passes a state-root proof. The value transfer fires. Because the decoded fields include no source-export identifier, the proof check is a content-validity check (are these bytes well-formed?) not an authorization check (do these bytes name a real authorized export?). Attacker drains custody with attacker-chosen parameters."
    WIKI_RECOMMENDATION = "Include a unique source-export/txid identifier in the decoded payload and bind it into the verified commitment (proof leaf / hash). The identifier must name a real authorized export on the source chain, not a freely-chosen attacker value. After verification, consume the identifier into a processed-txid ledger before the value transfer."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(bridge|crosschain|cross-chain|dispatcher|relayer|gateway)'}]
    _MATCH = [{'function.name_matches': '(?i).*(payout|payOut|disburse|release|settle|withdraw|claim|process|execute|receive|handle).*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.is_mutating': True}, {'function.body_contains_regex': '(?i)abi\\.decode\\s*\\(\\s*payload\\s*,\\s*\\(address\\s*,\\s*uint256\\s*,\\s*address\\s*\\)\\s*\\)'}, {'function.body_contains_regex': '(?i)(\\.transfer\\s*\\(|\\.call\\{value|safeTransfer|_mint\\s*\\(|safeTransferFrom)'}, {'function.body_not_contains_regex': '(?i)_processed[A-Za-z0-9_]*txid'}]

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
                info = [f, f" - bridge-deserialized-payout-without-source-export-commitment: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
