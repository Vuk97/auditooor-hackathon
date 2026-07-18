"""
bridge-proof-domain-bypass-ballot-field-omitted — generated from reference/patterns.dsl/bridge-proof-domain-bypass-ballot-field-omitted.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-proof-domain-bypass-ballot-field-omitted.yaml
Source: auditooor-batch5-bridge-recall-gap
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeProofDomainBypassBallotFieldOmitted(AbstractDetector):
    ARGUMENT = "bridge-proof-domain-bypass-ballot-field-omitted"
    HELP = "Cross-chain ballot/vote identifier omits a key payload field from the keccak256(abi.encode(...)) preimage. Two votes with different payloads hash to the same ID, enabling payload collision and overwrite."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-proof-domain-bypass-ballot-field-omitted.yaml"
    WIKI_TITLE = "Cross-chain ballot identifier omits payload field - collision enables message overwrite"
    WIKI_DESCRIPTION = "Bridge observer networks and TSS consensus mechanisms compute a vote/ballot identifier to deduplicate submitted votes. When the identifier omits a key payload field (new public key, message body, recipient), two structurally different votes can produce the same identifier. An attacker submits a malicious vote that collides with a legitimate vote's identifier, overwriting the stored payload. The le"
    WIKI_EXPLOIT_SCENARIO = "ZetaChain TSS ballot: `keccak256(abi.encode(chainId, creator, txHash, observerType))` omits newPubKey. Attacker submits TSS vote with a malicious newPubKey but the same (chainId, creator, txHash, observerType) tuple as a legitimate pending vote. The attacker's payload overwrites the legitimate vote's stored pubKey. When the vote reaches quorum, the attacker-controlled key is installed."
    WIKI_RECOMMENDATION = "Include ALL semantically-relevant fields in the ballot/vote identifier preimage: `keccak256(abi.encode(chainId, creator, txHash, observerType, newPubKey))`. The identifier must uniquely commit to the complete payload, not just the routing metadata. Add a unit test: assert that two votes with differe"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(ballot|vote|consensus|tss|relay|identifier|submitVote|ballotKey|messageId)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(?i)(ballot|vote|index|identifier|key|hash|digest|commitment)(.*)?'}, {'function.body_contains_regex': 'keccak256\\s*\\(\\s*abi\\.encode\\s*\\('}, {'function.body_contains_regex': '\\.(newPubKey|pubKey|newKey|body|payload|data|signature|sig|msg)\\b'}, {'function.body_not_contains_regex': 'abi\\.encode\\s*\\([^)]*\\.(newPubKey|pubKey|newKey|body|payload)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — bridge-proof-domain-bypass-ballot-field-omitted: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
