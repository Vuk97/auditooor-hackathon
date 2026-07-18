"""
bridge-receiver-domain-omitted-from-proof-digest - generated from reference/patterns.dsl/bridge-receiver-domain-omitted-from-proof-digest.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-receiver-domain-omitted-from-proof-digest.yaml
Source: auditooor-realworld-recall-gap-solidity-bridge-proof-domain-bypass-s1
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeReceiverDomainOmittedFromProofDigest(AbstractDetector):
    ARGUMENT = "bridge-receiver-domain-omitted-from-proof-digest"
    HELP = "Bridge receiver applies a proof or replay digest under a receiver/application/export domain that is not bound into the digest."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-receiver-domain-omitted-from-proof-digest.yaml"
    WIKI_TITLE = "Bridge receiver domain omitted from proof/replay digest"
    WIKI_DESCRIPTION = "Bridge receiver paths often verify a root or receipt proof, mark a replay digest consumed, then route the payload to a receiver application or export namespace. If the digest commits only to root, receipt, receiver, payload, or nonce, but omits the receiver/application/export domain used for delivery, the same proof tuple can be replayed or misapplied across application domains that share a root or receipt namespace."
    WIKI_EXPLOIT_SCENARIO = "A bridge receiver accepts `applicationDomain`, `exportRoot`, `receipt`, `receiver`, and `payload`. It computes `replayDigest = keccak256(abi.encode(exportRoot, receipt, receiver, keccak256(payload)))`, verifies that digest, and marks `consumedDigests[replayDigest] = true`. It then calls the receiver using the caller-supplied `applicationDomain`. Because the domain was never in the digest or replay key, the proof can be replayed under a different receiver application domain."
    WIKI_RECOMMENDATION = "Bind the receiver application/export domain into the exact digest that is verified and consumed, preferably with the destination contract address: `keccak256(abi.encode(applicationDomain, address(this), exportRoot, receipt, receiver, payloadHash))`. Alternatively scope the consumed mapping by application/export domain before the digest key and prove this structure with a regression fixture."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(bridge|cross.?chain|gateway|portal|receiver|router|proof|replay|export|applicationDomain|appDomain|receiverDomain)'}, {'contract.source_matches_regex': '(?i)(consumed|processed|used|spent|seen)\\w*\\s*\\['}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(?i)(apply|receive|process|execute|deliver|route|claim|finalize|verify).*(Proof|Message|Receipt|Export|Bridge)?|^(applyMessage|receiveMessage|processProof|executeMessage|deliverMessage)$'}, {'function.source_matches_regex': '(?i)\\b(application|app|receiver|export)\\w*(Domain|DomainId|Namespace|AppId|Id)\\b'}, {'function.body_contains_regex': 'keccak256\\s*\\(\\s*abi\\.encode(?:Packed)?\\s*\\('}, {'function.body_contains_regex': '(?i)\\b(root|receipt|leaf|nonce|payload|message|commitment|export)\\b'}, {'function.body_contains_regex': '(?i)(consumed|processed|used|spent|seen)\\w*\\s*\\['}, {'function.body_contains_regex': '(?i)(consumed|processed|used|spent|seen)\\w*\\s*\\[[^\\]]+\\]\\s*=\\s*(true|1)'}, {'function.body_contains_regex': '(?i)(application|app|receiver|export)\\w*(Domain|DomainId|Namespace|AppId|Id)'}, {'function.body_not_contains_regex': '(?is)keccak256\\s*\\(\\s*abi\\.encode(?:Packed)?\\s*\\([^;{}]*(application|app|receiver|export)\\w*(Domain|DomainId|Namespace|AppId|Id)'}, {'function.body_not_contains_regex': '(?is)(consumed|processed|used|spent|seen)\\w*\\s*\\[\\s*(application|app|receiver|export)\\w*(Domain|DomainId|Namespace|AppId|Id)\\s*\\]\\s*\\['}, {'function.body_not_contains_regex': '(?is)keccak256\\s*\\(\\s*abi\\.encode(?:Packed)?\\s*\\([^;{}]*(DOMAIN_SEPARATOR|domainSeparator|_domainSeparatorV4|address\\s*\\(\\s*this\\s*\\))'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" - bridge-receiver-domain-omitted-from-proof-digest: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
